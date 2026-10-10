package com.netguard.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import com.netguard.core.Finding
import com.netguard.core.FindingBus
import com.netguard.core.SocketProtector
import java.io.FileDescriptor
import java.net.DatagramSocket
import java.nio.channels.DatagramChannel
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.Selector
import java.util.concurrent.ConcurrentHashMap

/**
 * TUN-based traffic observer.
 *
 * Reads raw IPv4 packets from the TUN, parses TCP/UDP headers, extracts TLS
 * SNI from ClientHello (so we see *what domain* without decrypting anything),
 * resolves DNS lookups, and flags cleartext protocols / known tracker domains
 * as TrafficEvents.
 *
 * UDP: genuinely forwarded. Every UDP flow is NAT'd through a protect()'d
 * DatagramChannel to the real destination; replies are written back into the
 * TUN as hand-built IPv4/UDP packets with a correctly computed IP header
 * checksum (the Android kernel silently drops anything with a wrong one).
 * DNS aimed at the TUN's internal resolver address is redirected upstream.
 * This covers DNS and QUIC/HTTP3.
 *
 * TCP: observe-and-flag only, NOT forwarded. Forwarding means being a full
 * NAT/proxy — a userspace TCP/IP stack (retransmission, windowing,
 * reordering) — which is its own project. Consequence: while a session runs,
 * apps' TCP/HTTPS traffic stops flowing (UDP keeps working).
 */
class NetGuardVpnService : VpnService() {
    init {
        // Expose protect() to module code through the app-wide singleton, so
        // recon/BLE sockets bypass the VPN while a session is active. protect()
        // returns false when it fails — log that instead of failing silently
        // (a silent failure routes probe traffic INTO the tun and blackholes it).
        SocketProtector.protectSocketImpl = { socket ->
            val ok = protect(socket)
            if (!ok) android.util.Log.w("NetGuardVpn", "protect(socket) returned FALSE — bypass failed")
        }
        SocketProtector.protectDatagramImpl = { socket ->
            val ok = protect(socket)
            if (!ok) android.util.Log.w("NetGuardVpn", "protect(datagram) returned FALSE — bypass failed")
        }
    }

    companion object {
        const val EXTRA_SESSION_ID = "sessionId"
        /** Notification "Stop" action: delivered to onStartCommand as an intent. */
        const val ACTION_STOP = "com.netguard.vpn.STOP"
        private const val TAG = "NetGuardVpn"

        private const val VPN_MTU = 1280
        private const val TUN_ADDRESS = "10.111.222.3"
        private const val TUN_DNS = "10.111.222.4"
        private const val UPSTREAM_DNS = "1.1.1.1"
        private const val MAX_FLOWS = 256

        private val TRACKER_DOMAINS = setOf(
            "doubleclick.net", "google-analytics.com", "googletagmanager.com",
            "app-measurement.com", "crashlytics.com", "facebook.net",
            "graph.facebook.com", "appsflyer.com", "branch.io", "mixpanel.com",
            "segment.io", "amplitude.com", "sentry.io", "onesignal.com",
            "adcolony.com", "unityads.unity3d.com", "moatads.com",
            "scorecardresearch.com", "quantserve.com"
        )

        private val CLEARTEXT_PORTS = setOf(21, 23, 25, 80, 110, 143, 587, 1900, 8080)

        val SERVICE_PORTS = mapOf(
            21 to "FTP", 22 to "SSH", 23 to "Telnet", 25 to "SMTP", 53 to "DNS",
            80 to "HTTP", 110 to "POP3", 143 to "IMAP", 443 to "HTTPS",
            445 to "SMB", 3306 to "MySQL", 3389 to "RDP", 5353 to "mDNS",
            5432 to "Postgres", 5555 to "ADB", 8080 to "HTTP-alt", 853 to "DoT",
            1900 to "SSDP", 9100 to "JetDirect"
        )
    }

    /** One NATed UDP flow: phone srcPort <-> (real remote endpoint). */
    private class UdpFlow(
        val channel: DatagramChannel,
        val srcPort: Int,
        val replyIp: Int,   // what the reply's IP src must look like to the phone
        val replyPort: Int  // what the reply's UDP src port must look like
    )

    private var tunInterface: ParcelFileDescriptor? = null
    private var sessionThread: Thread? = null
    private var relayThread: Thread? = null
    @Volatile private var running = false
    private var startIntent: Intent? = null
    private var selector: Selector? = null
    private val udpFlows = ConcurrentHashMap<Int, UdpFlow>()
    private val seenTcpFlows: MutableSet<String> = ConcurrentHashMap.newKeySet()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        android.util.Log.d(TAG, "onStartCommand action=${intent?.action}")
        // Notification "Stop" button (and any other stop signal) lands here.
        if (intent?.action == ACTION_STOP) {
            running = false
            try { selector?.wakeup() } catch (_: Exception) {}
            // Close the TUN FIRST: unblocks the reader (blocked in Os.read) and
            // tears the VPN network down deterministically, instead of hoping
            // onDestroy's joins+close complete on every OEM.
            try { tunInterface?.close() } catch (_: Exception) {}
            tunInterface = null
            stopForeground(android.app.Service.STOP_FOREGROUND_REMOVE)
            stopSelf()
            android.util.Log.d(TAG, "ACTION_STOP: tun closed, service stopping")
            return START_NOT_STICKY
        }
        if (intent != null) startIntent = intent
        running = true
        startForegroundWithNotification()
        if (tunInterface == null && establishTun() == null) {
            // establish() returns null if VpnService.prepare() consent is missing.
            android.util.Log.d(TAG, "establish() returned null — consent missing?")
            VpnState.active.value = false
            stopSelf()
            return START_NOT_STICKY
        }
        VpnState.active.value = true
        android.util.Log.d(TAG, "tun established, starting threads")
        if (sessionThread == null) startThreads()
        // START_NOT_STICKY: a killed service comes back through the app's
        // explicit VPN-consent flow (banner shows "ENABLE VPN"), not by
        // silently resurrecting a tunnel with no session behind it.
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        android.util.Log.d(TAG, "onDestroy: tearing down")
        running = false
        VpnState.active.value = false
        try { selector?.wakeup() } catch (_: Exception) {}
        sessionThread?.join(1500)
        relayThread?.join(1500)
        android.util.Log.d(TAG, "onDestroy: threads joined")
        udpFlows.values.forEach { try { it.channel.close() } catch (_: Exception) {} }
        udpFlows.clear()
        try { tunInterface?.close() } catch (_: Exception) {}
        tunInterface = null
        android.util.Log.d(TAG, "onDestroy: tun fd closed")
        super.onDestroy()
    }

    @Suppress("DEPRECATION")
    private fun establishTun(): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("NetGuard")
            .setMtu(VPN_MTU)
            .addAddress(TUN_ADDRESS, 32)
            .addDnsServer(TUN_DNS)
            .addRoute("0.0.0.0", 0)
        // Exclude our OWN app from the tunnel: recon/OSINT probes then route
        // natively over wlan0 — no protect() needed, and on ROMs where
        // protect() silently fails (observed on OneUI with this builder), the
        // sweep still works instead of blackholing into the observe-only TUN.
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {
            android.util.Log.w(TAG, "addDisallowedApplication(self) failed — relying on protect()")
        }
        return try {
            builder.establish()?.also { tunInterface = it }
        } catch (_: Exception) {
            null
        }
    }

    private fun startForegroundWithNotification() {
        val channelId = "netguard_session"
        val nm = getSystemService(android.app.NotificationManager::class.java)
        nm.createNotificationChannel(
            android.app.NotificationChannel(
                channelId, "Monitoring session",
                android.app.NotificationManager.IMPORTANCE_LOW
            )
        )
        // Tap notification → open the app (so Disconnect/Enable is one tap away)
        val openApp = android.app.PendingIntent.getActivity(
            this, 0,
            android.content.Intent(this, com.netguard.ui.MainActivity::class.java),
            android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT
        )
        // "Stop monitoring" action → onStartCommand(ACTION_STOP) → service dies,
        // session cleanup happens in the app via VpnState observation.
        // foregroundServiceType is required on API 34+ for FGS PendingIntent
        // starts; the manifest declares specialUse for this service.
        val stopIntent = android.content.Intent(this, NetGuardVpnService::class.java)
            .setAction(ACTION_STOP)
        val stopAction = android.app.PendingIntent.getService(
            this, 1, stopIntent,
            android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notification = android.app.Notification.Builder(this, channelId)
            .setContentTitle("NetGuard monitoring active")
            .setContentText("Traffic observation session running")
            .setSmallIcon(android.R.drawable.ic_secure)
            .setContentIntent(openApp)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop monitoring", stopAction)
            .setOngoing(true)
            .build()
        if (android.os.Build.VERSION.SDK_INT >= 34) {
            startForeground(1, notification, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(1, notification)
        }
    }

    private fun startThreads() {
        val tun = tunInterface ?: return
        val fd: FileDescriptor = tun.fileDescriptor
        val sel = Selector.open()
        selector = sel

        // Reader thread: TUN -> observe + UDP NAT out
        sessionThread = Thread({
            android.util.Log.d(TAG, "reader: start (fd=$fd)")
            val packet = ByteBuffer.allocateDirect(VPN_MTU + 64)
            var first = true
            var handled = 0L
            while (running) {
                packet.clear()
                val n = try {
                    Os.read(fd, packet)
                } catch (e: android.system.ErrnoException) {
                    // The tun fd is O_NONBLOCK: EAGAIN just means no packet
                    // right now (netd opens it non-blocking) — never fatal.
                    // (The old reader treated this as EOF and EXITED after
                    // the first packet — the "VPN kills internet" bug.)
                    if (e.errno == android.system.OsConstants.EAGAIN) {
                        try { Thread.sleep(2) } catch (_: InterruptedException) { break }
                        continue
                    }
                    android.util.Log.w(TAG, "reader: read err ${e.errno}")
                    break
                } catch (e: Exception) {
                    android.util.Log.w(TAG, "reader: read err ${e.javaClass.simpleName}")
                    break
                }
                if (n <= 0) break
                if (first) {
                    first = false
                    val proto = packet.get(9).toInt() and 0xFF
                    android.util.Log.d(TAG, "reader: FIRST packet $n bytes proto=$proto")
                }
                try {
                    handlePacketFromDevice(packet, n)
                    handled++
                    if (handled % 50L == 0L) android.util.Log.d(TAG, "reader: handled=$handled")
                } catch (e: Exception) {
                    // never let one malformed packet kill the tunnel
                    android.util.Log.w(TAG, "reader: handle err ${e.javaClass.simpleName}: ${e.message?.take(80)}")
                }
            }
            android.util.Log.d(TAG, "reader: exit (handled=$handled)")
        }, "netguard-vpn-read")

        // Relay thread: upstream sockets -> replies written back into the TUN
        relayThread = Thread({
            val selLocal = sel
            val replyBuf = ByteBuffer.allocateDirect(65535)
            while (running) {
                if (try { selLocal.select(500) } catch (_: Exception) { break } == 0) continue
                val iter = selLocal.selectedKeys().iterator()
                while (iter.hasNext()) {
                    val key = iter.next()
                    iter.remove()
                    if (!key.isValid) continue
                    val flow = key.attachment() as? UdpFlow ?: continue
                    replyBuf.clear()
                    val source: InetAddress = try {
                        ((key.channel() as DatagramChannel).receive(replyBuf) as? InetSocketAddress)?.address ?: continue
                    } catch (_: Exception) {
                        continue
                    }
                    replyBuf.flip()
                    if (replyBuf.hasRemaining()) {
                        try { writeUdpReply(fd, source, flow, replyBuf) } catch (_: Exception) {}
                    }
                }
            }
        }, "netguard-vpn-relay")

        sessionThread?.start()
        relayThread?.start()
    }

    /** Only here so the reader loop's catch order stays explicit and readable. */
    private class Interruptible : Exception()

    private fun handlePacketFromDevice(packet: ByteBuffer, length: Int) {
        if (length < 20) return
        val version = (packet.get(0).toInt() shr 4) and 0xF
        if (version != 4) return

        val ihl = (packet.get(0).toInt() and 0xF) * 4
        if (ihl < 20 || length < ihl) return
        val protocol = packet.get(9).toInt() and 0xFF
        val srcIp = ipv4IntAt(packet, 12)
        val dstIp = ipv4IntAt(packet, 16)

        when (protocol) {
            17 -> { // UDP
                if (length < ihl + 8) return
                val srcPort = u16(packet, ihl)
                val dstPort = u16(packet, ihl + 2)
                if (dstPort == 53) {
                    val sid = sessionId()
                    observeDnsQuery(packet, ihl, length, sid, srcIp, dstIp)
                }
                forwardUdp(packet, ihl, length, dstIp, dstPort, srcPort)
            }
            6 -> { // TCP: observe only
                if (length < ihl + 20) return
                val srcPort = u16(packet, ihl)
                val dstPort = u16(packet, ihl + 2)
                observeTcpPacket(packet, ihl, length, sessionId(), srcPort, dstIp, dstPort)
            }
        }
    }

    private fun sessionId(): String =
        startIntent?.getStringExtra(EXTRA_SESSION_ID) ?: "unknown"

    // --- observation ---

    private fun observeDnsQuery(packet: ByteBuffer, ihl: Int, length: Int, sessionId: String, srcIp: Int, dstIp: Int) {
        // Question section QNAME starts after the 12-byte DNS header. Only the
        // literal labels of an outgoing query matter to us; pointers/compressed
        // names don't appear in the question section of a query.
        val qnameStart = ihl + 8 + 12
        if (qnameStart >= length) return
        try {
            val sb = StringBuilder()
            var i = qnameStart
            while (i < length) {
                val labelLen = packet.get(i).toInt() and 0xFF
                if (labelLen == 0 || (labelLen and 0xC0) != 0) break
                if (i + 1 + labelLen > length) break
                for (j in 1..labelLen) sb.append((packet.get(i + j).toInt() and 0xFF).toChar())
                sb.append('.')
                i += 1 + labelLen
            }
            if (sb.isEmpty()) return
            val domain = sb.removeSuffix(".").toString().lowercase()
            if (domain.length < 4 || !domain.contains('.')) return

            val isTracker = TRACKER_DOMAINS.any { domain == it || domain.endsWith(".$it") }
            FindingBus.emit(
                Finding.TrafficEvent(
                    sessionId = sessionId,
                    sni = domain,
                    dstIp = intToIp(if (dstIp == ipv4IntFromString(TUN_DNS)) ipv4IntFromString(UPSTREAM_DNS) else dstIp),
                    dstPort = 53,
                    protocol = "DNS",
                    flagReason = if (isTracker) "known tracker domain" else null,
                    flagged = isTracker
                )
            )
        } catch (_: Exception) {
        }
    }

    private fun observeTcpPacket(packet: ByteBuffer, ihl: Int, length: Int, sessionId: String, srcPort: Int, dstIp: Int, dstPort: Int) {
        // Emit once per flow, but at its FIRST DATA packet — the SYN
        // (payload-less) can't carry SNI, and emitting there once per flow
        // meant the ClientHello (a few packets later) was never read:
        // every TLS row showed a bare IP with no hostname.
        val dataOffset = ((packet.get(ihl + 12).toInt() shr 4) and 0xF) * 4
        val payloadLen = length - ihl - dataOffset
        if (payloadLen <= 0 && dstPort != 53) {
            // pure SYN/ACK/FIN — wait for the data packet; the flow key is
            // only added when we actually emit (below).
            return
        }
        val key = "$srcPort>$dstIp:$dstPort"
        if (!seenTcpFlows.add(key)) return
        if (seenTcpFlows.size > 512) seenTcpFlows.clear() // bounded memory

        val sni = extractTlsSni(packet, ihl, length)
        val cleartext = dstPort in CLEARTEXT_PORTS
        // Per-app attribution: fills only NetGuard's own flows (Android 10+
        // hides other apps' socket rows from /proc/net in non-privileged reads).
        val attribution = TrafficAttribution.attributablePackage(srcPort)
        FindingBus.emit(
            Finding.TrafficEvent(
                sessionId = sessionId,
                sni = sni,
                dstIp = intToIp(dstIp),
                dstPort = dstPort,
                protocol = if (dstPort == 443 || sni != null) "TLS" else SERVICE_PORTS[dstPort] ?: "TCP:$dstPort",
                appPackage = attribution,
                flagReason = if (cleartext) "cleartext destination port" else null,
                flagged = cleartext
            )
        )
    }

    /** Pull SNI from a TLS ClientHello if the first TCP payload happens to be one. */
    private fun extractTlsSni(packet: ByteBuffer, ihl: Int, length: Int): String? {
        return try {
            val dataOffset = ((packet.get(ihl + 12).toInt() shr 4) and 0xF) * 4
            val p0 = ihl + dataOffset
            if (p0 + 6 > length) return null
            if ((packet.get(p0).toInt() and 0xFF) != 0x16) return null           // not handshake record
            var p = p0 + 5                                                        // skip record header
            if ((packet.get(p).toInt() and 0xFF) != 0x01) return null             // not ClientHello
            p += 4                                                                // handshake header (type + 3-byte length)
            p += 2 + 32                                                           // legacy version + random
            val sessionIdLen = packet.get(p).toInt() and 0xFF
            p += 1 + sessionIdLen
            val cipherLen = u16(packet, p)
            p += 2 + cipherLen
            p += 1 + (packet.get(p).toInt() and 0xFF)                             // compression methods
            if (p + 2 > length) return null
            val extTotal = u16(packet, p)
            p += 2
            val extEnd = minOf(p + extTotal, length)
            while (p + 4 <= extEnd) {
                val extType = u16(packet, p)
                val extLen = u16(packet, p + 2)
                if (extType == 0) { // server_name extension
                    // data: list length (2) + entry type (1) + name length (2) + name
                    val q = p + 4 + 5
                    val end = minOf(p + 4 + extLen, length)
                    if (q < end) {
                        val sb = StringBuilder()
                        var i = q
                        while (i < end) {
                            val c = packet.get(i).toInt() and 0xFF
                            if (c == 0 || c !in 32..126) break
                            sb.append(c.toChar())
                            i++
                        }
                        val sni = sb.toString().lowercase()
                        if (sni.contains('.')) return sni
                    }
                    return null
                }
                p += 4 + extLen
            }
            null
        } catch (_: Exception) {
            null
        }
    }

    // --- UDP NAT forwarding ---

    private fun forwardUdp(packet: ByteBuffer, ihl: Int, length: Int, dstIp: Int, dstPort: Int, srcPort: Int) {
        var flow = udpFlows[srcPort]
        val internalDns = dstIp == ipv4IntFromString(TUN_DNS)

        if (flow == null) {
            if (udpFlows.size >= MAX_FLOWS) return
            val ch = try { DatagramChannel.open() } catch (_: Exception) { return }
            try {
                SocketProtector.protectDatagram(ch.socket()) // bypass the VPN so it can reach the real network
                ch.configureBlocking(false)
                selector ?: run { ch.close(); return }
                ch.register(selector, java.nio.channels.SelectionKey.OP_READ, null)
            } catch (_: Exception) {
                try { ch.close() } catch (_: Exception) {}
                return
            }
            // DNS sent to the TUN's internal resolver goes upstream; the reply
            // must be re-stamped as coming from the internal resolver so the
            // phone's DNS client accepts it.
            val upstreamIp = if (internalDns) ipv4IntFromString(UPSTREAM_DNS) else dstIp
            flow = UdpFlow(ch, srcPort, if (internalDns) ipv4IntFromString(TUN_DNS) else dstIp, dstPort)
            udpFlows[srcPort] = flow
            flow.channel.keyFor(selector)?.attach(flow)
            sendUdpPayload(ch, packet, ihl, length, upstreamIp, dstPort)
            return
        }

        // Re-attach in case a stale key lost it
        if (flow.channel.keyFor(selector)?.attachment() == null) {
            try { flow.channel.keyFor(selector)?.attach(flow) } catch (_: Exception) {}
        }
        val upstreamIp = if (internalDns && flow.replyIp == ipv4IntFromString(TUN_DNS)) ipv4IntFromString(UPSTREAM_DNS) else dstIp
        sendUdpPayload(flow.channel, packet, ihl, length, upstreamIp, dstPort)
    }

    private fun sendUdpPayload(ch: DatagramChannel, packet: ByteBuffer, ihl: Int, length: Int, dstIp: Int, dstPort: Int) {
        val payloadLen = length - ihl - 8
        if (payloadLen <= 0) return
        try {
            val payload = ByteBuffer.allocate(payloadLen)
            for (i in 0 until payloadLen) payload.put(packet.get(ihl + 8 + i))
            payload.flip()
            ch.send(payload, InetSocketAddress(intToInetAddress(dstIp), dstPort))
        } catch (_: Exception) {
        }
    }

    /**
     * Builds a real IPv4/UDP packet (with a correct IP checksum — the kernel
     * drops wrong ones) and writes it into the TUN so the phone receives the
     * upstream reply.
     */
    private fun writeUdpReply(fd: FileDescriptor, source: InetAddress, flow: UdpFlow, payload: ByteBuffer) {
        val payloadLen = payload.remaining()
        val totalLen = 20 + 8 + payloadLen
        val buf = ByteBuffer.allocate(totalLen)

        // ---- IP header (20 bytes) ----
        buf.put(0x45)                       // version 4, IHL 5
        buf.put(0)                          // DSCP/ECN
        buf.putShort(totalLen.toShort())
        buf.putShort(0)                     // identification
        buf.putShort(0x4000)                // flags: Don't Fragment
        buf.put(64)                         // TTL
        buf.put(17)                         // protocol: UDP
        buf.putShort(0)                     // checksum placeholder
        buf.put(0x0A)                       // src IP: written properly below
        buf.put(0x0A); buf.put(0x0A); buf.put(0x0A)
        buf.put(0x0A)                       // dst IP placeholder
        // Fix src/dst addresses in one pass:
        buf.position(12)
        buf.put(intToBytes(flow.replyIp))   // src = the remote the phone talked to
        buf.put(intToBytes(ipv4IntFromString(TUN_ADDRESS))) // dst = phone's TUN address

        // ---- UDP header (8 bytes) ----
        buf.putShort(flow.replyPort.toShort()) // src port = remote's port
        buf.putShort(flow.srcPort.toShort())   // dst port = phone's original source port
        buf.putShort((8 + payloadLen).toShort())
        buf.putShort(0)                        // UDP checksum: optional over IPv4

        // ---- payload ----
        buf.put(payload)

        // ---- IP header checksum (RFC 1071) ----
        buf.position(0)
        val checksum = ipChecksum(buf, 20)
        buf.position(10)
        buf.putShort(checksum.toShort())

        buf.position(0)
        buf.limit(totalLen)
        try { Os.write(fd, buf) } catch (_: Exception) {}
    }

    // --- byte helpers ---

    private fun u16(packet: ByteBuffer, offset: Int): Int =
        ((packet.get(offset).toInt() and 0xFF) shl 8) or (packet.get(offset + 1).toInt() and 0xFF)

    private fun ipv4IntAt(packet: ByteBuffer, offset: Int): Int =
        ((packet.get(offset).toInt() and 0xFF) shl 24) or
        ((packet.get(offset + 1).toInt() and 0xFF) shl 16) or
        ((packet.get(offset + 2).toInt() and 0xFF) shl 8) or
        (packet.get(offset + 3).toInt() and 0xFF)

    private fun intToIp(ip: Int): String =
        "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 8) and 0xFF}.${ip and 0xFF}"

    private fun intToInetAddress(ip: Int): InetAddress = InetAddress.getByAddress(
        byteArrayOf(
            ((ip shr 24) and 0xFF).toByte(),
            ((ip shr 16) and 0xFF).toByte(),
            ((ip shr 8) and 0xFF).toByte(),
            (ip and 0xFF).toByte()
        )
    )

    private fun ipv4IntFromString(s: String): Int {
        val parts = s.split(".")
        return (parts[0].toInt() shl 24) or (parts[1].toInt() shl 16) or
            (parts[2].toInt() shl 8) or parts[3].toInt()
    }

    private fun intToBytes(v: Int): ByteArray = byteArrayOf(
        ((v shr 24) and 0xFF).toByte(),
        ((v shr 16) and 0xFF).toByte(),
        ((v shr 8) and 0xFF).toByte(),
        (v and 0xFF).toByte()
    )

    /** RFC 1071 one's-complement sum over the 20-byte IP header. */
    private fun ipChecksum(buf: ByteBuffer, headerLen: Int): Int {
        var sum = 0L
        var i = 0
        while (i < headerLen) {
            if (i == 10) { i += 2; continue } // skip the checksum field itself
            sum += u16(buf, i)
            i += 2
        }
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.toInt().inv() and 0xFFFF)
    }
}