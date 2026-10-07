package com.netguard.recon

import android.content.Context
import android.net.wifi.WifiManager
import com.netguard.core.Finding
import com.netguard.core.FindingBus
import com.netguard.core.SocketProtector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.MulticastSocket
import java.net.SocketTimeoutException

/**
 * Passive service discovery: listens on mDNS (5353) and SSDP (1900) for a
 * short window and records which LAN hosts announce themselves. Needs a
 * multicast lock — Android filters multicast by default on WiFi.
 */
class PassiveDiscovery(private val context: Context? = null) {

    suspend fun listenMdns(sessionId: String, windowMs: Long = 12_000): Int =
        listenMulticast(
            sessionId = sessionId,
            port = 5353,
            group = "224.0.0.251",
            windowMs = windowMs,
            protoLabel = "mDNS",
            extractIdentity = ::extractMdnsNames
        )

    suspend fun listenSsdp(sessionId: String, windowMs: Long = 12_000): Int =
        listenMulticast(
            sessionId = sessionId,
            port = 1900,
            group = "239.255.255.250",
            windowMs = windowMs,
            protoLabel = "SSDP",
            extractIdentity = ::extractSsdpIdentity
        )

    private suspend fun listenMulticast(
        sessionId: String,
        port: Int,
        group: String,
        windowMs: Long,
        protoLabel: String,
        extractIdentity: (ByteArray, Int) -> String?
    ): Int = withContext(Dispatchers.IO) {
        // Multicast lock: without it the WiFi chipset drops inbound multicast
        // frames and both mDNS and SSDP stays silent.
        val wifi = context?.getSystemService(WifiManager::class.java)
        val lock = try { wifi?.createMulticastLock("netguard-$protoLabel") } catch (_: Exception) { null }
        lock?.setReferenceCounted(false)
        var seen = 0
        try {
            lock?.acquire()
            MulticastSocket(port).use { socket ->
                SocketProtector.protectDatagram(socket) // don't tunnel our own listener
                socket.joinGroup(InetAddress.getByName(group))
                socket.timeToLive = 2
                socket.soTimeout = 500

                val identities = HashSet<String>()
                val buf = ByteArray(8192)
                val deadline = System.currentTimeMillis() + windowMs
                while (System.currentTimeMillis() < deadline) {
                    val packet = DatagramPacket(buf, buf.size)
                    try {
                        socket.receive(packet)
                    } catch (_: SocketTimeoutException) {
                        continue
                    }
                    val ip = packet.address?.hostAddress ?: continue
                    val identity = extractIdentity(packet.data, packet.length) ?: continue
                    val dedupeKey = "$ip|$identity"
                    if (identities.add(dedupeKey)) {
                        FindingBus.emit(
                            Finding.Host(
                                sessionId = sessionId,
                                ip = ip,
                                hostname = identity,
                                vendor = protoLabel
                            )
                        )
                        seen++
                    }
                }
            }
        } catch (_: Exception) {
            // port in use, multicast unavailable, etc. — fail soft
        } finally {
            try { lock?.release() } catch (_: Exception) {}
        }
        seen
    }

    /** Maximal printable runs in the packet that look like `.local` hostnames. */
    private fun extractMdnsNames(data: ByteArray, length: Int): String? {
        var start = -1
        var best: String? = null
        var i = 0
        while (i < length) {
            val byte = data[i].toInt() and 0xFF
            val printable = byte in 0x21..0x7E
            if (printable) {
                if (start < 0) start = i
            } else {
                if (start >= 0) {
                    val run = String(data, start, i - start, Charsets.US_ASCII)
                    val found = run.split(' ', ',', ';').firstOrNull {
                        it.contains(".local") && it.length > 5 && validHostLabel(it.trimEnd('.'))
                    }?.trimEnd('.')
                    if (found != null && (best == null || found.length > best!!.length)) best = found
                    start = -1
                }
            }
            i++
        }
        return best
    }

    private fun validHostLabel(s: String): Boolean =
        s.all { it.isLetterOrDigit() || it == '-' || it == '.' || it == '_' }

    /** LOCATION header (URL host) or NT/ST device type in an SSDP packet. */
    private fun extractSsdpIdentity(data: ByteArray, length: Int): String? {
        val text = String(data, 0, length, Charsets.US_ASCII)
        val location = Regex("LOCATION:\\s*https?://([^:/\\s]+)", RegexOption.IGNORE_CASE)
            .find(text)?.groupValues?.get(1)
        if (location != null) return location
        return Regex("(?:^|\\r?\\n)(?:NT|ST):\\s*(\\S+)", RegexOption.IGNORE_CASE)
            .find(text)?.groupValues?.get(1)
    }
}