package com.netguard.recon

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.WifiManager
import androidx.core.content.ContextCompat
import com.netguard.core.DeviceClassifier
import com.netguard.core.Finding
import com.netguard.core.FindingBus
import com.netguard.core.SocketProtector
import com.netguard.core.WifiPinner
import com.netguard.net.ProtectedHttp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Collections

/**
 * Layer-3 host discovery without root, producing a real "network map" of the
 * CURRENT WiFi:
 *
 *  - ARP table read (devices that recently talked to us) + active TCP sweep
 *  - per open port: service name + what usually runs there + banner grab
 *    (SSH/FTP/SMTP announce product+OS version on connect)
 *  - OS inference per host (port pattern + banners + OUI vendor + hostname)
 *  - This Phone and the Gateway get their own categories (highlighted)
 *  - the network's public/edge IP is fetched and RDAP-enriched (ISP/ASN)
 */
class HostDiscovery {

    data class SweepContext(
        val ssid: String?,
        val thisPhoneIp: String?,
        val gatewayIp: String?,
        val subnet: String?,
        val publicIpFinding: Finding.PublicIp?,
        val probeFailuresWereTotal: Boolean = false,
        val arpHostsSeen: Int = 0
    )

    companion object {
        private val COMMON_PORTS = intArrayOf(
            21, 22, 23, 25, 53, 80, 111, 135, 139, 443, 445, 548, 5555,
            1900, 3306, 3389, 5000, 5353, 5432, 8009, 8080, 8443, 9100
        )

        /** Port -> (service, what usually runs there — shown to the user). */
        val PORT_INFO: Map<Int, Pair<String, String>> = mapOf(
            21 to ("FTP" to "file server — cleartext logins possible"),
            22 to ("SSH" to "remote shell (admin access)"),
            23 to ("Telnet" to "remote console — NO encryption, red flag"),
            25 to ("SMTP" to "mail transfer"),
            53 to ("DNS" to "name resolution (DNS server / Pi-hole?)"),
            80 to ("HTTP" to "web admin panel or service — cleartext"),
            111 to ("RPC" to "NFS/RPC portmapper (Unix/NAS)"),
            135 to ("MS-RPC" to "Windows RPC endpoint mapper"),
            139 to ("NetBIOS" to "Windows legacy file/print sharing"),
            443 to ("HTTPS" to "encrypted web service"),
            445 to ("SMB" to "Windows file sharing (or Samba)"),
            548 to ("AFP" to "macOS file sharing"),
            5555 to ("ADB" to "Android debug bridge — remote debug access, risky"),
            1900 to ("SSDP" to "UPnP discovery"),
            3306 to ("MySQL" to "database server"),
            3389 to ("RDP" to "Windows remote desktop"),
            5000 to ("UPnP/API" to "Synology/UPnP/web app"),
            5353 to ("mDNS" to "Bonjour/Chromecast discovery"),
            5432 to ("PostgreSQL" to "database server"),
            8009 to ("CASTV2" to "Chromecast protocol"),
            8080 to ("HTTP-alt" to "secondary web panel (proxies/IoT)"),
            8443 to ("HTTPS-alt" to "secondary encrypted web panel"),
            9100 to ("JetDirect" to "raw printer port")
        )

        private val OUI = mapOf(
            "00:1A:11" to "Google", "3C:5A:B4" to "Google", "F4:F5:D8" to "Google",
            "00:17:88" to "Philips Hue", "00:1D:7E" to "Philips",
            "B8:27:EB" to "Raspberry Pi Foundation", "DC:A6:32" to "Raspberry Pi Trading",
            "E4:5F:01" to "Raspberry Pi Trading", "D8:3A:DD" to "Raspberry Pi Trading",
            "00:0C:29" to "VMware", "00:50:56" to "VMware",
            "AC:DE:48" to "Private", "00:1B:63" to "Apple", "AC:BC:32" to "Apple",
            "F0:18:98" to "Apple", "A4:83:E7" to "Apple", "28:6A:BA" to "Hewlett Packard",
            "00:1E:52" to "Hewlett Packard", "00:0B:82" to "Grandstream Networks",
            "00:04:F3" to "Polycom", "00:1F:33" to "Netgear", "A0:40:A6" to "Wistron Neweb (Netgear)",
            "34:31:C4" to "Actiontec (Verizon)", "44:47:CC" to "D-Link", "B0:39:56" to "D-Link",
            "C8:D7:19" to "TP-Link", "50:C7:BF" to "TP-Link", "18:D6:C7" to "TP-Link",
            "EC:08:6B" to "Xiaomi", "78:11:24" to "Xiaomi", "64:09:80" to "Xiaomi",
            "00:1A:2A" to "AzureWave", "00:08:9B" to "ICP Electronics",
            "02:00:00" to "Locally administered (randomized MAC)"
        )

        private const val CONNECT_TIMEOUT_MS = 300
        private const val BANNER_TIMEOUT_MS = 1500

        private fun ouiVendor(mac: String?): String? {
            if (mac == null || mac.length < 8) return null
            val prefix = mac.take(8).uppercase()
            return OUI.entries.firstOrNull { it.key == prefix }?.value
        }
    }

    private fun hasFineLocation(context: Context): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED

    /** SSID needs fine-location post-Q; falls back to a generic label. */
    fun currentSsid(context: Context): String? = try {
        if (hasFineLocation(context)) {
            val wifi = context.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            @Suppress("DEPRECATION")
            wifi?.connectionInfo?.ssid?.trim('"')?.takeIf {
                it.isNotBlank() && it != "<unknown ssid>"
            } ?: "WiFi"
        } else "WiFi"
    } catch (_: Exception) {
        "WiFi"
    }

    /**
     * Full network map of the CURRENT WiFi: emits HOST + OPEN_PORT findings
     * (this phone, gateway, every responder with ports/banners/OS guess),
     * fetches the public IP, and returns the sweep context for the UI.
     */
    suspend fun sweepCurrentNetwork(sessionId: String, context: Context): SweepContext =
        withContext(Dispatchers.IO) {
            val wifi = context.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            // Re-resolve the WiFi Network at sweep time — the cached one from
            // app start can be stale after a reconnect/roam.
            WifiPinner.refresh(context)
            resetDiagnostics()

            @Suppress("DEPRECATION")
            val dhcp = wifi?.dhcpInfo
            val ipInt = dhcp?.ipAddress ?: 0
            val gwInt = dhcp?.gateway ?: 0
            // dhcpInfo stores the address little-endian (reversed octets) —
            // 192.168.2.252 arrives as 0xFC02A8C0 → intToIp must read LSB first.
            val thisIp = if (ipInt != 0) intToIpReversed(ipInt) else null
            val gatewayIp = if (gwInt != 0) intToIpReversed(gwInt) else null
            val subnet = thisIp?.substringBeforeLast(".")
            val ssid = currentSsid(context)

            // This phone first — always present in the map.
            if (thisIp != null) {
                FindingBus.emit(
                    Finding.Host(
                        sessionId = sessionId, ip = thisIp,
                        hostname = "this-phone",
                        category = DeviceClassifier.CAT_THISPHONE,
                        osGuess = "Android (this device)"
                    )
                )

                // Gateway next — usually the most interesting device on the LAN.
                if (gatewayIp != null) {
                    val gwMac = arpLookup(gatewayIp)
                    val (ports, banners) = probePorts(gatewayIp)
                    emitHost(sessionId, gatewayIp, "gateway", gwMac, ports, banners,
                        DeviceClassifier.CAT_GATEWAY)
                }
            }

            // Public IP runs IN PARALLEL with the sweep so a slow/blocked
            // ipify fetch can never stall the map. Plain `launch` — NOT
            // `coroutineScope { launch {} }`, which suspends the caller until
            // the child completes (that exact mistake stalled the whole sweep
            // behind the public-IP fetch).
            launch { fetchPublicIp(sessionId) }

            // Active sweep of the subnet (skips this phone + gateway).
            var isolation = false
            var arpHostsSeen = 0
            if (subnet != null) {
                val skip = setOfNotNull(thisIp, gatewayIp)
                val sweepT0 = android.os.SystemClock.elapsedRealtime()
                val portReachable = activeSweep(sessionId, subnet, skipIps = skip)
                // ARP pass catches devices that answered nothing but are in the
                // neighbor cache (phones, TVs idle) — light probe each.
                arpHostsSeen = arpTable(sessionId, skipIps = skip).size

                // Client-isolation detection (verified on-device: Guest APs with
                // AP isolation answer ARP at L2 but drop ALL host-host IP):
                // many live L2 neighbors + zero TCP responses + internet works.
                isolation = arpHostsSeen >= 2 && !portReachable &&
                    hasInternet()
            }

            // give the public-IP lookup its grace window (it may still be in
            // flight; withContext joins it when we return — lastPublicIp has
            // the result if it landed in time)
            kotlinx.coroutines.withTimeoutOrNull(12000) { }
            val publicIpFinding = lastPublicIp.value

            if (isolation) {
                FindingBus.emit(
                    Finding.Host(
                        sessionId = sessionId,
                        ip = gatewayIp ?: "unknown",
                        hostname = "isolation-note",
                        vendor = null, mac = null,
                        category = DeviceClassifier.CAT_GATEWAY,
                        osGuess = "AP CLIENT ISOLATION detected: this WiFi blocks device-to-device " +
                            "traffic ( Guest/VMWiFi networks do this). ARP + mDNS/SSDP intel still " +
                            "collected below; port scans and OS guesses are unanswerable here — " +
                            "switch to the main SSID to map the LAN."
                    )
                )
            }

            SweepContext(ssid, thisIp, gatewayIp, subnet, publicIpFinding, isolation, arpHostsSeen)
        }

    /** Instant: whatever the kernel's neighbor cache currently holds. */
    suspend fun scanArpTable(sessionId: String): List<Finding.Host> =
        arpTable(sessionId, skipIps = emptySet())

    private suspend fun arpTable(sessionId: String, skipIps: Set<String>): List<Finding.Host> =
        withContext(Dispatchers.IO) {
            val hosts = mutableListOf<Finding.Host>()
            runCatching {
                File("/proc/net/arp").readLines().drop(1).forEach { line ->
                    val parts = line.trim().split(Regex("\\s+"))
                    if (parts.size >= 6) {
                        val ip = parts[0]
                        val mac = parts[3].uppercase()
                        val flags = parts[2]
                        if (flags != "0x0" && mac.isNotBlank() && mac != "00:00:00:00:00:00" &&
                            ip.isNotEmpty() && ip !in skipIps
                        ) {
                            val vendor = ouiVendor(mac)
                            val (ports, banners, _) = probePorts(ip)
                            if (ports.isNotEmpty()) {
                                ports.forEach { p ->
                                    FindingBus.emit(
                                        Finding.OpenPort(
                                            sessionId = sessionId, ip = ip, port = p,
                                            service = PORT_INFO[p]?.first,
                                            product = bannerProduct(p, banners[p]),
                                            flagged = p == 23 || p == 5555
                                        )
                                    )
                                }
                            }
                            hosts += buildHost(sessionId, ip, mac, vendor, ports, banners)
                        }
                    }
                }
            }
            hosts.distinctBy { it.ip }.also { list -> list.forEach { FindingBus.emit(it) } }
        }

    private fun arpLookup(ip: String): String? = runCatching {
        File("/proc/net/arp").readLines().drop(1)
            .firstOrNull { it.trim().startsWith("$ip ") }
            ?.trim()?.split(Regex("\\s+"))?.getOrNull(3)
            ?.uppercase()?.takeIf { it != "00:00:00:00:00:00" }
    }.getOrNull()

    /**
     * Slower: TCP-connect probe of the whole /24 with banner grabbing, then
     * ARP enrichment (MAC/vendor) for each responder.
     * @return true when at least one host answered (any open port) — the
     * caller uses it for AP-isolation detection.
     */
    suspend fun activeSweep(
        sessionId: String,
        subnet: String,
        skipIps: Set<String> = emptySet()
    ): Boolean = withContext(Dispatchers.IO) {
        val t0 = android.os.SystemClock.elapsedRealtime()
        android.util.Log.d("NetGuardSweep", "activeSweep begin $subnet.0/24 skip=$skipIps")
        val alive: MutableMap<String, Triple<List<Int>, Map<Int, String>, Boolean>> =
            Collections.synchronizedMap(mutableMapOf())

        coroutineScope {
            (2..254).forEach { last ->
                launch {
                    val ip = "$subnet.$last"
                    if (ip in skipIps) return@launch
                    val (ports, banners, responded) = try { probePorts(ip) } catch (e: Exception) {
                        android.util.Log.d("NetGuardSweep", "probePorts($ip) threw ${e.javaClass.simpleName}")
                        return@launch
                    }
                    if (ports.isNotEmpty() || responded) {
                        android.util.Log.d("NetGuardSweep",
                            "$ip alive ports=$ports responded=$responded @${android.os.SystemClock.elapsedRealtime() - t0}ms")
                        alive[ip] = Triple(ports, banners, responded)
                    }
                }
            }
        }
        android.util.Log.d("NetGuardSweep", "probe phase done @${android.os.SystemClock.elapsedRealtime() - t0}ms alive=${alive.size}")

        val arpByIp = runCatching {
            File("/proc/net/arp").readLines().drop(1)
                .map { it.trim().split(Regex("\\s+")) }
                .filter { it.size >= 4 }
                .associate { parts ->
                    parts[0] to parts[3].uppercase().takeIf { it != "00:00:00:00:00:00" }
                }
        }.getOrDefault(emptyMap())

        android.util.Log.d("NetGuardSweep", "emitting ${alive.size} hosts")
        var anyReachable = false
        alive.forEach { (ip, results) ->
            val (ports, banners, responded) = results
            if (ports.isNotEmpty() || responded) anyReachable = true
            val mac = arpByIp[ip] ?: arpLookup(ip)
            val vendor = ouiVendor(mac)
            ports.forEach { p ->
                FindingBus.emit(
                    Finding.OpenPort(
                        sessionId = sessionId, ip = ip, port = p,
                        service = PORT_INFO[p]?.first,
                        product = bannerProduct(p, banners[p]),
                        flagged = p == 23 || p == 5555
                    )
                )
            }
            FindingBus.emit(buildHost(sessionId, ip, mac, vendor, ports, banners))
        }
        anyReachable
    }

    /** Bounded in-flight probes so 253 IPs × 23 ports can't exhaust the IO pool. */
    private val probeLimiter = kotlinx.coroutines.sync.Semaphore(48)
    private val failLog = java.util.concurrent.atomic.AtomicInteger(0)

    /** Connect-probes common ports + classifies every response.
     *  Returns (openPorts, banners, hostRespondedAtAll):
     *  - open port → SYN-ACK (in `open`)
     *  - refused  → RST = host ALIVE, port closed (ConnectException)
     *  - silent   → timeout / unreachable (no evidence)
     *  The third flag lets the map show hosts that answered RSTs even when
     *  every scanned port is closed — they were invisible before. */
    private suspend fun probePorts(ip: String): Triple<List<Int>, Map<Int, String>, Boolean> =
        coroutineScope {
            val open = Collections.synchronizedList(mutableListOf<Int>())
            val banners = Collections.synchronizedMap(mutableMapOf<Int, String>())
            val responded = Collections.synchronizedList(mutableListOf<Boolean>())
            COMMON_PORTS.map { port ->
                async(Dispatchers.IO) {
                    probeLimiter.withPermit {
                        try {
                            Socket().use { s ->
                                SocketProtector.protect(s) // pin to wlan0 + bypass our own VPN tunnel
                                s.connect(InetSocketAddress(InetAddress.getByName(ip), port), CONNECT_TIMEOUT_MS)
                                open += port
                                grabBanner(s, port)?.let { banners[port] = it }
                            }
                        } catch (e: Exception) {
                            // RST/refused = the HOST answered (port closed) —
                            // still proof of life for the map.
                            if (e is java.net.ConnectException) responded += true
                            // first few failures get logged for diagnosis
                            val n = failLog.getAndIncrement()
                            if (n < 8) {
                                android.util.Log.d("NetGuardSweep",
                                    "probe $ip:$port -> ${e.javaClass.simpleName}: ${e.message ?: ""}")
                            } else {
                                Unit
                            }
                        }
                    }
                }
            }.awaitAll()
            open.sorted() to banners to responded.isNotEmpty()
        }.let { Triple(it.first.first, it.first.second, it.second) }

    /** Reads the server greeting (protocols that speak first: SSH/FTP/SMTP/POP3/IMAP). */
    private fun grabBanner(socket: Socket, port: Int): String? {
        if (port !in intArrayOf(21, 22, 23, 25, 110, 143)) return null
        return try {
            socket.soTimeout = BANNER_TIMEOUT_MS
            val ins = socket.getInputStream()
            val buf = ByteArray(256)
            val deadline = System.currentTimeMillis() + BANNER_TIMEOUT_MS
            var read = 0
            while (read == 0 && System.currentTimeMillis() < deadline) {
                try {
                    read = ins.read(buf)
                } catch (_: java.net.SocketTimeoutException) {
                    break
                }
            }
            if (read > 0)
                String(buf, 0, read, Charsets.US_ASCII).lines().firstOrNull()?.trim()?.takeIf { it.isNotBlank() }
            else null
        } catch (_: Exception) {
            null
        }
    }

    /** Human product line from a banner ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"). */
    private fun bannerProduct(port: Int, banner: String?): String? {
        if (banner.isNullOrBlank()) return null
        return when (port) {
            22 -> banner.removePrefix("SSH-2.0-").removePrefix("SSH-1.99-").take(80)
            else -> banner.take(90)
        }
    }

    private fun buildHost(
        sessionId: String,
        ip: String,
        mac: String?,
        vendor: String?,
        ports: List<Int>,
        banners: Map<Int, String>
    ): Finding.Host {
        val os = DeviceClassifier.guessOs(ports, banners, vendor)
        val category = DeviceClassifier.classifyVendor(vendor) ?: DeviceClassifier.CAT_OTHER
        return Finding.Host(
            sessionId = sessionId, ip = ip,
            vendor = vendor, mac = mac,
            category = category,
            osGuess = os ?: if (ports.isEmpty()) "alive, no open ports found" else null,
            flagged = ports.any { it == 23 || it == 5555 }
        )
    }

    private fun emitHost(
        sessionId: String, ip: String, hostname: String?, mac: String?,
        ports: List<Int>, banners: Map<Int, String>, categoryOverride: String?
    ) {
        val vendor = ouiVendor(mac)
        FindingBus.emit(
            Finding.Host(
                sessionId = sessionId, ip = ip, hostname = hostname,
                vendor = vendor, mac = mac,
                category = categoryOverride,
                osGuess = DeviceClassifier.guessOs(ports, banners, vendor, hostname),
                flagged = ports.any { it == 23 || it == 5555 }
            )
        )
        ports.forEach { p ->
            val info = PORT_INFO[p]
            val serviceLine = info?.let { "${it.first} — ${it.second}" } ?: "port $p"
            FindingBus.emit(
                Finding.OpenPort(
                    sessionId = sessionId, ip = ip, port = p,
                    service = serviceLine,
                    product = bannerProduct(p, banners[p]),
                    flagged = p == 23 || p == 5555
                )
            )
        }
    }

    /** Last PUBLIC_IP emitted — lets the parallel fetch report into the context. */
    private val lastPublicIp = kotlinx.coroutines.flow.MutableStateFlow<Finding.PublicIp?>(null)

    /** true when the WAN-TCP egress test/fetch timed out — LAN probes still
     *  worked → the router is refusing NEW forwarded TCP from this client
     *  (flood guard or broken NAT), while ICMP-NAAT still passes. Surfaced
     *  in the status strip so "public IP unavailable" has an explanation. */
    @Volatile var publicIpTcpBlocked: Boolean = false
        private set

    /** Reset at the start of every sweep. */
    internal fun resetDiagnostics() {
        publicIpTcpBlocked = false
    }

    /** Dedicated 1-thread dispatcher: the sweep floods Dispatchers.IO with
     *  5,819 probe jobs — a fetch launched onto that pool starves until the
     *  storm ends and then blows its own timeout (observed on-device). */
    private val publicIpDispatcher = java.util.concurrent.Executors.newSingleThreadExecutor { r ->
        Thread(r, "netguard-publicip").also { it.isDaemon = true }
    }.asCoroutineDispatcher()

    /** Public/edge IP via ipify, then RDAP org/country/ASN enrichment. */
    private suspend fun fetchPublicIp(sessionId: String): Finding.PublicIp? =
        withContext(publicIpDispatcher) {
            // 12s per attempt: pinned-network TLS handshake competes with the
            // sweep's probe storm on the same wlan0 queue — 6s timed out
            // on-device. getWithFallback then retries over the DEFAULT
            // network (cellular) — on-device the router NATed WAN only for
            // default clients, so the pinned wlan0 path had no WAN.
            val resp = kotlinx.coroutines.withTimeoutOrNull(40000) {
                ProtectedHttp.getWithFallback("https://api.ipify.org/", minIntervalMs = 0)
                    ?: ProtectedHttp.getWithFallback("https://api64.ipify.org/", minIntervalMs = 0)
            } ?: run {
                android.util.Log.w("NetGuardSweep", "public IP fetch failed/timeout (both providers)")
                publicIpTcpBlocked = true
                return@withContext null
            }
            val code = resp.first
            val body = resp.second
            if (code != 200) return@withContext null
            val ip = body.trim().takeIf { it.matches(Regex("[0-9.]{7,15}")) } ?: return@withContext null

            var org: String? = null; var country: String? = null; var asn: Int? = null
            runCatching {
                val rdap = kotlinx.coroutines.withTimeoutOrNull(8000) {
                    ProtectedHttp.get("https://rdap.org/ip/$ip", minIntervalMs = 0)
                } ?: return@runCatching
                if (rdap.first in 200..299) {
                    val rbody = rdap.second
                    org = Regex("\"name\"\\s*:\\s*\"([^\"]{2,80})\"").find(rbody)?.groupValues?.get(1)
                        ?: Regex("\"handle\"\\s*:\\s*\"([^\"]+)\"").find(rbody)?.groupValues?.get(1)
                    country = Regex("\"country\"\\s*:\\s*\"([^\"]+)\"").find(rbody)?.groupValues?.get(1)
                    asn = Regex("\\bAS(\\d{2,6})\\b", RegexOption.IGNORE_CASE).find(rbody)
                        ?.groupValues?.get(1)?.toIntOrNull()
                }
            }
            android.util.Log.d("NetGuardSweep", "public IP resolved: $ip org=$org")
            val finding = Finding.PublicIp(sessionId = sessionId, ip = ip,
                org = org, country = country, asn = asn)
            lastPublicIp.value = finding
            FindingBus.emit(finding)
            finding
        }

    private fun intToIp(ip: Int): String =
        "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 8) and 0xFF}.${ip and 0xFF}"

    /** WifiManager.dhcpInfo is little-endian: 192.168.2.252 → LSB-first. */
    private fun intToIpReversed(ip: Int): String =
        "${ip and 0xFF}.${(ip shr 8) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 24) and 0xFF}"

    /** Cheap internet check: 1.1.1.1:443 — used to qualify AP-isolation (LAN dead + WAN alive). */
    private suspend fun hasInternet(): Boolean = withContext(Dispatchers.IO) {
        try {
            Socket().use { s ->
                SocketProtector.protect(s)
                s.bind(null)
                s.connect(InetSocketAddress(InetAddress.getByName("1.1.1.1"), 443), 2500)
                true
            }
        } catch (_: Exception) {
            false
        }
    }
}