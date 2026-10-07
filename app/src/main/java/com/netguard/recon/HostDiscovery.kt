package com.netguard.recon

import com.netguard.core.DeviceClassifier
import com.netguard.core.Finding
import com.netguard.core.FindingBus
import com.netguard.core.SocketProtector
import com.netguard.vpn.NetGuardVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Collections

/**
 * Layer-3 host discovery without root: reads the kernel ARP table (devices
 * that recently talked to you) and does an active TCP-connect sweep of the
 * /24 on a small set of common ports.
 */
class HostDiscovery {

    companion object {
        private val COMMON_PORTS = intArrayOf(22, 53, 80, 443, 445, 3389, 5353, 8080, 8009, 9100)
        private const val CONNECT_TIMEOUT_MS = 250

        // Starter OUI table — swap in the full IEEE registry later when it matters.
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
    }

    /** Instant: whatever the kernel's neighbor cache currently holds. */
    suspend fun scanArpTable(sessionId: String): List<Finding.Host> = withContext(Dispatchers.IO) {
        val hosts = mutableListOf<Finding.Host>()
        runCatching {
            File("/proc/net/arp").readLines().drop(1).forEach { line ->
                val parts = line.trim().split(Regex("\\s+"))
                if (parts.size >= 6) {
                    val ip = parts[0]
                    val mac = parts[3].uppercase()
                    val flags = parts[2]
                    // flags 0x0 = incomplete entry (probe unanswered); skip those
                    if (flags != "0x0" && mac.isNotBlank() && mac != "00:00:00:00:00:00") {
                        hosts += Finding.Host(sessionId = sessionId, ip = ip, mac = mac, vendor = ouiVendor(mac))
                    }
                }
            }
        }
        hosts.distinctBy { it.ip }.also { list -> list.forEach { FindingBus.emit(it) } }
    }

    /** Slower: TCP-connect probe of the whole /24, then re-read ARP for MAC enrichment. */
    suspend fun activeSweep(sessionId: String, subnet: String) = withContext(Dispatchers.IO) {
        val aliveIps = Collections.synchronizedSet(mutableSetOf<String>())

        coroutineScope {
            (2..254).forEach { last ->
                launch {
                    val ip = "$subnet.$last"
                    val open = mutableListOf<Int>()
                    for (port in COMMON_PORTS) {
                        try {
                            Socket().use { s ->
                                SocketProtector.protect(s) // bypass our own VPN tunnel
                                s.bind(null)
                                s.connect(InetSocketAddress(InetAddress.getByName(ip), port), CONNECT_TIMEOUT_MS)
                                open += port
                            }
                        } catch (_: Exception) {
                        }
                    }
                    if (open.isNotEmpty()) {
                        aliveIps += ip
                        open.forEach {
                            FindingBus.emit(
                                Finding.OpenPort(sessionId = sessionId, ip = ip, port = it,
                                    service = NetGuardVpnService.SERVICE_PORTS[it])
                            )
                        }
                    }
                }
            }
        }

        // Enrich with MACs from the (now warmed-up) ARP table.
        val arpByIp = runCatching {
            File("/proc/net/arp").readLines().drop(1)
                .map { it.trim().split(Regex("\\s+")) }
                .filter { it.size >= 4 }
                .associate { parts -> parts[0] to parts[3].uppercase() }
        }.getOrDefault(emptyMap())

        aliveIps.forEach { ip ->
            val mac = arpByIp[ip]?.takeIf { it != "00:00:00:00:00:00" }
            val vendor = mac?.let(::ouiVendor)
            FindingBus.emit(
                Finding.Host(sessionId = sessionId, ip = ip, mac = mac, vendor = vendor,
                    category = DeviceClassifier.classifyVendor(vendor))
            )
        }
    }

    private fun ouiVendor(mac: String): String? {
        if (mac.length < 8) return null
        val prefix = mac.take(8).uppercase()
        return OUI.entries.firstOrNull { it.key == prefix }?.value
    }
}