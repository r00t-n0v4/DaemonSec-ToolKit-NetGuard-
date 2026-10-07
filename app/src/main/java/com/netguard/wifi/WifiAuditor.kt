package com.netguard.wifi

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import androidx.core.content.ContextCompat
import com.netguard.core.DeviceClassifier
import com.netguard.core.Finding
import com.netguard.core.FindingBus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/**
 * WiFi Tier 1 audit — no external hardware required.
 *
 * Full sweep: every visible AP gets recorded as a WIFI_AP finding (SSID,
 * BSSID, channel, security, RSSI) — the raw airspace picture, not just the
 * anomalies. Multiple passes because Android caches scan results and each
 * startScan() rotates in what the chip has newly heard; the aggregate is the
 * closest thing to "all available networks" the platform allows.
 *
 * On top of the listing, the analyzers run:
 *  - channel congestion: per-channel AP counts, "move to channel N" advisory
 *  - evil-twin: same SSID broadcast by multiple BSSIDs w/ differing security
 *  - security downgrade: weak (open/WEP/WPA-TKIP) sibling next to a strong AP
 *
 * WiFi Tier 2 (monitor mode via OTG dongle) is deliberately NOT built.
 */
class WifiAuditor(private val context: Context) {

    data class ApEntry(
        val ssid: String?,
        val bssid: String,
        val channel: Int,
        val security: String,
        val rssi: Int,
        val category: String? = null
    )

    data class SweepResult(val aps: List<ApEntry>, val anomalies: List<Finding.WifiAnomaly>)

    suspend fun sweep(sessionId: String, passes: Int = 4): SweepResult = withContext(Dispatchers.IO) {
        val aggregated = LinkedHashMap<String, ScanResult>() // BSSID -> latest result
        repeat(passes) {
            scanOnce().forEach { aggregated[it.BSSID] = it }
            delay(1500)
        }

        val aps = aggregated.values.map { r ->
            val ssidText = r.SSID?.takeIf { it.isNotBlank() } ?: "<hidden>"
            val category = DeviceClassifier.categorize(
                name = ssidText.takeIf { it != "<hidden>" },
                serviceUuids = emptyList(),
                companies = emptyList()
            )
            ApEntry(
                ssid = ssidText,
                bssid = r.BSSID,
                channel = frequencyToChannel(r.frequency),
                security = describeSecurity(r.capabilities ?: ""),
                rssi = r.level,
                category = ssidText.takeIf { it != "<hidden>" }?.let { _ -> category } ?: DeviceClassifier.CAT_HIDDEN
            )
        }

        // Airspace listing: every AP as its own finding.
        aps.forEach { ap ->
            FindingBus.emit(
                Finding.WifiAp(
                    sessionId = sessionId,
                    ssid = ap.ssid,
                    bssid = ap.bssid,
                    channel = ap.channel,
                    security = ap.security,
                    rssi = ap.rssi,
                    category = ap.category,
                    flagged = DeviceClassifier.isAlertCategory(ap.category ?: "")
                )
            )
        }

        val anomalies = analyze(sessionId, aggregated.values.toList())
        SweepResult(aps, anomalies)
    }

    @Suppress("DEPRECATION")
    private suspend fun scanOnce(): List<ScanResult> = withContext(Dispatchers.IO) {
        val wifi = context.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            ?: return@withContext emptyList()
        if (!hasLocationPermission()) return@withContext emptyList()
        try {
            if (!wifi.isWifiEnabled) return@withContext emptyList()
            wifi.startScan()
            delay(1200) // give the chip a beat to deliver results
            wifi.scanResults ?: emptyList()
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun analyze(sessionId: String, results: List<ScanResult>): List<Finding.WifiAnomaly> {
        val anomalies = mutableListOf<Finding.WifiAnomaly>()

        data class Ap(val ssid: String, val bssid: String, val caps: String, val level: Int, val freq: Int)

        val bySsid = results
            .filter { !it.SSID.isNullOrBlank() }
            .groupBy { it.SSID }
            .mapValues { (_, list) ->
                list.map { Ap(it.SSID, it.BSSID, it.capabilities ?: "", it.level, it.frequency) }
            }

        for ((ssid, aps) in bySsid) {
            // security downgrade: strongest AP is WPA2/3 but a sibling is open/legacy
            val strongest = aps.maxByOrNull { it.level } ?: continue
            val strongSecure = isSecure(strongest.caps)
            aps.forEach { ap ->
                if (strongSecure && (!isSecure(ap.caps) || isLegacyWeak(ap.caps))) {
                    val detail = "SSID '$ssid' has a weak sibling AP: ${describe(ap.caps)} " +
                        "alongside ${describe(strongest.caps)} — downgrade/downgrade-decoy pattern (possible evil twin)"
                    emitAnomaly(sessionId, ssid, ap.bssid, detail, kind = "DOWNGRADE", flagged = true, anomalies)
                }
            }

            // evil twin heuristic: same SSID, several APs, differing security configs
            val securityModes = aps.map { normalizeSecurity(it.caps) }.toSet()
            if (aps.size >= 2 && securityModes.size >= 2) {
                val detail = "SSID '$ssid' broadcast by ${aps.size} BSSIDs with differing security " +
                    "(${securityModes.joinToString(", ")}) — evil-twin pattern"
                emitAnomaly(sessionId, ssid, aps.first().bssid, detail, kind = "EVIL_TWIN", flagged = true, anomalies)
            }
        }

        // venue-SSID rule: a lone visible AP carrying a branded venue name with
        // OPEN/UNKNOWN security — the classic café/airport rogue-AP spoof. The
        // "same SSID twice" pattern can't fire when only the twin is in range.
        bySsid.forEach { (ssid, aps) ->
            if (isVenueSsid(ssid)) {
                aps.forEach { ap ->
                    val mode = normalizeSecurity(ap.caps)
                    if (mode == "OPEN" || mode == "UNKNOWN") {
                        val detail = "'$ssid' matches a known venue SSID and is $mode — " +
                            "probable evil twin (rogue venue spoof). Verify SSID ownership before connecting."
                        emitAnomaly(sessionId, ssid, ap.bssid, detail, kind = "EVIL_TWIN", flagged = true, anomalies)
                    }
                }
            }
        }

        // channel congestion: per-channel occupancy of the 2.4 GHz band
        val band24 = results.filter { it.frequency in 2400..2500 }
        if (band24.size >= 4) {
            val perChannel = band24.groupingBy { frequencyToChannel(it.frequency) }.eachCount()
            val busiest = perChannel.maxByOrNull { it.value }
            val quiet24 = listOf(1, 6, 11).minByOrNull { perChannel[it] ?: 0 }
            if (busiest != null && busiest.value >= 4 && quiet24 != null) {
                val detail = "2.4 GHz congestion: ${band24.size} APs; busiest channel ${busiest.key} " +
                    "(${busiest.value} APs). Channel $quiet24 is clearest."
                emitAnomaly(sessionId, null, null, detail, kind = "CONGESTION", flagged = false, anomalies)
            }
        }

        // WEP / open networks anywhere in range
        results.filter { (it.capabilities ?: "").let { c -> c.contains("WEP") || c.isBlank() } }
            .forEach { r ->
                val detail = "Open/WEP network in range: '${r.SSID.ifBlank { "<hidden>" }}' (${describe(r.capabilities ?: "")})"
                emitAnomaly(sessionId, r.SSID.ifBlank { null }, r.BSSID, detail, kind = "OPEN_NET", flagged = false, anomalies)
            }

        return anomalies
    }

    private fun emitAnomaly(sessionId: String, ssid: String?, bssid: String?, detail: String, kind: String, flagged: Boolean, sink: MutableList<Finding.WifiAnomaly>) {
        val finding = Finding.WifiAnomaly(
            sessionId = sessionId, ssid = ssid, bssid = bssid,
            detail = detail, kind = kind, flagged = flagged
        )
        FindingBus.emit(finding)
        sink += finding
    }

    private fun isSecure(caps: String): Boolean =
        caps.contains("WPA") || caps.contains("RSN") || caps.contains("WEP")

    /**
     * Venue SSIDs worth flagging as probable evil twins even when only ONE
     * BSSID is visible (the "same SSID twice" pattern can't fire for a lone
     * rogue AP). Branded/venue networks users blindly trust; UNKNOWN or OPEN
     * security on them makes the spoof near-certain. Extend as needed.
     */
    private val venueSsidPatterns = listOf(
        "starbucks", "mcdonald", "mcdonalds", "airport", "marriott", "hilton",
        "deltawifi", "walmart", "target guest", "bestbuy", "tim hortons",
        "timhortons", "shaw open", "shawopen", "bell_hotspot", "bell hotspot",
        "publicwifi", "public wifi", "freewifi", "free wifi", "panera", "chipotle"
    )

    private fun isVenueSsid(ssid: String?): Boolean {
        if (ssid.isNullOrBlank()) return false
        val s = ssid.lowercase()
        return venueSsidPatterns.any { s.contains(it) }
    }

    private fun isLegacyWeak(caps: String): Boolean =
        caps.contains("WEP") || (caps.contains("WPA ") || caps.contains("WPA-")) && !caps.contains("RSN")

    private fun normalizeSecurity(caps: String): String = when {
        caps.contains("RSN") && caps.contains("SAE") -> "WPA3"
        caps.contains("RSN") -> "WPA2"
        caps.contains("WPA") -> "WPA"
        caps.contains("WEP") -> "WEP"
        caps.isBlank() -> "OPEN"
        else -> "UNKNOWN"
    }

    private fun describeSecurity(caps: String): String =
        normalizeSecurity(caps) + if (caps.contains("TKIP")) "+TKIP" else ""

    private fun describe(caps: String): String = describeSecurity(caps)

    /** Frequency to 2.4/5/6 GHz channel number. */
    private fun frequencyToChannel(freq: Int): Int = when {
        freq in 2412..2484 -> (freq - 2407) / 5
        freq in 5170..5825 -> (freq - 5000) / 5
        freq in 5955..7115 -> (freq - 5950) / 5
        else -> 0
    }

    private fun hasLocationPermission(): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED
}