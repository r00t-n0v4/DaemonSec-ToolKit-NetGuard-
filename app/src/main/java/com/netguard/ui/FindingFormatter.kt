package com.netguard.ui

import com.netguard.core.DeviceClassifier
import com.netguard.core.Finding
import com.netguard.db.FindingEntity
import kotlinx.serialization.json.Json

private val formatJson = Json { ignoreUnknownKeys = true }

/**
 * Turns a raw FindingEntity — a type discriminator plus a JSON blob — into
 * a short headline + detail line. This is what makes the scan-log-style
 * Findings feed actually scannable; without it every row is a truncated
 * JSON dump, which looks like a terminal but reads like a debugger.
 */
object FindingFormatter {
    data class Summary(val headline: String, val detail: String)

    /** Category label for BLE grouping (Nearby tab); falls back to "Other". */
    fun summaryCategory(entity: FindingEntity): String =
        DeviceClassifier.categoryOfEntity(entity.payloadJson)
            ?: DeviceClassifier.CAT_OTHER

    /**
     * Human SOURCE tag for a finding row (Findings tab badge): which sensor
     * produced it — Bluetooth / WiFi / LAN / Traffic / Recon / Info.
     */
    fun sourceLabel(entity: FindingEntity): String = when (entity.type) {
        "BLE", "GATT" -> "Bluetooth"
        "WIFI_AP", "WIFI_ANOMALY" -> "WiFi"
        "HOST", "OPEN_PORT" -> "LAN scan"
        "PUBLIC_IP" -> "Network info"
        "ATTACKER_LOOKUP", "OSINT" -> "OSINT"
        "WEB" -> "Web recon"
        "TRAFFIC" -> "Traffic"
        else -> "Info"
    }

    fun summarize(entity: FindingEntity): Summary = try {
        when (entity.type) {
            "HOST" -> {
                val f = formatJson.decodeFromString(Finding.Host.serializer(), entity.payloadJson)
                val bits = buildList {
                    add(f.ip)
                    if (f.ip == f.hostname || f.hostname == "this-phone" || f.hostname == "gateway") {
                        // marker hostnames: skip detail duplication
                    } else f.hostname?.let { add(it) }
                    f.vendor?.let { add(it) }
                    f.mac?.let { add(it) }
                }
                Summary(
                    headline = when (f.category) {
                        "This Phone" -> "📱 THIS PHONE — ${f.ip}"
                        "Gateway/Router" -> "🌐 GATEWAY — ${f.ip}"
                        else -> f.ip
                    },
                    detail = listOfNotNull(
                        bits.drop(1).joinToString(" · ").ifBlank { null },
                        f.osGuess?.let { "OS: $it" }
                    ).joinToString(" — ").ifBlank { "host discovered" }
                )
            }
            "OPEN_PORT" -> {
                val f = formatJson.decodeFromString(Finding.OpenPort.serializer(), entity.payloadJson)
                Summary(
                    headline = "${f.ip}:${f.port}${if (f.flagged) "  ⚠" else ""}",
                    detail = listOfNotNull(
                        f.product?.let { it } ?: f.service,
                        if (f.flagged) "EXPOSED/RISKY" else null
                    ).joinToString(" · ")
                )
            }
            "PUBLIC_IP" -> {
                val f = formatJson.decodeFromString(Finding.PublicIp.serializer(), entity.payloadJson)
                Summary(
                    headline = "🌍 PUBLIC IP — ${f.ip}",
                    detail = listOfNotNull(f.org, f.country, f.asn?.let { "AS$it" })
                        .joinToString(" · ").ifBlank { "your network's internet-facing address" }
                )
            }
            "TRAFFIC" -> {
                val f = formatJson.decodeFromString(Finding.TrafficEvent.serializer(), entity.payloadJson)
                Summary(
                    headline = f.sni ?: "${f.dstIp}:${f.dstPort}",
                    detail = listOfNotNull(f.protocol, f.appPackage, f.flagReason)
                        .joinToString(" · ")
                )
            }
            "ATTACKER_LOOKUP" -> {
                val f = formatJson.decodeFromString(Finding.AttackerLookup.serializer(), entity.payloadJson)
                Summary(
                    headline = f.ip,
                    detail = listOfNotNull(f.org, f.country, f.asn?.let { "AS$it" })
                        .joinToString(" · ")
                        .ifBlank { f.note ?: "lookup" }
                )
            }
            "BLE" -> {
                val f = formatJson.decodeFromString(Finding.BleDevice.serializer(), entity.payloadJson)
                Summary(
                    headline = f.trackerType ?: f.name ?: f.address,
                    detail = listOfNotNull(
                        f.category,
                        f.name?.takeIf { it != (f.trackerType ?: f.name) }?.let { "${it} ${f.address}" } ?: f.address,
                        "RSSI ${f.rssi}"
                    ).joinToString(" · ")
                )
            }
            "WIFI_ANOMALY" -> {
                val f = formatJson.decodeFromString(Finding.WifiAnomaly.serializer(), entity.payloadJson)
                // Anomalies often have NO ssid/bssid (congestion reports are
                // band-wide) — headline = the anomaly kind + the finding's
                // own SSID when present, never a bare crushed "wifi".
                val head = when {
                    !f.ssid.isNullOrBlank() -> f.ssid ?: ""
                    !f.bssid.isNullOrBlank() -> f.bssid ?: ""
                    else -> (f.kind ?: "wifi").lowercase()
                        .replaceFirstChar { it.uppercase() }
                }
                Summary(headline = head, detail = f.detail)
            }
            "WIFI_AP" -> {
                val f = formatJson.decodeFromString(Finding.WifiAp.serializer(), entity.payloadJson)
                Summary(
                    headline = f.ssid ?: "<hidden>",
                    detail = "${f.security} · ch${f.channel} · ${f.rssi}dBm · ${f.bssid}"
                )
            }
            "WEB" -> {
                val f = formatJson.decodeFromString(Finding.Web.serializer(), entity.payloadJson)
                val tags = listOfNotNull(f.severity?.let { "sev=$it" }, f.owasp)
                Summary(
                    headline = "[${f.kind}] ${f.target}",
                    detail = f.detail + if (tags.isNotEmpty()) " (${tags.joinToString(", ")})" else ""
                )
            }
            "OSINT" -> {
                val f = formatJson.decodeFromString(Finding.OsintHit.serializer(), entity.payloadJson)
                Summary(headline = "[${f.kind}] ${f.identifier}", detail = f.detail)
            }
            "GATT" -> {
                val f = formatJson.decodeFromString(Finding.GattDevice.serializer(), entity.payloadJson)
                Summary(
                    headline = f.name ?: f.address,
                    detail = "${f.services.size} services" +
                        (if (f.writableUnencrypted > 0) " · ${f.writableUnencrypted} WRITABLE-UNENCRYPTED" else "")
                )
            }
            else -> Summary(entity.type, entity.payloadJson.take(80))
        }
    } catch (e: Exception) {
        // Schema drift between what's stored and what's expected shouldn't
        // crash the feed — fall back to the raw type/JSON like before.
        Summary(entity.type, entity.payloadJson.take(80))
    }
}