package com.netguard.report

import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import com.netguard.core.Finding
import com.netguard.db.FindingDao
import com.netguard.db.FindingEntity
import com.netguard.db.SessionDao
import com.netguard.db.SessionEntity
import kotlinx.serialization.json.Json
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.TimeZone

/**
 * Markdown + JSON report writer. Includes the session's scope declaration on
 * every page (that's the whole point of a pentest report) and a
 * "new since last session" diff so repeat scans read as deltas, not walls.
 */
class ReportExporter(
    private val sessionDao: SessionDao,
    private val findingDao: FindingDao
) {

    /** Decode payloads for readable text (best-effort — schema drift shouldn't kill a report). */
    private val json = Json { ignoreUnknownKeys = true; prettyPrint = true }

    /** Names MainActivity's export flow calls. */
    suspend fun exportMarkdown(sessionId: String, file: File): File? = exportSession(sessionId, file)

    suspend fun exportJson(sessionId: String, file: File): File? = exportJsonSession(sessionId, file)

    suspend fun exportSession(sessionId: String, file: File): File? {
        val session = sessionDao.getById(sessionId) ?: return null
        val findings = findingDao.getForSession(sessionId)
        val previous = sessionDao.previousBefore(session.startedAt)
        val previousHostIps = previous?.let { prev ->
            findingDao.getForSession(prev.id)
                .filter { it.type == "HOST" }
                .mapNotNull { decodeHost(it)?.ip }
                .toSet()
        } ?: emptySet()

        val markdown = renderMarkdown(
            session = session,
            findings = findings,
            previousLabel = previous?.label,
            previousHostIps = previousHostIps
        )
        file.writeText(markdown)
        return file
    }

    suspend fun exportJsonSession(sessionId: String, file: File): File? {
        val session = sessionDao.getById(sessionId) ?: return null
        val findings = findingDao.getForSession(sessionId)
        val previous = sessionDao.previousBefore(session.startedAt)
        val previousHostIps = previous?.let { prev ->
            findingDao.getForSession(prev.id)
                .filter { it.type == "HOST" }
                .mapNotNull { decodeHost(it)?.ip }
                .toSet()
        } ?: emptySet()

        val envelope = buildString {
            appendLine("{")
            appendLine("  \"report\": \"NetGuard session export\",")
            appendLine("  \"generatedAt\": ${System.currentTimeMillis()},")
            appendLine("  \"session\": {")
            appendLine("    \"id\": \"${session.id}\",")
            appendLine("    \"label\": ${json enc session.label},")
            appendLine("    \"scopeDeclaration\": ${json enc session.scopeDeclaration},")
            appendLine("    \"startedAt\": ${session.startedAt},")
            appendLine("    \"endedAt\": ${session.endedAt ?: "null"},")
            appendLine("    \"previousSession\": ${previous?.id?.let { json enc it } ?: "null"}")
            appendLine("  },")
            appendLine("  \"newHostsSinceLastSession\": [")
            val newHosts = findings.filter { it.type == "HOST" && decodeHost(it)?.ip !in previousHostIps }
                .mapNotNull { decodeHost(it)?.ip }
                .distinct()
            newHosts.forEachIndexed { i, ip -> append("    ${json enc ip}${if (i == newHosts.size - 1) "" else ","}").appendLine() }
            appendLine("  ],")
            appendLine("  \"findings\": [")
            findings.forEachIndexed { i, f ->
                val type = json enc f.type
                val payload = f.payloadJson
                val comma = if (i == findings.size - 1) "" else ","
                append("    {\"type\": $type, \"flagged\": ${f.flagged}, \"timestamp\": ${f.timestamp}, \"payload\": $payload}$comma")
                appendLine()
            }
            appendLine("  ]")
            appendLine("}")
        }
        file.writeText(envelope)
        return file
    }

    /**
     * PDF export: same content as the Markdown report, rendered to a real
     * PDF via android.graphics.pdf.PdfDocument — no external deps, works on
     * any phone. Monospace, auto-paginated, scope declaration on page 1.
     */
    suspend fun exportPdf(sessionId: String, file: File): File? {
        val session = sessionDao.getById(sessionId) ?: return null
        val findings = findingDao.getForSession(sessionId)
        val previous = sessionDao.previousBefore(session.startedAt)
        val previousHostIps = previous?.let { prev ->
            findingDao.getForSession(prev.id)
                .filter { it.type == "HOST" }
                .mapNotNull { decodeHost(it)?.ip }
                .toSet()
        } ?: emptySet()
        val markdown = renderMarkdown(session, findings, previous?.label, previousHostIps)
        writePdf(markdown, file)
        return file
    }

    private fun writePdf(content: String, file: File) {
        val pageWidth = 595
        val pageHeight = 842
        val margin = 40f
        val doc = PdfDocument()
        val body = Paint().apply {
            typeface = Typeface.MONOSPACE
            textSize = 8.5f
            isAntiAlias = true
        }
        val title = Paint().apply {
            typeface = Typeface.DEFAULT_BOLD
            textSize = 14f
            isAntiAlias = true
        }
        val heading = Paint().apply {
            typeface = Typeface.MONOSPACE
            textSize = 10f
            isAntiAlias = true
            isFakeBoldText = true
        }

        var pageNumber = 0
        var page: PdfDocument.Page? = null
        var canvas = android.graphics.Canvas()
        var y = 0f

        fun startNewPage() {
            page?.let { doc.finishPage(it) }
            pageNumber++
            page = doc.startPage(PdfDocument.PageInfo.Builder(pageWidth, pageHeight, pageNumber).create())
            canvas = page!!.canvas
            y = margin
        }

        fun ensureSpace(needed: Float) {
            if (y + needed > pageHeight - margin) startNewPage()
        }

        startNewPage()
        canvas.drawText("NetGuard Session Report", margin, y, title)
        y += 20f

        for (raw in content.lines().drop(1)) { // skip the md title; drawn above
            val line = raw.replace("**", "").replace("`", "").trimEnd()
            if (line.isBlank()) {
                y += 5f
                continue
            }
            val paintToUse = when {
                line.startsWith("#") -> heading.also { y += 4f }
                line.startsWith("- ") -> body
                line.startsWith("_") && line.endsWith("_") -> body
                else -> body
            }
            val text = line.removePrefix("#").trim() + if (raw.startsWith("- ")) "" else ""
            ensureSpace(12f)
            var remaining = if (raw.startsWith("- ")) "- $text" else text
            var drewPrefixX = margin
            while (remaining.isNotBlank()) {
                val fits = paintToUse.breakText(remaining, true, pageWidth - 2 * margin, null)
                val chunk = remaining.take(fits)
                canvas.drawText(chunk, drewPrefixX, y, paintToUse)
                remaining = remaining.drop(fits)
                y += 11f
                ensureSpace(12f)
                drewPrefixX = margin + 12f
            }
        }
        page?.let { doc.finishPage(it) }

        file.outputStream().use { doc.writeTo(it) }
        doc.close()
    }

    private fun decodeHost(entity: FindingEntity): Finding.Host? = try {
        json.decodeFromString(Finding.Host.serializer(), entity.payloadJson)
    } catch (_: Exception) {
        null
    }

    private fun renderMarkdown(
        session: SessionEntity,
        findings: List<FindingEntity>,
        previousLabel: String?,
        previousHostIps: Set<String>
    ): String {
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss").apply { timeZone = TimeZone.getDefault() }
        val flagged = findings.filter { it.flagged }
        val grouped = findings.groupBy { it.type }

        return buildString {
            appendLine("# NetGuard Session Report")
            appendLine()
            appendLine("- **Session:** ${session.label}")
            appendLine("- **Scope declaration:** ${session.scopeDeclaration}")
            appendLine("- **Started:** ${fmt.format(Date(session.startedAt))}")
            session.endedAt?.let { appendLine("- **Ended:** ${fmt.format(Date(it))}") }
            previousLabel?.let { appendLine("- **Previous session:** $it") }
            appendLine("- **Total findings:** ${findings.size} (${flagged.size} flagged)")
            appendLine()

            // ---- diff section: what's new since the previous session ----
            if (previousHostIps.isNotEmpty()) {
                val newHosts = grouped["HOST"].orEmpty()
                    .mapNotNull { decodeHost(it)?.ip }
                    .filter { it !in previousHostIps }
                    .distinct()
                if (newHosts.isNotEmpty()) {
                    appendLine("## New hosts since last session")
                    appendLine()
                    newHosts.forEach { appendLine("- $it") }
                    appendLine()
                }
            }

            // ---- flagged first ----
            if (flagged.isNotEmpty()) {
                appendLine("## Flagged")
                appendLine()
                flagged.forEach { appendLine("- `${it.type}` @ ${fmt.format(Date(it.timestamp))} — ${short(it.payloadJson)}") }
                appendLine()
            }

            // ---- everything, grouped by type ----
            val typeTitles = mapOf(
                "HOST" to "Hosts discovered",
                "OPEN_PORT" to "Open ports",
                "TRAFFIC" to "Traffic observations",
                "ATTACKER_LOOKUP" to "IP intelligence",
                "BLE" to "BLE devices / trackers",
                "WIFI_ANOMALY" to "WiFi anomalies",
                "WIFI_AP" to "Wireless airspace (all APs seen)",
                "WEB" to "Web recon / testing",
                "OSINT" to "OSINT hits",
                "GATT" to "BLE GATT profiles",
                "PUBLIC_IP" to "Public IP"
            )
            typeTitles.forEach { (type, title) ->
                val rows = grouped[type].orEmpty()
                if (rows.isNotEmpty()) {
                    appendLine("## $title")
                    appendLine()
                    rows.forEach {
                        val flagMark = if (it.flagged) " **[FLAGGED]**" else ""
                        appendLine("- ${fmt.format(Date(it.timestamp))}$flagMark — ${short(it.payloadJson)}")
                    }
                    appendLine()
                }
            }

            // ---- leftovers (unknown types) ----
            val known = typeTitles.keys
            val others = findings.filter { it.type !in known }
            if (others.isNotEmpty()) {
                appendLine("## Other findings")
                appendLine()
                others.forEach { appendLine("- `${it.type}` @ ${fmt.format(Date(it.timestamp))} — ${short(it.payloadJson)}") }
                appendLine()
            }

            appendLine("---")
            appendLine()
            appendLine("_Generated on-device by NetGuard. Scope: \"${session.scopeDeclaration}\"._")
        }
    }

    /** Compact payload for report bullets: try a decoded summary, else trimmed JSON. */
    private fun short(payloadJson: String): String {
        decodeHost(payloadJson)?.let { h ->
            val bits = listOfNotNull(ch(h.hostname), ch(h.vendor), ch(h.mac))
            val os = h.osGuess?.let { " — OS: $it" } ?: ""
            val label = when (h.category) {
                "This Phone" -> "THIS PHONE"
                "Gateway/Router" -> "GATEWAY"
                else -> null
            }
            return ((label?.let { "$it (${h.ip})" } ?: h.ip) + if (bits.isEmpty()) "" else " · " + bits.joinToString(" · ")) + os
        }
        decodeOpenPort(payloadJson)?.let { p ->
            val svc = p.product ?: p.service ?: ""
            return "${p.ip}:${p.port} ${svc}${if (p.flagged) "  [RISKY]" else ""}".trim()
        }
        decodePublicIp(payloadJson)?.let { pi ->
            return "PUBLIC IP ${pi.ip}" + listOfNotNull(pi.org, pi.country,
                pi.asn?.let { "AS$it" }).joinToString(" · ", prefix = " — ")
        }
        decodeWifiAnomaly(payloadJson)?.let { w ->
            return listOfNotNull(ch(w.ssid), ch(w.bssid), w.detail).joinToString(" · ")
        }
        decodeWifiAp(payloadJson)?.let { a ->
            return "ch${a.channel} ${a.security} ${a.rssi}dBm — ${a.ssid ?: "?"} [${a.bssid}]"
        }
        decodeWeb(payloadJson)?.let { w ->
            val tags = listOfNotNull(
                w.severity?.let { "sev=$it" },
                w.owasp?.let { "owasp=$it" }
            ).joinToString(" ")
            return "[${w.kind}] ${w.target} — ${w.detail}" + (if (tags.isNotBlank()) " ($tags)" else "")
        }
        decodeOsint(payloadJson)?.let { o ->
            return "[${o.kind}] ${o.identifier} — ${o.detail}"
        }
        decodeGatt(payloadJson)?.let { g ->
            return "${g.name ?: g.address}: ${g.services.size} services, " +
                "${g.writableUnencrypted} writable-unencrypted chars"
        }
        return payloadJson.take(120)
    }

    /** null-safe blank collapse for optional strings in summaries. */
    private fun ch(s: String?): String? = s?.takeIf { it.isNotBlank() }

    private fun decodeWifiAp(payloadJson: String): Finding.WifiAp? = try {
        json.decodeFromString(Finding.WifiAp.serializer(), payloadJson)
    } catch (_: Exception) { null }

    private fun decodePublicIp(payloadJson: String): Finding.PublicIp? = try {
        json.decodeFromString(Finding.PublicIp.serializer(), payloadJson)
    } catch (_: Exception) { null }

    private fun decodeWeb(payloadJson: String): Finding.Web? = try {
        json.decodeFromString(Finding.Web.serializer(), payloadJson)
    } catch (_: Exception) { null }

    private fun decodeOsint(payloadJson: String): Finding.OsintHit? = try {
        json.decodeFromString(Finding.OsintHit.serializer(), payloadJson)
    } catch (_: Exception) { null }

    private fun decodeGatt(payloadJson: String): Finding.GattDevice? = try {
        json.decodeFromString(Finding.GattDevice.serializer(), payloadJson)
    } catch (_: Exception) { null }

    private fun decodeHost(payloadJson: String): Finding.Host? = try {
        json.decodeFromString(Finding.Host.serializer(), payloadJson)
    } catch (_: Exception) { null }

    private fun decodeOpenPort(payloadJson: String): Finding.OpenPort? = try {
        json.decodeFromString(Finding.OpenPort.serializer(), payloadJson)
    } catch (_: Exception) { null }

    private fun decodeWifiAnomaly(payloadJson: String): Finding.WifiAnomaly? = try {
        json.decodeFromString(Finding.WifiAnomaly.serializer(), payloadJson)
    } catch (_: Exception) { null }

    // Minimal string-encoding helper inline: quotes/backslashes/newlines.
    private infix fun Json.enc(s: String): String =
        "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r") + "\""
}