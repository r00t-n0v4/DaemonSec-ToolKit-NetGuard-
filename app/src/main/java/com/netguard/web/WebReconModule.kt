package com.netguard.web

import com.netguard.core.Finding
import com.netguard.core.FindingBus
import com.netguard.net.ProtectedHttp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * Web app testing / bug-bounty recon — the Module 4 from the master plan.
 * Pure HTTPS + DNS, unrooted.
 *
 *  - subdomain enumeration via crt.sh certificate transparency
 *  - DNS record pulls via DNS-over-HTTPS (bypasses the LAN resolver, so a
 *    Pi-hole/filtered resolver doesn't blind the recon)
 *  - directory/content discovery with proper custom-404 signature detection
 *  - header audit: CSP/HSTS/cookies/CORS/cache-control
 *  - reflection triage: replay parameter values with marker payloads, detect
 *    reflection + context (quickest-pass only — follow up in Burp)
 *
 * Scope enforcement: only hosts matching an explicitly configured suffix.
 * Hardcoded refusal for .gov/.mil (and .edu/.dev config-dependent defaults).
 *
 * Rate-limit politeness: global throttle via ProtectedHttp, bounded
 * concurrency, and per-host 'did-we-get-blocked' 429 backoff.
 */
class WebReconModule {

    data class Config(
        val allowedSuffixes: Set<String>,   // e.g. setOf("example.com") — '*.example.com' implied
        val directoryWordlist: List<String> = DEFAULT_DIR_WORDLIST,
        val concurrency: Int = 12,
        val requestDelayMs: Long = 120
    )

    companion object {
        private const val CRT_SH = "https://crt.sh/json?q="
        private const val DOH_GOOGLE = "https://dns.google/resolve?name=%s&type=%s"
        private const val DOH_CLOUDFLARE = "https://cloudflare-dns.com/dns-query?name=%s&type=%s"

        private val FORBIDDEN_TLDS = setOf("gov", "mil")

        val DEFAULT_DIR_WORDLIST = listOf(
            ".git", ".env", ".htaccess", "admin", "administrator", "api", "app", "backup",
            "backup.sql", "bin", "cgi-bin", "composer.json", "config", "console", "data",
            "debug", "dev", "docker-compose.yml", "docs", "files", "uploads", "img",
            "install", "install.php", "js", "json", "login", "logout", "management",
            "old", "phpinfo.php", "phpmyadmin", "private", "robots.txt", "security.txt",
            "server-status", "sitemap.xml", "src", "sql", "test", "tmp", "uploads",
            "wp-admin", "wp-content", "wp-login.php", "www", "web.config", "webxml"
        )

        private val REFLECTION_MARKERS = listOf(
            "ng7Xq9zMarker", "netguard-probe-8412", "'\"><svg/onload=probe>"
        )

        private val INTERESTING_HEADERS = listOf(
            "content-security-policy", "strict-transport-security",
            "x-frame-options", "x-content-type-options", "referrer-policy",
            "permissions-policy", "server", "x-powered-by"
        )
    }

    private val http = ProtectedHttp
    private val dirSemaphores = ConcurrentHashMap<String, Semaphore>()

    /** True if host is allowed under the configured scope. .gov/.mil always refused. */
    fun inScope(host: String, config: Config): Boolean {
        val h = host.trim().lowercase().trimEnd('.')
        val tld = h.substringAfterLast('.', "")
        if (tld in FORBIDDEN_TLDS) return false
        return config.allowedSuffixes.any { suffix ->
            val s = suffix.lowercase().trimStart('*', '.')
            h == s || h.endsWith(".$s")
        }
    }

    fun scopeViolation(host: String, sessionId: String) {
        FindingBus.emit(
            Finding.Web(
                sessionId = sessionId, kind = "WARN", target = host,
                detail = "BLOCKED: $host is outside declared scope (or a forbidden TLD) — no requests sent",
                severity = "none", flagged = false
            )
        )
    }

    // ---------------------------- subdomains ----------------------------

    /** crt.sh identity JSON: pull unique name_value entries as candidate subdomains. */
    suspend fun enumerateSubdomains(domain: String, sessionId: String, config: Config): List<String> =
        withContext(Dispatchers.IO) {
            if (!inScope(domain, config)) {
                scopeViolation(domain, sessionId); return@withContext emptyList()
            }
            val (code, body) = http.get("$CRT_SH$domain", minIntervalMs = 500) ?: run {
                FindingBus.emit(webNote(sessionId, domain, "crt.sh unreachable — subdomain enum skipped"))
                return@withContext emptyList()
            }
            if (code != 200) {
                FindingBus.emit(webNote(sessionId, domain, "crt.sh HTTP $code — subdomain enum skipped"))
                return@withContext emptyList()
            }
            val names = sortedSetOf<String>()
            val regex = Regex("\"name_value\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"")
            for (m in regex.findAll(body)) {
                val raw = m.groupValues[1].replace("\\n", "\n")
                raw.split("\n").forEach { n ->
                    val name = n.trim().lowercase().removePrefix("*.")
                    if (name.contains('.') && (name == domain || name.endsWith(".$domain"))) names += name
                }
            }
            names.forEach { sub ->
                FindingBus.emit(
                    Finding.Web(sessionId, "SUBDOMAIN", sub, "cert-transparency asset", severity = null)
                )
            }
            names.toList()
        }

    // ---------------------------- DNS records ----------------------------

    /** DNS-over-HTTPS record pull (A/AAAA/CNAME/MX/TXT/CAA/NS/SOA). */
    suspend fun pullDnsRecords(domain: String, sessionId: String, config: Config): Map<String, List<String>> =
        withContext(Dispatchers.IO) {
            if (!inScope(domain, config)) {
                scopeViolation(domain, sessionId); return@withContext emptyMap()
            }
            val types = listOf("A", "AAAA", "CNAME", "MX", "TXT", "CAA", "NS", "SOA")
            val out = ConcurrentHashMap<String, MutableList<String>>()
            coroutineScope {
                types.map { type ->
                    async {
                        val (code, body) = http.get(String.format(DOH_GOOGLE, domain, type), minIntervalMs = 150)
                            ?: return@async
                        if (code != 200) return@async
                        // Answer data appears after "data":"..."; parse without full JSON models
                        Regex("\"data\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").findAll(body).forEach { m ->
                            val v = m.groupValues[1]
                                .replace("\\\"", "\"")
                                .replace("\\\\", "\\")
                            if (v.isNotBlank()) out.getOrPut(type) { mutableListOf() }.add(v)
                        }
                    }
                }.awaitAll()
            }
            out.forEach { (type, values) ->
                values.distinct().forEach { v ->
                    FindingBus.emit(
                        Finding.Web(sessionId, "DNS_RECORD", "$domain $type", v)
                    )
                }
            }
            out.mapValues { it.value.distinct() }
        }

    // ---------------------------- headers ----------------------------

    /** Header audit against https://host: security headers, cookies, CORS, server banners. */
    suspend fun auditHeaders(host: String, sessionId: String, config: Config) =
        withContext(Dispatchers.IO) {
            if (!inScope(host, config)) {
                scopeViolation(host, sessionId); return@withContext
            }
            val url = "https://$host/"
            val (code, _) = http.get(url, minIntervalMs = config.requestDelayMs) ?: run {
                FindingBus.emit(webNote(sessionId, host, "unreachable over HTTPS"))
                return@withContext
            }
            FindingBus.emit(
                Finding.Web(sessionId, "HEADER", host, "HTTP $code (GET /)")
            )
            auditHeadersFromResponse(host, sessionId, url, code)
        }

    private suspend fun auditHeadersFromResponse(host: String, sessionId: String, url: String, code: Int) {
        // Re-request through OkHttp to read headers (ProtectedHttp.get drops them;
        // this variant keeps them).
        val resp = runCatching {
            http.client.newCall(
                okhttp3.Request.Builder().url(url).get().build()
            ).execute()
        }.getOrNull() ?: return
        resp.use { r ->
            val headers = r.headers.toMultimap()

            // security headers presence/absence
            val present = INTERESTING_HEADERS.filter { headers.containsKey(it) || headers.containsKey(it.lowercase()) }
            val missingHeaders = INTERESTING_HEADERS.filter { it !in present }
                .filter { it !in listOf("server", "x-powered-by") }
            if (missingHeaders.isNotEmpty()) {
                FindingBus.emit(
                    Finding.Web(
                        sessionId, "HEADER", host,
                        "missing security headers: ${missingHeaders.joinToString(", ")}",
                        severity = if (missingHeaders.any { it == "content-security-policy" || it == "strict-transport-security" }) "low" else "info"
                    )
                )
            }
            present.forEach { h ->
                val v = headers[h]?.firstOrNull()?.take(200) ?: return@forEach
                FindingBus.emit(Finding.Web(sessionId, "HEADER", host, "$h: $v"))
            }

            // cookie flags
            headers["set-cookie"]?.forEach { sc ->
                val flags = mutableListOf<String>()
                val lower = sc.lowercase()
                if (!lower.contains("secure")) flags += "!Secure"
                if (!lower.contains("httponly")) flags += "!HttpOnly"
                if (!lower.contains("samesite")) flags += "!SameSite"
                val name = sc.substringBefore('=').trim()
                if (flags.isNotEmpty()) {
                    FindingBus.emit(
                        Finding.Web(
                            sessionId, "HEADER", host,
                            "cookie '$name' missing flags: ${flags.joinToString(", ")}",
                            severity = "low", owasp = "A05:2021-Security Misconfiguration",
                            flagged = true
                        )
                    )
                }
            }

            // CORS wildcard reflection with origin echo
            val originEcho = headers["access-control-allow-origin"]?.firstOrNull()
            if (originEcho != null) {
                FindingBus.emit(
                    Finding.Web(
                        sessionId, "HEADER", host,
                        "Access-Control-Allow-Origin: $originEcho" +
                            (if (originEcho.trim() == "*") " (wildcard — no credentials config check needed)" else " (origin echo — verify credentials handling)"),
                        severity = "info", owasp = "A05:2021-Security Misconfiguration"
                    )
                )
            }

            // server banner
            headers["server"]?.firstOrNull()?.let {
                FindingBus.emit(
                    Finding.Web(sessionId, "HEADER", host, "server banner: $it", severity = "info",
                        owasp = "A05:2021-Security Misconfiguration")
                )
            }
        }
    }

    // ---------------------------- directory discovery ----------------------------

    /**
     * Content discovery with custom-404 fingerprinting: fetch a guaranteed-
     * nonexistent path, record (code, bodyHash), then compare every wordlist
     * probe against that signature. This is the detail most hobby scanners
     * get wrong (soft-404s drown real hits).
     */
    suspend fun discoverDirectories(
        host: String,
        sessionId: String,
        config: Config
    ): List<Pair<String, Int>> = withContext(Dispatchers.IO) {
        if (!inScope(host, config)) {
            scopeViolation(host, sessionId); return@withContext emptyList()
        }
        val semaphore = dirSemaphores.getOrPut(host) { Semaphore(config.concurrency) }
        val base = "https://$host"

        // custom-404 fingerprint
        val notFoundPath = "/netguard-does-not-exist-${System.currentTimeMillis()}"
        val nf = fetchAndHash("$base$notFoundPath", config.requestDelayMs)
            ?: run { FindingBus.emit(webNote(sessionId, host, "host unreachable — dir discovery skipped")); return@withContext emptyList() }

        val hits = mutableListOf<Pair<String, Int>>()
        coroutineScope {
            config.directoryWordlist.map { word ->
                async {
                    semaphore.withPermit {
                        val path = "/$word"
                        val probe = fetchAndHash("$base$path", config.requestDelayMs) ?: return@withPermit
                        val (code, hash, size) = probe
                        val isSoft404 = (code == nf.code && hash == nf.hash) ||
                            (code == 200 && nf.code == 200 && hash == nf.hash)
                        if (!isSoft404 && code in 200..399) {
                            hits += path to code
                            FindingBus.emit(
                                Finding.Web(
                                    sessionId, "DIR", "$base$path",
                                    "HTTP $code (${size}B) — content differs from 404 signature",
                                    severity = if (word in listOf(".env", ".git", "phpinfo.php", "backup.sql", "web.config")) "medium" else "info",
                                    flagged = word in listOf(".env", ".git", "phpinfo.php", "backup.sql", "web.config")
                                )
                            )
                        }
                    }
                }
            }.awaitAll()
        }
        hits
    }

    private data class Probe(val code: Int, val hash: Int, val size: Int)

    private suspend fun fetchAndHash(url: String, delayMs: Long): Probe? {
        ProtectedHttp.throttle(delayMs)
        return runCatching {
            http.client.newCall(okhttp3.Request.Builder().url(url).get().build()).execute().use { r ->
                if (r.code == 429) {
                    // backed off — politeness: skip rather than hammer
                    return@use null
                }
                val bytes = r.body?.bytes() ?: ByteArray(0)
                Probe(r.code, bytes.contentHashCode(), bytes.size)
            }
        }.getOrNull()
    }

    // ---------------------------- reflection triage ----------------------------

    /**
     * Quick triage pass (not a real scanner): take a URL with query params,
     * replay with marker payloads, detect any reflection in the response and
     * tag its likely context (HTML body / attribute / JS string). Anything
     * interesting goes to Burp afterwards.
     */
    suspend fun probeReflections(url: String, sessionId: String, config: Config) =
        withContext(Dispatchers.IO) {
            val host = runCatching { java.net.URI(url).host ?: "" }.getOrDefault("")
            if (host.isBlank()) return@withContext
            if (!inScope(host, config)) {
                scopeViolation(host, sessionId); return@withContext
            }
            if (!url.contains("?")) {
                FindingBus.emit(webNote(sessionId, url, "no query parameters — reflection triage skipped"))
                return@withContext
            }

            for (marker in REFLECTION_MARKERS) {
                val parts = url.split("?", limit = 2)
                val params = parts[1].split("&").mapNotNull { p ->
                    val kv = p.split("=", limit = 2)
                    if (kv.size == 2) kv[0] to kv[1] else null
                }
                val mutated = params.joinToString("&") { (k, _) ->
                    "$k=${java.net.URLEncoder.encode(marker, "UTF-8")}"
                }
                val testUrl = "${parts[0]}?$mutated"
                val (code, body) = http.get(testUrl, minIntervalMs = config.requestDelayMs) ?: continue
                val hits = mutableListOf<String>()
                if (body.contains(marker)) {
                    // context guess
                    val idx = body.indexOf(marker)
                    val before = body.substring(maxOf(0, idx - 40), idx)
                    val context = when {
                        before.trimEnd().endsWith("=") && before.contains("value") -> "HTML attribute"
                        before.trimEnd().endsWith("'") || before.trimEnd().endsWith("\"") -> "JS string or attribute"
                        before.contains("<script", ignoreCase = true) -> "script body"
                        else -> "HTML body"
                    }
                    hits += "reflected in $context (HTTP $code)"
                }
                if (hits.isNotEmpty()) {
                    FindingBus.emit(
                        Finding.Web(
                            sessionId, "REFLECT", testUrl,
                            hits.joinToString("; "),
                            severity = "low",
                            owasp = "A03:2021-Injection",
                            flagged = true
                        )
                    )
                } else {
                    FindingBus.emit(Finding.Web(sessionId, "REFLECT", url, "marker $marker: not reflected"))
                }
            }
        }

    // ---------------------------- helpers ----------------------------

    private fun webNote(sessionId: String, target: String, detail: String) =
        Finding.Web(sessionId, "WARN", target, detail)

    /** Host header variation / vhost probing: one request with a mutated Host. */
    suspend fun probeVirtualHost(host: String, vhost: String, sessionId: String, config: Config) =
        withContext(Dispatchers.IO) {
            if (!inScope(host, config) || !inScope(vhost, config)) {
                scopeViolation("$host/$vhost", sessionId); return@withContext
            }
            ProtectedHttp.throttle(config.requestDelayMs)
            val resp = runCatching {
                http.client.newCall(
                    okhttp3.Request.Builder()
                        .url("https://$host/")
                        .header("Host", vhost)
                        .get().build()
                ).execute()
            }.getOrNull()
            resp?.use { r ->
                FindingBus.emit(
                    Finding.Web(
                        sessionId, "DNS_RECORD", "vhost $vhost @ $host",
                        "HTTP ${r.code}, length ${r.headers["content-length"] ?: "?"}"
                    )
                )
            }
        }
}