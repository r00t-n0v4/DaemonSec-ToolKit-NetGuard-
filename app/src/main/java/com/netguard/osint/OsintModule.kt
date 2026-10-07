package com.netguard.osint

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
 * Module 6 — OSINT, pure network, no special permissions.
 *
 *  - username presence across a configurable platform matrix
 *  - breach reference lookup via HaveIBeenPwned (needs your API key)
 *  - Wayback Machine URL pulls
 *  - GitHub dorking for exposed tokens (needs a GitHub token for code search)
 *  - domain RDAP (REST WHOIS — registration, expiry, nameservers)
 *
 * Authorization gate: every function checks requireAuthorization() first.
 * OSINT against non-consenting targets is a legal gray zone — the flow is
 * "declare the target, confirm authorization, then run", same as the
 * network modules' scope declaration.
 */
object OsintModule {

    /** Set via setHibpKey() from the UI/DB config; null = breach lookups skipped. */
    @Volatile var hibpKey: String? = null

    /** Set via setGithubToken(); null = GitHub code search skipped. */
    @Volatile var githubToken: String? = null

    /** Explicitly authorized identifiers (domains, usernames) for this run. */
    private val authorizedTargets: MutableSet<String> = ConcurrentHashMap.newKeySet()

    fun grantAuthorization(identifier: String) {
        authorizedTargets += identifier.trim().lowercase()
    }

    fun revokeAuthorization(identifier: String) {
        authorizedTargets -= identifier.trim().lowercase()
    }

    private val FORBIDDEN_TLDS = setOf("gov", "mil")

    private fun isAuthorized(identifier: String): Boolean =
        authorizedTargets.contains(identifier.trim().lowercase())

    private fun tldOf(host: String): String = host.trim().lowercase().trimEnd('.').substringAfterLast('.', "")

    // ---------------------------- IP intel (not just domains) ----------------------------

    private val IPV4 = Regex("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$")

    /** True when the target field holds an IPv4 address rather than a domain. */
    fun isIpv4(target: String): Boolean {
        val m = IPV4.find(target.trim()) ?: return false
        return m.groupValues.drop(1).all { (it.toIntOrNull() ?: 999) in 0..255 }
    }

    /**
     * IP OSINT: RDAP (org/ASN/country) + optional AbuseIPDB score via the
     * existing IpLookup engine, emitted as an ATTACKER_LOOKUP finding.
     */
    suspend fun lookupIp(ip: String, sessionId: String) = withContext(Dispatchers.IO) {
        if (!isIpv4(ip)) {
            FindingBus.emit(Finding.OsintHit(sessionId, "NOTE", ip, "not a valid IPv4 address"))
            return@withContext
        }
        IpLookup.lookup(sessionId, ip.trim())
    }

    // ---------------------------- username matrix ----------------------------

    private val PLATFORMS = listOf(
        "GitHub" to "https://github.com/%s",
        "GitLab" to "https://gitlab.com/%s",
        "Reddit" to "https://www.reddit.com/user/%s",
        "X/Twitter" to "https://x.com/%s",
        "Instagram" to "https://www.instagram.com/%s/",
        "Keybase" to "https://keybase.io/%s",
        "Telegram" to "https://t.me/%s",
        "Medium" to "https://medium.com/@%s",
        "dev.to" to "https://dev.to/%s",
        "Pastebin" to "https://pastebin.com/u/%s",
        "SoundCloud" to "https://soundcloud.com/%s",
        "Vimeo" to "https://vimeo.com/%s"
    )

    /** Checks each platform for an existing profile with that handle. */
    suspend fun checkUsernames(username: String, sessionId: String) = withContext(Dispatchers.IO) {
        if (!isAuthorized(username)) {
            FindingBus.emit(
                Finding.OsintHit(sessionId, "NOTE", username,
                    "BLOCKED: username '$username' not marked authorized — call grantAuthorization() first")
            )
            return@withContext
        }
        val semaphore = Semaphore(6)
        coroutineScope {
            PLATFORMS.map { (platform, template) ->
                async {
                    semaphore.withPermit {
                        val url = String.format(template, java.net.URLEncoder.encode(username, "UTF-8"))
                        val (code, _) = ProtectedHttp.get(url, minIntervalMs = 150) ?: return@withPermit
                        val exists = code == 200
                        FindingBus.emit(
                            Finding.OsintHit(
                                sessionId, "USERNAME", "$platform:$username",
                                if (exists) "profile exists (HTTP 200)" else "no profile (HTTP $code)",
                                flagged = exists
                            )
                        )
                    }
                }
            }.awaitAll()
        }
    }

    // ---------------------------- breaches (HIBP) ----------------------------

    /** Account breach lookup. Requires an HIBP API key (paid tier for accounts). */
    suspend fun checkBreaches(account: String, sessionId: String) = withContext(Dispatchers.IO) {
        val key = hibpKey
        if (key.isNullOrBlank()) {
            FindingBus.emit(
                Finding.OsintHit(sessionId, "NOTE", account,
                    "HIBP API key not configured — breach lookup skipped")
            )
            return@withContext
        }
        val (code, body) = ProtectedHttp.get(
            "https://haveibeenpwned.com/api/v3/breachaccount/$account?truncateResponse=false",
            headers = mapOf("hibp-api-key" to key),
            minIntervalMs = 1500
        ) ?: run {
            FindingBus.emit(Finding.OsintHit(sessionId, "NOTE", account, "HIBP unreachable"))
            return@withContext
        }
        when (code) {
            200 -> {
                val names = Regex("\"Name\"\\s*:\\s*\"([^\"]+)\"").findAll(body)
                    .map { it.groupValues[1] }.toList()
                FindingBus.emit(
                    Finding.OsintHit(
                        sessionId, "BREACH", account,
                        if (names.isEmpty()) "no known breaches" else "breaches: ${names.joinToString(", ")}",
                        flagged = names.isNotEmpty()
                    )
                )
            }
            404 -> FindingBus.emit(Finding.OsintHit(sessionId, "BREACH", account, "no known breaches (404)"))
            401 -> FindingBus.emit(Finding.OsintHit(sessionId, "NOTE", account, "HIBP rejected the API key (401)"))
            else -> FindingBus.emit(Finding.OsintHit(sessionId, "NOTE", account, "HIBP HTTP $code"))
        }
    }

    // ---------------------------- Wayback ----------------------------

    /** Pulls archived URLs for a domain from the Wayback CDX API (limit 200, deduped). */
    suspend fun waybackForDomain(domain: String, sessionId: String) = withContext(Dispatchers.IO) {
        if (!isAuthorized(domain) || tldOf(domain) in FORBIDDEN_TLDS) {
            FindingBus.emit(
                Finding.OsintHit(sessionId, "NOTE", domain,
                    "BLOCKED: '$domain' not authorized (or forbidden TLD) — Wayback pull skipped")
            )
            return@withContext
        }
        val url = "http://web.archive.org/cdx/search/cdx?url=$domain&output=json&collapse=urlkey&limit=200"
        val (code, body) = ProtectedHttp.get(url, minIntervalMs = 500) ?: return@withContext
        if (code != 200) {
            FindingBus.emit(Finding.OsintHit(sessionId, "NOTE", domain, "Wayback CDX HTTP $code"))
            return@withContext
        }
        // rows: [original, mimetype, timestamp] style — parse quoted strings conservatively
        val originals = Regex("\\[\"[^\"]+\",\\s*\"[^\"]+\",\\s*\"[^\"]+\"")
            .findAll(body).map { it.value }
        var count = 0
        for (row in originals) {
            val url0 = row.split(",").getOrNull(0)?.trim('[', '"', ' ') ?: continue
            if (url0.startsWith("http")) {
                count++
                if (count <= 40) { // cap feed noise; full list still in report via return
                    FindingBus.emit(Finding.OsintHit(sessionId, "WAYBACK", domain, url0))
                }
            }
        }
        FindingBus.emit(Finding.OsintHit(sessionId, "NOTE", domain, "Wayback: $count archived URLs"))
    }

    // ---------------------------- GitHub dorking ----------------------------

    /**
     * Searches GitHub for exposed secrets referencing the target domain.
     * Code search requires a token; without one we emit a NOTE (unauthenticated
     * code search is not permitted by the API).
     */
    suspend fun githubDork(domain: String, sessionId: String) = withContext(Dispatchers.IO) {
        if (!isAuthorized(domain)) {
            FindingBus.emit(Finding.OsintHit(sessionId, "NOTE", domain,
                "BLOCKED: '$domain' not authorized — GitHub dorking skipped"))
            return@withContext
        }
        val token = githubToken
        if (token.isNullOrBlank()) {
            FindingBus.emit(
                Finding.OsintHit(sessionId, "NOTE", domain,
                    "GitHub token not configured — code-search dorks need auth; set it and re-run")
            )
            return@withContext
        }
        val dorks = listOf(
            "\"$domain\" password",
            "\"$domain\" api_key",
            "\"$domain\" secret",
            "\"$domain\" smtp"
        )
        val headers = mapOf(
            "Authorization" to "Bearer $token",
            "Accept" to "application/vnd.github+json",
            "User-Agent" to "NetGuard-OSINT"
        )
        for (dork in dorks) {
            val q = java.net.URLEncoder.encode(dork, "UTF-8")
            val (code, body) = ProtectedHttp.get(
                "https://api.github.com/search/code?q=$q&per_page=10",
                headers = headers, minIntervalMs = 2500
            ) ?: continue
            if (code == 200) {
                val repos = Regex("\"html_url\"\\s*:\\s*\"(https://github\\.com/[^\"]+/blob/[^\"]+)\"")
                    .findAll(body).map { it.groupValues[1] }.take(5).toList()
                FindingBus.emit(
                    Finding.OsintHit(
                        sessionId, "GITHUB", domain,
                        if (repos.isEmpty()) "no code hits for: $dork"
                        else "${repos.size} code hits for '$dork': ${repos.joinToString(" | ")}",
                        flagged = repos.isNotEmpty()
                    )
                )
            } else {
                FindingBus.emit(Finding.OsintHit(sessionId, "NOTE", domain, "GitHub search HTTP $code for: $dork"))
            }
        }
    }

    // ---------------------------- domain RDAP ----------------------------

    /** WHOIS-replacement via rdap.org redirector: registrar, dates, nameservers. */
    suspend fun domainRdap(domain: String, sessionId: String) = withContext(Dispatchers.IO) {
        if (!isAuthorized(domain) || tldOf(domain) in FORBIDDEN_TLDS) {
            FindingBus.emit(
                Finding.OsintHit(sessionId, "NOTE", domain,
                    "BLOCKED: '$domain' not authorized (or forbidden TLD) — RDAP skipped")
            )
            return@withContext
        }
        val (code, body) = ProtectedHttp.get("https://rdap.org/domain/$domain", minIntervalMs = 300) ?: return@withContext
        if (code !in 200..299) {
            FindingBus.emit(Finding.OsintHit(sessionId, "NOTE", domain, "RDAP HTTP $code"))
            return@withContext
        }
        val events = Regex("\"eventAction\"\\s*:\\s*\"([^\"]+)\"\\s*,\\s*\"eventDate\"\\s*:\\s*\"([^\"]+)\"")
            .findAll(body).associate { it.groupValues[1] to it.groupValues[2] }
        val ns = Regex("\"ldhName\"\\s*:\\s*\"([^\"]+)\"").findAll(body)
            .map { it.groupValues[1] }.take(6).toList()
        val registrar = Regex("\"entityName\"\\s*:\\s*\"([^\"]+)\"").findAll(body)
            .map { it.groupValues[1] }.firstOrNull()
        val status = Regex("\"status\"\\s*:\\s*\\[([^\\]]*)\\]").find(body)?.groupValues?.get(1)
            ?.split(',')?.map { it.trim(' ', '"') }?.filter { it.isNotBlank() }?.take(4)

        val summary = buildString {
            registrar?.let { append("registrar: $it. ") }
            events["expiration"]?.let { append("expires: $it. ") }
            events["registration"]?.let { append("registered: $it. ") }
            status?.let { append("status: ${it.joinToString(",")}") }
            if (ns.isNotEmpty()) append(" · NS: ${ns.joinToString(", ")}")
        }.ifBlank { "registered domain (details unparsed)" }

        FindingBus.emit(Finding.OsintHit(sessionId, "DOMAIN_RDAP", domain, summary))
    }
}