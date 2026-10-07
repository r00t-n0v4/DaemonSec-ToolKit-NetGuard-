package com.netguard.osint

import com.netguard.core.Finding
import com.netguard.core.FindingBus
import com.netguard.core.SocketProtector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL

/**
 * Attacker-IP OSINT: RDAP/WHOIS org/country/ASN for IPs seen in traffic,
 * plus an optional AbuseIPDB abuse-confidence score (free key, set via
 * [setAbuseIpDbKey]). RDAP needs no API key.
 */
object IpLookup {

    private val json = Json { ignoreUnknownKeys = true }

    @Volatile private var abuseIpDbKey: String? = null

    fun setAbuseIpDbKey(key: String) {
        abuseIpDbKey = key
    }

    @Serializable
    data class RdapResult(val org: String?, val country: String?, val asn: Int?, val note: String?)

    /** Looks up a public IP; private/reserved ranges short-circuit with a note. */
    suspend fun lookup(sessionId: String, ip: String) = withContext(Dispatchers.IO) {
        val addr = runCatching { InetAddress.getByName(ip) }.getOrNull() ?: return@withContext
        if (isPrivate(ip)) {
            FindingBus.emit(
                Finding.AttackerLookup(
                    sessionId = sessionId, ip = ip,
                    note = "private/RFC1918 address — not an internet attacker",
                    flagged = false
                )
            )
            return@withContext
        }
        val rdap = rdapLookup(ip)
        val abuse = abuseIpDbKey?.let { abuseIpDbScore(ip, it) }
        FindingBus.emit(
            Finding.AttackerLookup(
                sessionId = sessionId, ip = ip,
                org = rdap?.org,
                country = rdap?.country,
                asn = rdap?.asn,
                note = abuse?.let { "abuse score $it/100" },
                flagged = (abuse ?: 0) >= 75
            )
        )
    }

    private fun isPrivate(ip: String): Boolean {
        val parts = ip.split('.').map { it.toIntOrNull() ?: return true }
        if (parts.size != 4) return true
        val (a, b) = parts
        return a == 10 ||
            (a == 172 && b in 16..31) ||
            (a == 192 && b == 168) ||
            a == 127 ||
            a == 169 && b == 254 ||
            (a == 100 && b in 64..127) // CGNAT
    }

    /** IANA bootstrap: asking ARIN's RDAP redirector works for any global IP. */
    private fun rdapLookup(ip: String): RdapResult? = try {
        val conn = protectedConnection("https://rdap.arin.net/registry/ip/$ip")
        if (conn.responseCode !in 200..299) {
            conn.disconnect(); null
        } else {
            val body = conn.inputStream.use { it.readBytes().decodeToString() }
            conn.disconnect()
            val obj = json.parseToJsonElement(body).let { e ->
                json.decodeFromJsonElement(RdapResponseShim.serializer(), e)
            }
            val asnMatch = Regex("(?i)AS(\\d+)").find(obj.handle ?: "")?.groupValues?.get(1)?.toIntOrNull()
                ?: Regex("(?i)\\bAS(\\d+)\\b").find(body)?.groupValues?.get(1)?.toIntOrNull()
            RdapResult(
                org = obj.name ?: obj.entities.firstOrNull()?.handle,
                country = obj.country,
                asn = asnMatch,
                note = null
            )
        }
    } catch (_: Exception) {
        null
    }

    private fun abuseIpDbScore(ip: String, key: String): Int? = try {
        val conn = protectedConnection("https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90")
        conn.setRequestProperty("Key", key)
        conn.setRequestProperty("Accept", "application/json")
        if (conn.responseCode !in 200..299) {
            conn.disconnect(); null
        } else {
            val body = conn.inputStream.use { it.readBytes().decodeToString() }
            conn.disconnect()
            Regex("\"abuseConfidenceScore\"\\s*:\\s*(\\d+)").find(body)?.groupValues?.get(1)?.toIntOrNull()
        }
    } catch (_: Exception) {
        null
    }

    /**
     * Plain HttpURLConnection. NOTE: during an active VPN session TCP is not
     * forwarded, so these lookups may fail until Firestack lands — emit
     * failures as nil results rather than crashing.
     */
    private fun protectedConnection(url: String): HttpURLConnection {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = 8000
        conn.readTimeout = 8000
        conn.setRequestProperty("Accept", "application/rdap+json, application/json")
        conn.setRequestProperty("User-Agent", "NetGuard/0.1")
        return conn
    }

    @Serializable
    private data class RdapResponseShim(
        val handle: String? = null,
        val name: String? = null,
        val country: String? = null,
        val entities: List<EntityShim> = emptyList()
    ) {
        @Serializable
        data class EntityShim(val handle: String? = null)
    }
}