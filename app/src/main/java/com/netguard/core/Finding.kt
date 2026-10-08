package com.netguard.core

import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.serialization.Serializable

/**
 * The event model: every module emits Finding subtypes into the FindingBus;
 * the app-level collector stamps them into Room. Payloads are stored as JSON
 * (so the DB schema doesn't churn as Finding subtypes evolve), which is why
 * every subtype is @Serializable.
 */
@Serializable
sealed class Finding {
    abstract val sessionId: String
    abstract val flagged: Boolean

    /** Which module discovered it (recon / vpn / ble / wifi / osint / web). */
    abstract val source: String

    @Serializable
    data class Host(
        override val sessionId: String,
        val ip: String,
        val hostname: String? = null,
        val vendor: String? = null,
        val mac: String? = null,
        val category: String? = null,
        /** Heuristic OS guess, e.g. "likely Windows (RDP open, SMB)" — never gospel. */
        val osGuess: String? = null,
        override val flagged: Boolean = false,
        override val source: String = "recon"
    ) : Finding()

    @Serializable
    data class OpenPort(
        override val sessionId: String,
        val ip: String,
        val port: Int,
        val service: String? = null,
        val product: String? = null,
        override val flagged: Boolean = false,
        override val source: String = "recon"
    ) : Finding()

    @Serializable
    data class TrafficEvent(
        override val sessionId: String,
        val sni: String? = null,
        val dstIp: String,
        val dstPort: Int,
        val protocol: String? = null,
        val appPackage: String? = null,
        val flagReason: String? = null,
        override val flagged: Boolean = false,
        override val source: String = "vpn"
    ) : Finding()

    @Serializable
    data class AttackerLookup(
        override val sessionId: String,
        val ip: String,
        val org: String? = null,
        val country: String? = null,
        val asn: Int? = null,
        val note: String? = null,
        override val flagged: Boolean = false,
        override val source: String = "osint"
    ) : Finding()

    @Serializable
    data class BleDevice(
        override val sessionId: String,
        val address: String,
        val name: String? = null,
        val trackerType: String? = null,
        val rssi: Int = 0,
        val timesSeenAtDistinctLocations: Int = 0,
        val category: String? = null,
        override val flagged: Boolean = false,
        override val source: String = "ble"
    ) : Finding()

    @Serializable
    data class WifiAnomaly(
        override val sessionId: String,
        val ssid: String? = null,
        val bssid: String? = null,
        val detail: String,
        /** EVIL_TWIN / DOWNGRADE / CONGESTION / OPEN_NET — drives UI grouping. */
        val kind: String? = null,
        override val flagged: Boolean = false,
        override val source: String = "wifi"
    ) : Finding()

    /** Every visible AP from a full WiFi sweep — the raw airspace listing. */
    @Serializable
    data class WifiAp(
        override val sessionId: String,
        val ssid: String? = null,
        val bssid: String,
        val channel: Int,
        val security: String,
        val rssi: Int,
        val category: String? = null,
        override val flagged: Boolean = false,
        override val source: String = "wifi"
    ) : Finding()

    /**
     * Web/bug-bounty recon result. severity: none/low/medium/high/critical;
     * owasp maps to the OWASP Top 10 category when known.
     * kind: SUBDOMAIN / DNS_RECORD / HEADER / DIR / REFLECT / WARN
     */
    @Serializable
    data class Web(
        override val sessionId: String,
        val kind: String,
        val target: String,
        val detail: String,
        val severity: String? = null,
        val owasp: String? = null,
        override val flagged: Boolean = false,
        override val source: String = "web"
    ) : Finding()

    /**
     * OSINT hit.
     * kind: USERNAME / BREACH / WAYBACK / GITHUB / DOMAIN_RDAP / NOTE
     */
    @Serializable
    data class OsintHit(
        override val sessionId: String,
        val kind: String,
        val identifier: String,
        val detail: String,
        override val flagged: Boolean = false,
        override val source: String = "osint"
    ) : Finding()

    /** This network's edge/public IP (fetched + RDAP-enriched during sweeps). */
    @Serializable
    data class PublicIp(
        override val sessionId: String,
        val ip: String,
        val org: String? = null,
        val country: String? = null,
        val asn: Int? = null,
        override val flagged: Boolean = false,
        override val source: String = "recon"
    ) : Finding()

    /** GATT profile of one BLE device (services + characteristics). */
    @Serializable
    data class GattDevice(
        override val sessionId: String,
        val address: String,
        val name: String? = null,
        val services: List<GattService> = emptyList(),
        val writableUnencrypted: Int = 0,
        override val flagged: Boolean = false,
        override val source: String = "ble"
    ) : Finding()
}

@Serializable
data class GattService(
    val uuid: String,
    val characteristics: List<GattChar> = emptyList()
)

@Serializable
data class GattChar(
    val uuid: String,
    val properties: String,
    val writable: Boolean = false,
    val writesUnencrypted: Boolean = false
)

/** Stable type discriminators persisted in the findings table. */
fun findingTypeOf(finding: Finding): String = when (finding) {
    is Finding.Host -> "HOST"
    is Finding.OpenPort -> "OPEN_PORT"
    is Finding.TrafficEvent -> "TRAFFIC"
    is Finding.AttackerLookup -> "ATTACKER_LOOKUP"
    is Finding.BleDevice -> "BLE"
    is Finding.WifiAnomaly -> "WIFI_ANOMALY"
    is Finding.WifiAp -> "WIFI_AP"
    is Finding.Web -> "WEB"
    is Finding.OsintHit -> "OSINT"
    is Finding.GattDevice -> "GATT"
    is Finding.PublicIp -> "PUBLIC_IP"
}

/**
 * Process-wide event bus. Modules emit here; exactly one collector (NetGuardApp)
 * persists to Room. DROP_OLDEST so a chatty module can never OOM the process.
 */
object FindingBus {
    private val _events = MutableSharedFlow<Finding>(
        extraBufferCapacity = 512,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val events: SharedFlow<Finding> = _events

    /** Never blocks the emitting module — buffer full or no collector yet → dropped. */
    fun emit(finding: Finding) {
        _events.tryEmit(finding)
    }
}