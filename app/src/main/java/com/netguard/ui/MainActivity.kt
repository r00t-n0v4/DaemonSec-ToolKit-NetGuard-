@file:OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)

package com.netguard.ui

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import androidx.activity.compose.BackHandler
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.netguard.core.DeviceClassifier
import com.netguard.NetGuardApp
import com.netguard.ble.BleDiscovery
import com.netguard.ble.FoxHunt
import com.netguard.ble.TrackerScanner
import com.netguard.db.FindingEntity
import com.netguard.db.NetGuardDatabase
import com.netguard.db.SessionEntity
import com.netguard.osint.OsintModule
import com.netguard.recon.HostDiscovery
import com.netguard.recon.PassiveDiscovery
import com.netguard.report.ReportExporter
import com.netguard.ui.theme.AlertRed
import com.netguard.ui.theme.NetBlack
import com.netguard.ui.theme.NetGuardTheme
import com.netguard.ui.theme.SignalYellow
import com.netguard.ui.theme.TerminalGreen
import com.netguard.vpn.NetGuardVpnService
import com.netguard.vpn.VpnState
import com.netguard.vpn.VpnState as VpnStateFlow
import com.netguard.web.WebReconModule
import com.netguard.wifi.WifiAuditor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.time.Instant
import java.util.UUID
import android.os.ParcelFileDescriptor
import android.graphics.pdf.PdfRenderer
import androidx.compose.ui.platform.LocalDensity

enum class ExportFormat(val extension: String, val mimeType: String) {
    MARKDOWN("md", "text/markdown"),
    JSON("json", "application/json"),
    PDF("pdf", "application/pdf")
}

/** What the in-app report viewer renders (text for md/json, pages for pdf). */
data class ReportViewerPayload(
    val title: String,
    val file: File,
    val isPdf: Boolean,
    val text: String?
)

/**
 * Four tabs: Monitor (session + all scan controls), Findings (filterable live
 * feed), Reports (session history + md/json/pdf export), GATT (BLE profiles).
 * Each module still just writes into Room via FindingBus — tabbing is purely
 * a presentation split, no new data plumbing.
 */
class MainActivity : ComponentActivity() {

    private lateinit var trackerScanner: TrackerScanner
    private lateinit var hostDiscovery: HostDiscovery
    private lateinit var passiveDiscovery: PassiveDiscovery
    private lateinit var wifiAuditor: WifiAuditor
    private lateinit var bleDiscovery: BleDiscovery
    private lateinit var foxHunt: FoxHunt
    private lateinit var webRecon: WebReconModule
    private lateinit var reportExporter: ReportExporter
    private var activeSessionId: String? = null

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result -> if (result.resultCode == RESULT_OK) startVpnService() }

    private val runtimePermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { /* each module fails soft without permission; nothing to react to here */ }

    private var sessionActiveOverride = false

    /** VPN running state exposed to Compose (service updates it; UI observes). */
    private val vpnStateFlow = VpnState.active

    /**
     * Single source of truth for the pinned status strip. StateFlow instead of
     * a Compose remember{} var: long coroutines (~2min sweeps) writing the
     * captured Compose-state setter proved unreliable (write lost after tab
     * lifetime exceeded one composition), while a StateFlow shared from the
     * activity survives relaunches and tab switches by construction.
     */
    val statusStrip = kotlinx.coroutines.flow.MutableStateFlow<String?>(null)

    /**
     * On relaunch while the tunnel survived (START_STICKY): re-attach truthfully.
     * If the tunnel is running but we don't hold a session id, adopt an
     * "orphaned" marker so the banner shows the real state and Disconnect
     * works — instead of pretending nothing is running.
     */
    private fun reconcileVpnState() {
        if (VpnState.active.value && activeSessionId == null) {
            activeSessionId = "orphaned-" + UUID.randomUUID()
            sessionActiveOverride = true
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        trackerScanner = TrackerScanner(this)
        hostDiscovery = HostDiscovery()
        passiveDiscovery = PassiveDiscovery(applicationContext)
        wifiAuditor = WifiAuditor(this)
        bleDiscovery = BleDiscovery(this)
        foxHunt = FoxHunt(this)
        webRecon = WebReconModule()
        val app = application as NetGuardApp
        reportExporter = ReportExporter(app.database.sessionDao(), app.database.findingDao())

        // OSINT keys persist across launches; loaded into the module on start.
        val prefs = getSharedPreferences("netguard-config", Context.MODE_PRIVATE)
        OsintModule.hibpKey = prefs.getString("hibp_key", null)
        OsintModule.githubToken = prefs.getString("github_token", null)
        reconcileVpnState()

        requestRuntimePermissions()

        setContent {
            NetGuardTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    NetGuardScreen(
                        database = app.database,
                        onStartSession = { scope, sessionId -> startSession(scope, sessionId) },
                        onStopSession = ::disconnectVpn,
                        statusStrip = statusStrip,
                        onScanHostsArp = ::runArpScan,
                        onScanHostsActive = ::runActiveSweep,
                        onScanWifi = ::runFullWifiSweep,
                        onBleScan = ::runBleScan,
                        onHuntStart = ::startTargetedHunt,
                        onHuntStop = ::stopTargetedHunt,
                        huntUi = huntUi,
                        vpnActive = vpnStateFlow,
                        onVpnDisconnect = ::disconnectVpn,
                        onVpnEnable = { startVpnService() },
                        onWebRecon = ::runWebRecon,
                        onOsint = ::runOsint,
                        onOsintUsernames = ::runOsintUsernames,
                        onOsintBreaches = ::runOsintBreaches,
                        onOsintIpOrDomain = ::runOsintIpOrDomain,
                        onOsintWayback = ::runOsintWayback,
                        onOsintGithubDorks = ::runOsintGithubDorks,
                        onWebSubdomains = ::runWebSubdomains,
                        onWebDns = ::runWebDns,
                        onWebHeaders = ::runWebHeaders,
                        onWebDirs = ::runWebDirs,
                        onWebReflections = ::runWebReflections,
                        onGattProbe = ::runGattProbe,
                        onExportAndShare = ::exportAndShare,
                        onDeleteSession = ::deleteSession,
                        onOpenReport = ::openReport,
                        onSaveAllToDownloads = ::saveAllReports,
                        onSaveKeys = { hibp, gh ->
                            prefs.edit().putString("hibp_key", hibp.ifBlank { null })
                                .putString("github_token", gh.ifBlank { null }).apply()
                            OsintModule.hibpKey = hibp.ifBlank { null }
                            OsintModule.githubToken = gh.ifBlank { null }
                        },
                        savedHibpKey = prefs.getString("hibp_key", "") ?: "",
                        savedGithubToken = prefs.getString("github_token", "") ?: ""
                    )
                }
            }
        }
    }

    private fun requestRuntimePermissions() {
        val perms = mutableListOf(
            android.Manifest.permission.ACCESS_FINE_LOCATION,
            android.Manifest.permission.CHANGE_WIFI_STATE
        )
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
            perms += android.Manifest.permission.BLUETOOTH_SCAN
            perms += android.Manifest.permission.BLUETOOTH_CONNECT
        }
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            perms += android.Manifest.permission.POST_NOTIFICATIONS
        }
        runtimePermissionLauncher.launch(perms.toTypedArray())
    }

    // --- Module actions ---

    private fun runArpScan(onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first")
        val app = application as NetGuardApp
        app.appScope.launchSafely {
            val hosts = hostDiscovery.scanArpTable(sessionId)
            onStatus("ARP scan: ${hosts.size} hosts found")
        }
    }

    private fun runActiveSweep(onStatus: (String) -> Unit) {
        // Auto-open a session if none is live — the sweep button must never
        // dead-end with "start a session first" after an app relaunch.
        val sessionId = activeSessionId ?: UUID.randomUUID().toString().also {
            activeSessionId = it
            val app = application as NetGuardApp
            app.appScope.launchSafely {
                app.database.sessionDao().insert(
                    SessionEntity(
                        id = it,
                        startedAt = System.currentTimeMillis(),
                        scopeDeclaration = "Auto-opened by Network scan",
                        label = "Session ${Instant.now()}"
                    )
                )
            }
        }
        val app = application as NetGuardApp
        onStatus("Mapping your network — devices, ports, banners, OS guesses (may take ~60s)...")
        app.appScope.launchSafely {
            android.util.Log.d("NetGuardUI", "sweep coroutine start")
            val ctx = runCatching { hostDiscovery.sweepCurrentNetwork(sessionId, applicationContext) }
                .onFailure { android.util.Log.e("NetGuardUI", "sweep THREW", it) }
                .getOrElse { null }
            android.util.Log.d("NetGuardUI", "sweep returned ctx=${ctx != null} iso=${ctx?.probeFailuresWereTotal}")
            passiveDiscovery.listenMdns(sessionId, windowMs = 6000)
            passiveDiscovery.listenSsdp(sessionId, windowMs = 6000)
            android.util.Log.d("NetGuardUI", "listeners done")
            if (ctx == null) {
                statusStrip.value = "Sweep finished with errors — check Findings (HOST/OPEN_PORT)"
                return@launchSafely
            }
            val pub = ctx.publicIpFinding
            android.util.Log.d("NetGuardUI", "setting final status")
            statusStrip.value =
                "Network map done: ${ctx.ssid ?: "WiFi"} — you are ${ctx.thisPhoneIp ?: "?"}, " +
                "gateway ${ctx.gatewayIp ?: "?"}, " +
                "public IP ${pub?.ip ?: "unavailable"}" +
                (if (pub == null && hostDiscovery.publicIpTcpBlocked)
                    " — router blocking new WAN TCP from this device (ICMP still passes)"
                else "") +
                (pub?.org?.let { " ($it)" } ?: "") +
                " — details in Findings"
        }
    }

    /**
     * Full WiFi sweep: every visible AP recorded (airspace listing) PLUS the
     * anomaly analyzers. Works with the VPN stopped too — WiFi scans don't
     * need the tunnel.
     */
    private fun runFullWifiSweep(onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first (WiFi scan files findings under the session)")
        val app = application as NetGuardApp
        onStatus("WiFi scan running (4 passes, ~10s)...")
        app.appScope.launchSafely {
            val result = wifiAuditor.sweep(sessionId)
            val flagged = result.anomalies.count { it.flagged }
            onStatus("WiFi scan: ${result.aps.size} APs listed, ${result.anomalies.size} anomalies ($flagged flagged)")
        }
    }

    /**
     * Web recon against one declared target: subdomains (crt.sh), DNS records
     * (DoH), header audit, directory discovery. testUrl (optional) also runs
     * reflection triage on its query parameters.
     */
    private fun runWebRecon(domain: String, testUrl: String?, onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first")
        if (domain.isBlank()) return onStatus("Enter a target domain")
        val app = application as NetGuardApp
        val config = WebReconModule.Config(allowedSuffixes = setOf(domain))
        onStatus("Web recon on $domain — subdomains → DNS → headers → dirs...")
        app.appScope.launchSafely {
            var subs = 0; var dirs = 0
            runCatching {
                subs = webRecon.enumerateSubdomains(domain, sessionId, config).size
                webRecon.pullDnsRecords(domain, sessionId, config)
                webRecon.auditHeaders(domain, sessionId, config)
                dirs = webRecon.discoverDirectories(domain, sessionId, config).size
                testUrl?.takeIf { it.isNotBlank() }?.let { webRecon.probeReflections(it.trim(), sessionId, config) }
            }
            onStatus("Web recon $domain done: $subs subdomains, $dirs dirs; results in Findings (WEB)")
        }
    }

    /**
     * OSINT run: username matrix (usernames are authorized by entering them),
     * domain RDAP + Wayback, optional breach check (needs HIBP key in
     * settings), optional GitHub dorking (needs token in settings).
     */
    private fun runOsint(username: String, breachAccount: String, domain: String, onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first")
        val app = application as NetGuardApp
        if (username.isBlank() && domain.isBlank() && breachAccount.isBlank()) {
            return onStatus("Enter a username and/or domain")
        }
        onStatus("OSINT running...")
        app.appScope.launchSafely {
            runCatching {
                username.trim().takeIf { it.isNotBlank() }?.let { u ->
                    OsintModule.grantAuthorization(u)
                    OsintModule.checkUsernames(u, sessionId)
                }
                breachAccount.trim().takeIf { it.isNotBlank() }?.let { a ->
                    OsintModule.grantAuthorization(a)
                    OsintModule.checkBreaches(a, sessionId)
                }
                domain.trim().lowercase().takeIf { it.isNotBlank() }?.let { d ->
                    if (OsintModule.isIpv4(d)) {
                        // IP input: RDAP/AbuseIPDB intel instead of domain lookups
                        OsintModule.lookupIp(d, sessionId)
                    } else {
                        OsintModule.grantAuthorization(d)
                        OsintModule.domainRdap(d, sessionId)
                        OsintModule.waybackForDomain(d, sessionId)
                        OsintModule.githubDork(d, sessionId)
                    }
                }
            }
            onStatus("OSINT done — results in Findings (OSINT / ATTACKER_LOOKUP)")
        }
    }

    /** Individual OSINT tool runners for the dropdown sheet (one tap = one tool). */

    private fun runOsintUsernames(username: String, onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first")
        val app = application as NetGuardApp
        if (username.isBlank()) return onStatus("Enter a username")
        onStatus("Username matrix running for ${username.trim()}...")
        app.appScope.launchSafely {
            runCatching {
                OsintModule.grantAuthorization(username.trim())
                OsintModule.checkUsernames(username.trim(), sessionId)
            }
            onStatus("Username matrix done — results in Findings (OSINT)")
        }
    }

    private fun runOsintBreaches(account: String, onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first")
        val app = application as NetGuardApp
        if (account.isBlank()) return onStatus("Enter an email/account")
        if (OsintModule.hibpKey == null)
            return onStatus("No HIBP API key — add it in Settings (gear icon)")
        onStatus("Breach lookup running for ${account.trim()}...")
        app.appScope.launchSafely {
            runCatching {
                OsintModule.grantAuthorization(account.trim())
                OsintModule.checkBreaches(account.trim(), sessionId)
            }
            onStatus("Breach lookup done — results in Findings (OSINT)")
        }
    }

    private fun runOsintIpOrDomain(target: String, onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first")
        val app = application as NetGuardApp
        val t = target.trim()
        if (t.isBlank()) return onStatus("Enter an IP or domain")
        onStatus("RDAP/intel lookup running for $t...")
        app.appScope.launchSafely {
            runCatching {
                if (OsintModule.isIpv4(t)) {
                    OsintModule.lookupIp(t, sessionId)
                } else {
                    OsintModule.grantAuthorization(t.lowercase())
                    OsintModule.domainRdap(t.lowercase(), sessionId)
                }
            }
            onStatus("RDAP lookup done — results in Findings (OSINT / ATTACKER_LOOKUP)")
        }
    }

    private fun runOsintWayback(domain: String, onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first")
        val app = application as NetGuardApp
        val d = domain.trim().lowercase()
        if (d.isBlank()) return onStatus("Enter a domain")
        onStatus("Wayback history pulling for $d...")
        app.appScope.launchSafely {
            runCatching {
                OsintModule.grantAuthorization(d)
                OsintModule.waybackForDomain(d, sessionId)
            }
            onStatus("Wayback pull done — results in Findings (OSINT)")
        }
    }

    private fun runOsintGithubDorks(domain: String, onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first")
        val app = application as NetGuardApp
        val d = domain.trim().lowercase()
        if (d.isBlank()) return onStatus("Enter a domain")
        if (OsintModule.githubToken == null)
            return onStatus("No GitHub token — add it in Settings (gear icon)")
        onStatus("GitHub dorking running for $d...")
        app.appScope.launchSafely {
            runCatching {
                OsintModule.grantAuthorization(d)
                OsintModule.githubDork(d, sessionId)
            }
            onStatus("GitHub dorks done — results in Findings (OSINT)")
        }
    }

    /** Individual web-recon tool runners for the dropdown sheet. */

    private fun runWebSubdomains(domain: String, onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first")
        val d = domain.trim().lowercase()
        if (d.isBlank()) return onStatus("Enter a target domain")
        val app = application as NetGuardApp
        val config = WebReconModule.Config(allowedSuffixes = setOf(d))
        onStatus("crt.sh subdomain enum running for $d...")
        app.appScope.launchSafely {
            val subs = runCatching { webRecon.enumerateSubdomains(d, sessionId, config) }
                .getOrElse { emptyList<String>() }
            onStatus("Subdomains: ${subs.size} found — results in Findings (WEB)")
        }
    }

    private fun runWebDns(domain: String, onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first")
        val d = domain.trim().lowercase()
        if (d.isBlank()) return onStatus("Enter a target domain")
        val app = application as NetGuardApp
        val config = WebReconModule.Config(allowedSuffixes = setOf(d))
        onStatus("DNS record pull running for $d (DoH)...")
        app.appScope.launchSafely {
            val recs = runCatching { webRecon.pullDnsRecords(d, sessionId, config) }
                .getOrElse { emptyMap<String, List<String>>() }
            onStatus("DNS done: ${recs.size} record types — results in Findings (WEB)")
        }
    }

    private fun runWebHeaders(domain: String, onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first")
        val d = domain.trim().lowercase()
        if (d.isBlank()) return onStatus("Enter a target domain")
        val app = application as NetGuardApp
        val config = WebReconModule.Config(allowedSuffixes = setOf(d))
        onStatus("Header audit running for $d...")
        app.appScope.launchSafely {
            runCatching { webRecon.auditHeaders(d, sessionId, config) }
            onStatus("Header audit done — results in Findings (WEB)")
        }
    }

    private fun runWebDirs(domain: String, onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first")
        val d = domain.trim().lowercase()
        if (d.isBlank()) return onStatus("Enter a target domain")
        val app = application as NetGuardApp
        val config = WebReconModule.Config(allowedSuffixes = setOf(d))
        onStatus("Directory discovery running for $d (~${WebReconModule.DEFAULT_DIR_WORDLIST.size} paths)...")
        app.appScope.launchSafely {
            val dirs = runCatching { webRecon.discoverDirectories(d, sessionId, config) }
                .getOrElse { emptyList<String>() }
            onStatus("Dir busting done: ${dirs.size} live paths — results in Findings (WEB)")
        }
    }

    private fun runWebReflections(domain: String, testUrl: String, onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first")
        val d = domain.trim().lowercase()
        val u = testUrl.trim()
        if (d.isBlank() || u.isBlank()) return onStatus("Enter a target domain and the URL with params")
        val app = application as NetGuardApp
        val config = WebReconModule.Config(allowedSuffixes = setOf(d))
        val urlHost = try { java.net.URI(u).host ?: d } catch (_: Exception) { d }
        if (!webRecon.inScope(urlHost, config)) {
            return onStatus("BLOCKED: URL outside declared scope (or forbidden TLD)")
        }
        onStatus("Reflection triage running on $u...")
        app.appScope.launchSafely {
            runCatching { webRecon.probeReflections(u, sessionId, config) }
            onStatus("Reflection triage done — results in Findings (WEB)")
        }
    }

    /** Connects to one BLE device and dumps its GATT profile as a finding. */
    private fun runGattProbe(address: String, onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first")
        val app = application as NetGuardApp
        if (!address.matches(Regex("([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"))) {
            return onStatus("Enter a MAC address like AA:BB:CC:DD:EE:FF")
        }
        onStatus("GATT probe on $address (up to 15s)...")
        app.appScope.launchSafely {
            val result = com.netguard.ble.GattProbe.probe(applicationContext, sessionId, address.trim())
            if (result == null) {
                onStatus("GATT probe failed — device out of range / not connectable?")
            } else {
                onStatus("GATT probe: ${result.services.size} services, ${result.writableUnencrypted} writable-unencrypted")
            }
        }
    }

    /**
     * Nearby-BLE discovery scan: enumerates every device the radio can hear
     * (~15s), classifies each into a category (headphones, Meta glasses,
     * Flipper, TVs, trackers...), emits live into the feed. Run with the VPN
     * active or stopped — BLE doesn't touch the tunnel.
     */
    private fun runBleScan(onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first")
        val app = application as NetGuardApp
        onStatus("BLE scan running (~15s) — watch the feed fill in live...")
        app.appScope.launchSafely {
            val devices = bleDiscovery.scan(sessionId)
            val grouped = devices.groupBy { it.category }
            val top = grouped.entries.maxByOrNull { it.value.size }
            onStatus(
                "BLE scan: ${devices.size} devices. " +
                    (top?.let { "Biggest group: ${it.key} (${it.value.size})." } ?: "No devices heard.")
            )
        }
    }

    /**
     * BLE Fox Hunt: proximity hunting for tracker-class devices. Runs a
     * low-latency scan, ranks trackers by RSSI per tick, and posts live
     * warmer/colder status lines. Every tick is logged to the feed.
     */
    /** Live Fox Hunt tab state. */
    private val huntUi = kotlinx.coroutines.flow.MutableStateFlow<FoxHuntUi?>(null)

    /**
     * Continuous targeted hunt for the Fox Hunt tab: low-latency BLE scan
     * filtered to the given MAC; every packet updates huntUi live (the tab
     * re-renders warmer/colder instantly), and every packet logs to the feed.
     */
    private fun startTargetedHunt(mac: String, onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first")
        val norm = mac.trim().uppercase().replace('-', ':')
        if (!Regex("([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}").matches(norm)) {
            return onStatus("Enter a MAC like AA:BB:CC:DD:EE:FF")
        }
        val target = norm
        huntUi.value = FoxHuntUi(target, running = true)
        onStatus("🦊 Hunting $target — walk slowly; watch the signal.")
        foxHunt.startTargetedHunt(target) { rssi, estimate, best, count ->
            // callback arrives on Dispatchers.Main; publish straight to the flow
            huntUi.value = FoxHuntUi(
                target = target, running = true, rssi = rssi, estimate = estimate,
                bestRssi = best, observations = count, lastUpdateMs = System.currentTimeMillis()
            )
        }
    }

    private fun stopTargetedHunt() {
        foxHunt.stopHunt()
        huntUi.value?.let { huntUi.value = it.copy(running = false) }
    }

    /** Writes the report, then hands it to the system share sheet via a FileProvider content:// URI. */
    private fun exportAndShare(sessionId: String, format: ExportFormat, onStatus: (String) -> Unit) {
        val app = application as NetGuardApp
        app.appScope.launchSafely {
            val file = File(getExternalFilesDir(null), "netguard-report-$sessionId.${format.extension}")
            when (format) {
                ExportFormat.MARKDOWN -> reportExporter.exportMarkdown(sessionId, file)
                ExportFormat.JSON -> reportExporter.exportJson(sessionId, file)
                ExportFormat.PDF -> reportExporter.exportPdf(sessionId, file)
            }

            if (!file.exists()) {
                onStatus("Export failed — no data for that session?")
                return@launchSafely
            }

            val uri = FileProvider.getUriForFile(this@MainActivity, "$packageName.fileprovider", file)
            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = format.mimeType
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                startActivity(Intent.createChooser(shareIntent, "Share NetGuard report"))
            }
            onStatus("Report ready: ${file.name}")
        }
    }

    /**
     * Deletes a session end-to-end: findings row set, the session row itself,
     * and any exported report files — frees the phone space the session took.
     */
    private fun deleteSession(sessionId: String, onStatus: (String) -> Unit) {
        val app = application as NetGuardApp
        app.appScope.launchSafely {
            val findingsDeleted = app.database.findingDao().deleteForSession(sessionId)
            app.database.sessionDao().deleteById(sessionId)
            // best-effort cleanup of exported report files for that session
            listOf("md", "json", "pdf").forEach { ext ->
                try { File(getExternalFilesDir(null), "netguard-report-$sessionId.$ext").delete() } catch (_: Exception) {}
            }
            if (activeSessionId == sessionId) activeSessionId = null
            onStatus("Report deleted — $findingsDeleted findings + files removed")
        }
    }

    /** Generates the report file if it doesn't exist yet, then returns it. */
    private suspend fun ensureReportFile(sessionId: String, format: ExportFormat): File? {
        val file = File(getExternalFilesDir(null), "netguard-report-$sessionId.${format.extension}")
        if (!file.exists()) {
            val ok = when (format) {
                ExportFormat.MARKDOWN -> reportExporter.exportMarkdown(sessionId, file)
                ExportFormat.JSON -> reportExporter.exportJson(sessionId, file)
                ExportFormat.PDF -> reportExporter.exportPdf(sessionId, file)
            }
            if (ok == null) return null
        }
        return file
    }

    /** Opens a report in the in-app viewer (md/json as text, pdf rendered). */
    private fun openReport(sessionId: String, format: ExportFormat, onReady: (ReportViewerPayload?) -> Unit) {
        val app = application as NetGuardApp
        app.appScope.launchSafely {
            val file = ensureReportFile(sessionId, format)
            if (file == null || !file.exists()) {
                kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) { onReady(null) }
                return@launchSafely
            }
            val payload = if (format == ExportFormat.PDF) {
                ReportViewerPayload(title = file.name, file = file, isPdf = true, text = null)
            } else {
                val text = runCatching { file.readText() }.getOrNull()
                ReportViewerPayload(title = file.name, file = file, isPdf = false, text = text)
            }
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) { onReady(payload) }
        }
    }

    /**
     * Saves all three report formats into MediaStore Downloads under
     * Download/NetGuard/ — visible in any file manager, no share sheet needed.
     */
    private fun saveAllReports(sessionId: String, onStatus: (String) -> Unit) {
        val app = application as NetGuardApp
        app.appScope.launchSafely {
            val saved = mutableListOf<String>()
            val failed = mutableListOf<String>()
            for (format in ExportFormat.entries) {
                try {
                    val f = ensureReportFile(sessionId, format)
                    if (f == null || !f.exists()) { failed += format.extension; continue }
                    copyToDownloads(f, format.mimeType)
                    saved += format.extension
                } catch (_: Exception) {
                    failed += format.extension
                }
            }
            onStatus(
                when {
                    failed.isEmpty() -> "Saved ${saved.size} files to Download/NetGuard/"
                    saved.isEmpty() -> "Save failed — nothing written"
                    else -> "Saved ${saved.size} to Download/NetGuard/; failed: ${failed.joinToString(", ")}"
                }
            )
        }
    }

    /** MediaStore insert into Download/NetGuard/ (Q+; no storage permission needed). */
    private fun copyToDownloads(file: File, mime: String) {
        val resolver = applicationContext.contentResolver
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, file.name)
            put(MediaStore.MediaColumns.MIME_TYPE, mime)
            put(MediaStore.MediaColumns.RELATIVE_PATH, "${Environment.DIRECTORY_DOWNLOADS}/NetGuard")
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
        val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            ?: throw IllegalStateException("MediaStore rejected the insert")
        try {
            resolver.openOutputStream(uri)?.use { out ->
                file.inputStream().use { it.copyTo(out, 64 * 1024) }
            } ?: throw IllegalStateException("couldn't open output stream")
            values.clear()
            values.put(MediaStore.MediaColumns.IS_PENDING, 0)
            resolver.update(uri, values, null, null)
        } catch (e: Exception) {
            try { resolver.delete(uri, null, null) } catch (_: Exception) {}
            throw e
        }
    }

    @Suppress("DEPRECATION")
    private fun subnetBase(): String? {
        val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return null
        val ipInt = wifiManager.connectionInfo?.ipAddress ?: return null
        if (ipInt == 0) return null
        val ip = String.format(
            "%d.%d.%d.%d",
            ipInt and 0xFF, (ipInt shr 8) and 0xFF, (ipInt shr 16) and 0xFF, (ipInt shr 24) and 0xFF
        )
        return ip.substringBeforeLast(".")
    }

    private fun startSession(scopeDeclaration: String, sessionId: String) {
        activeSessionId = sessionId
        val app = application as NetGuardApp

        app.appScope.launchSafely {
            app.database.sessionDao().insert(
                SessionEntity(
                    id = sessionId,
                    startedAt = System.currentTimeMillis(),
                    scopeDeclaration = scopeDeclaration,
                    label = "Session ${Instant.now()}"
                )
            )
        }

        val consentIntent = VpnService.prepare(this)
        if (consentIntent != null) {
            vpnPermissionLauncher.launch(consentIntent)
        } else {
            startVpnService()
        }

        trackerScanner.startScanning(app.appScope, sessionId)
    }

    private fun startVpnService() {
        val sessionId = activeSessionId ?: return
        val intent = Intent(this, NetGuardVpnService::class.java)
            .putExtra(NetGuardVpnService.EXTRA_SESSION_ID, sessionId)
        // startForegroundService so the call is legal even when the app is in
        // the background (notification tap, etc.); the service already calls
        // startForeground promptly in onStartCommand.
        androidx.core.content.ContextCompat.startForegroundService(this, intent)
    }

    /**
     * In-app tunnel shutdown. Delivers the same ACTION_STOP the notification
     * Stop uses, but via plain startService(): the app is always foreground
     * when the user taps, so background-start limits don't apply, and plain
     * starts carry NO startForeground-within-5s obligation — critical,
     * because an ACTION_STOP start never calls startForeground (it's tearing
     * the service down) and using startForegroundService for it crashes with
     * ForegroundServiceDidNotStartInTimeException (caught live on-device).
     * The service handler closes the tun fd first, so teardown is <1s.
     */
    private fun disconnectVpn() {
        startService(
            Intent(this, NetGuardVpnService::class.java)
                .setAction(NetGuardVpnService.ACTION_STOP)
        )
        trackerScanner.stopScanning()
        val id = activeSessionId
        if (id != null && !id.startsWith("orphaned-")) {
            val app = application as NetGuardApp
            app.appScope.launchSafely {
                app.database.sessionDao().markEnded(id, System.currentTimeMillis())
            }
        }
        activeSessionId = null
    }
}

private fun kotlinx.coroutines.CoroutineScope.launchSafely(block: suspend () -> Unit) {
    launch {
        try {
            block()
        } catch (e: Exception) {
            // A dead coroutine that used to only fail silently is how scan
            // features "disappear" — surface it in logcat at least.
            android.util.Log.e("NetGuardUI", "launchSafely block crashed", e)
        }
    }
}

// ================= UI =================

/** Live UI state for the Fox Hunt tab (published from the hunt callback). */
public data class FoxHuntUi(
    val target: String,
    val running: Boolean,
    val rssi: Int = Int.MIN_VALUE,
    val estimate: String = "waiting for signal...",
    val bestRssi: Int = Int.MIN_VALUE,
    val observations: Int = 0,
    val lastUpdateMs: Long = 0
)

private enum class Tab(val label: String, val icon: androidx.compose.ui.graphics.vector.ImageVector) {
    MONITOR("Monitor", Icons.Default.PlayArrow),
    NEARBY("Nearby", Icons.Default.Wifi),
    FINDINGS("Findings", Icons.Default.List),
    HUNT("Fox Hunt", Icons.Default.Flag),
    REPORTS("Reports", Icons.Default.Share),
    GATT("GATT", Icons.Default.Bluetooth)
}

@Composable
fun NetGuardScreen(
    database: NetGuardDatabase,
    onStartSession: (String, String) -> Unit,
    onStopSession: () -> Unit,
    statusStrip: kotlinx.coroutines.flow.StateFlow<String?>,
    onScanHostsArp: ((String) -> Unit) -> Unit,
    onScanHostsActive: ((String) -> Unit) -> Unit,
    onScanWifi: ((String) -> Unit) -> Unit,
    onBleScan: ((String) -> Unit) -> Unit,
    onHuntStart: (String, (String) -> Unit) -> Unit,
    onHuntStop: () -> Unit,
    huntUi: kotlinx.coroutines.flow.StateFlow<FoxHuntUi?>,
    vpnActive: kotlinx.coroutines.flow.StateFlow<Boolean>,
    onVpnDisconnect: () -> Unit,
    onVpnEnable: () -> Unit,
    onWebRecon: (String, String?, (String) -> Unit) -> Unit,
    onOsint: (String, String, String, (String) -> Unit) -> Unit,
    onOsintUsernames: (String, (String) -> Unit) -> Unit,
    onOsintBreaches: (String, (String) -> Unit) -> Unit,
    onOsintIpOrDomain: (String, (String) -> Unit) -> Unit,
    onOsintWayback: (String, (String) -> Unit) -> Unit,
    onOsintGithubDorks: (String, (String) -> Unit) -> Unit,
    onWebSubdomains: (String, (String) -> Unit) -> Unit,
    onWebDns: (String, (String) -> Unit) -> Unit,
    onWebHeaders: (String, (String) -> Unit) -> Unit,
    onWebDirs: (String, (String) -> Unit) -> Unit,
    onWebReflections: (String, String, (String) -> Unit) -> Unit,
    onGattProbe: (String, (String) -> Unit) -> Unit,
    onExportAndShare: (String, ExportFormat, (String) -> Unit) -> Unit,
    onDeleteSession: (String, (String) -> Unit) -> Unit,
    onOpenReport: (String, ExportFormat, (ReportViewerPayload?) -> Unit) -> Unit,
    onSaveAllToDownloads: (String, (String) -> Unit) -> Unit,
    onSaveKeys: (String, String) -> Unit,
    savedHibpKey: String,
    savedGithubToken: String
) {
    var selectedTab by remember { mutableStateOf(Tab.MONITOR) }
    var sessionActive by remember { mutableStateOf(false) }
    var activeSessionId by remember { mutableStateOf<String?>(null) }
    var showSettings by remember { mutableStateOf(false) }
    var viewer by remember { mutableStateOf<ReportViewerPayload?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("NetGuard") },
                actions = {
                    IconButton(onClick = { showSettings = true }) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                }
            )
        },
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { tab ->
                    NavigationBarItem(
                        selected = selectedTab == tab,
                        onClick = { selectedTab = tab },
                        icon = { Icon(tab.icon, contentDescription = tab.label) },
                        label = { Text(tab.label) }
                    )
                }
            }
        }
    ) { padding ->
        Box(modifier = Modifier.padding(padding)) {
            // Glitch streaks only run behind the Monitor tab — ambient
            // texture is nice on the control screen, but a continuous
            // animation under dense scan-log text or report lists just
            // fights readability (and burns battery) for no real gain.
            if (selectedTab == Tab.MONITOR) {
                com.netguard.ui.theme.GlitchStreakBackground(modifier = Modifier.matchParentSize())
            }
            when (selectedTab) {
                Tab.MONITOR -> MonitorTab(
                    sessionActive = sessionActive,
                    onToggleSession = { scope ->
                        if (sessionActive) {
                            onStopSession()
                            activeSessionId = null
                        } else {
                            val newId = UUID.randomUUID().toString()
                            activeSessionId = newId
                            onStartSession(scope, newId)
                        }
                        sessionActive = !sessionActive
                    },
                    pinnedStatus = statusStrip,
                    onScanHostsArp = onScanHostsArp,
                    onScanHostsActive = onScanHostsActive,
                    onScanWifi = onScanWifi,
                    onBleScan = onBleScan,
                    vpnActive = vpnActive,
                    onVpnDisconnect = onVpnDisconnect,
                    onVpnEnable = onVpnEnable,
                    onWebRecon = onWebRecon,
                    onOsint = onOsint,
                    onOsintUsernames = onOsintUsernames,
                    onOsintBreaches = onOsintBreaches,
                    onOsintIpOrDomain = onOsintIpOrDomain,
                    onOsintWayback = onOsintWayback,
                    onOsintGithubDorks = onOsintGithubDorks,
                    onWebSubdomains = onWebSubdomains,
                    onWebDns = onWebDns,
                    onWebHeaders = onWebHeaders,
                    onWebDirs = onWebDirs,
                    onWebReflections = onWebReflections
                )
                Tab.FINDINGS -> FindingsTab(database = database, sessionId = activeSessionId)
                Tab.HUNT -> FoxHuntTab(
                    activeSessionId = activeSessionId,
                    onHuntStart = onHuntStart,
                    onHuntStop = onHuntStop,
                    huntState = huntUi,
                    prefillMac = null
                )
                Tab.NEARBY -> NearbyTab(
                    database = database,
                    activeSessionId = activeSessionId,
                    onBleScan = onBleScan,
                    onScanWifi = onScanWifi
                )
                Tab.REPORTS -> ReportsTab(
                    database = database,
                    activeSessionId = activeSessionId,
                    onExportAndShare = onExportAndShare,
                    onDeleteSession = onDeleteSession,
                    onOpenReport = onOpenReport,
                    onShowViewer = { payload -> viewer = payload },
                    onSaveAllToDownloads = onSaveAllToDownloads
                )
                Tab.GATT -> GattTab(
                    database = database,
                    activeSessionId = activeSessionId,
                    onGattProbe = onGattProbe
                )
            }
            if (showSettings) {
                SettingsDialog(
                    savedHibpKey = savedHibpKey,
                    savedGithubToken = savedGithubToken,
                    onDismiss = { showSettings = false },
                    onSave = { hibp, gh -> onSaveKeys(hibp, gh); showSettings = false }
                )
            }
            // Full-screen report viewer, drawn over everything incl. the nav bar
            viewer?.let { payload ->
                ReportViewerScreen(payload = payload, onClose = { viewer = null })
            }
        }
    }
}

@Composable
private fun MonitorTab(
    sessionActive: Boolean,
    onToggleSession: (String) -> Unit,
    pinnedStatus: kotlinx.coroutines.flow.StateFlow<String?>,
    onScanHostsArp: ((String) -> Unit) -> Unit,
    onScanHostsActive: ((String) -> Unit) -> Unit,
    onScanWifi: ((String) -> Unit) -> Unit,
    onBleScan: ((String) -> Unit) -> Unit,
    vpnActive: kotlinx.coroutines.flow.StateFlow<Boolean>,
    onVpnDisconnect: () -> Unit,
    onVpnEnable: () -> Unit,
    onWebRecon: (String, String?, (String) -> Unit) -> Unit,
    onOsint: (String, String, String, (String) -> Unit) -> Unit,
    onOsintUsernames: (String, (String) -> Unit) -> Unit,
    onOsintBreaches: (String, (String) -> Unit) -> Unit,
    onOsintIpOrDomain: (String, (String) -> Unit) -> Unit,
    onOsintWayback: (String, (String) -> Unit) -> Unit,
    onOsintGithubDorks: (String, (String) -> Unit) -> Unit,
    onWebSubdomains: (String, (String) -> Unit) -> Unit,
    onWebDns: (String, (String) -> Unit) -> Unit,
    onWebHeaders: (String, (String) -> Unit) -> Unit,
    onWebDirs: (String, (String) -> Unit) -> Unit,
    onWebReflections: (String, String, (String) -> Unit) -> Unit
) {
    var scopeText by remember { mutableStateOf("My home network / own devices only") }
    var statusMessage by remember { mutableStateOf<String?>(null) }
    var osintSheetOpen by remember { mutableStateOf(false) }
    var webSheetOpen by remember { mutableStateOf(false) }
    var osintUser by remember { mutableStateOf("") }
    var osintBreach by remember { mutableStateOf("") }
    var osintIpDomain by remember { mutableStateOf("") }
    var osintWaybackDomain by remember { mutableStateOf("") }
    var osintGithubDomain by remember { mutableStateOf("") }
    var webDomain by remember { mutableStateOf("") }
    var webTestUrl by remember { mutableStateOf("") }
    val isVpnActive by vpnActive.collectAsStateWithLifecycle()
    // activity-level strip wins if set (long-running sweeps publish here);
    // short scans keep using the local callback state.
    val stripFromFlow by pinnedStatus.collectAsStateWithLifecycle()
    val pinned = stripFromFlow ?: statusMessage

    Column(modifier = Modifier.fillMaxSize()) {
        // ---- VPN tunnel banner: shows REAL service state, offers direct
        // disconnect/enable without leaving the app ----
        when {
            isVpnActive -> Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surfaceVariant)
                    .padding(horizontal = 16.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .background(SignalYellow, shape = androidx.compose.foundation.shape.CircleShape)
                )
                Spacer(Modifier.width(8.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        "VPN MONITORING — ${if (sessionActive) "SESSION ACTIVE" else "TUNNEL ONLY"}",
                        style = MaterialTheme.typography.bodySmall,
                        color = SignalYellow,
                        letterSpacing = 1.sp
                    )
                    Text(
                        if (sessionActive) "Traffic observation + scans running"
                        else "Tunnel running from a previous session — restart a session to unlock scans",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                TextButton(onClick = onVpnDisconnect) {
                    Text("DISCONNECT", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelLarge)
                }
            }
            sessionActive -> Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surfaceVariant)
                    .padding(horizontal = 16.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .background(MaterialTheme.colorScheme.onSurfaceVariant, shape = androidx.compose.foundation.shape.CircleShape)
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    "SESSION ACTIVE — VPN PERMISSION NEEDED",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    letterSpacing = 1.sp
                )
                Spacer(Modifier.weight(1f))
                TextButton(onClick = onVpnEnable) {
                    Text("ENABLE VPN", color = SignalYellow, style = MaterialTheme.typography.labelLarge)
                }
            }
            else -> {}
        }

        // Pinned completion strip — sits directly under MONITORING ACTIVE so
        // a finished scan "pops up to the top" instead of scrolling away
        // with the rest of the controls.
        pinned?.let {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = if (it.startsWith("BLE scan:") || it.startsWith("🦊") || it.startsWith("WiFi scan:") ||
                        it.startsWith("Web recon") || it.startsWith("OSINT done") || it.contains("done")
                    ) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.surfaceVariant
                ),
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
                ) {
                    Icon(
                        Icons.Default.CheckCircle, contentDescription = null,
                        tint = TerminalGreen, modifier = Modifier.size(16.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                }
            }
        }

        Column(
            modifier = Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(16.dp)
        ) {
            OutlinedTextField(
                value = scopeText,
                onValueChange = { scopeText = it },
                label = { Text("Scope declaration (printed on every report)") },
                enabled = !sessionActive,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(12.dp))

            Button(
                onClick = {
                    onToggleSession(scopeText)
                    if (sessionActive) statusMessage = null
                },
                modifier = Modifier.fillMaxWidth(),
                colors = if (sessionActive) ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error) else ButtonDefaults.buttonColors()
            ) {
                Icon(if (sessionActive) Icons.Default.Stop else Icons.Default.PlayArrow, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text(if (sessionActive) "Stop monitoring" else "Start monitoring")
            }

            if (sessionActive) {
                Spacer(Modifier.height(20.dp))
                Text("Scans", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(8.dp))

                ScanRow(
                    label = "ARP scan",
                    description = "Instant — devices that recently talked to you",
                    onClick = { onScanHostsArp { statusMessage = it } }
                )
                ScanRow(
                    label = "Network scan",
                    description = "Slower — TCP-probes your whole /24 + mDNS/SSDP listen",
                    onClick = { onScanHostsActive { statusMessage = it } }
                )
                ScanRow(
                    label = "WiFi scan",
                    description = "ALL visible APs listed + congestion, evil-twin & downgrade detection",
                    onClick = { onScanWifi { statusMessage = it } }
                )
                ScanRow(
                    label = "BLE device scan",
                    description = "Nearby devices grouped: headphones, Meta glasses, TVs, Flipper, trackers",
                    onClick = { onBleScan { statusMessage = it } }
                )
                ToolSheet(
                    title = "OSINT",
                    summary = "Username/IP/domain matrix, RDAP, Wayback, breaches (HIBP key), GitHub dorks",
                    expanded = osintSheetOpen,
                    onToggle = { osintSheetOpen = !osintSheetOpen }
                ) {
                    ToolField(
                        label = "Username (platform matrix)",
                        value = osintUser,
                        onChange = { osintUser = it },
                        onRun = { onOsintUsernames(osintUser) { statusMessage = it } }
                    )
                    ToolField(
                        label = "Email/account (HIBP breaches — key in Settings)",
                        value = osintBreach,
                        onChange = { osintBreach = it },
                        onRun = { onOsintBreaches(osintBreach) { statusMessage = it } }
                    )
                    ToolField(
                        label = "IP or domain (RDAP intel)",
                        value = osintIpDomain,
                        onChange = { osintIpDomain = it },
                        onRun = { onOsintIpOrDomain(osintIpDomain) { statusMessage = it } }
                    )
                    ToolField(
                        label = "Domain (Wayback history)",
                        value = osintWaybackDomain,
                        onChange = { osintWaybackDomain = it },
                        onRun = { onOsintWayback(osintWaybackDomain) { statusMessage = it } }
                    )
                    ToolField(
                        label = "Domain (GitHub dorks — token in Settings)",
                        value = osintGithubDomain,
                        onChange = { osintGithubDomain = it },
                        onRun = { onOsintGithubDorks(osintGithubDomain) { statusMessage = it } }
                    )
                    Text(
                        "Entering a target and running = declaring authorization for it. IPs get RDAP + abuse intel; domains get RDAP/Wayback/GitHub. .gov/.mil refused.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                ToolSheet(
                    title = "Web recon (bug bounty)",
                    summary = "crt.sh subdomains, DoH records, header audit, dir busting, reflection triage — target-scoped",
                    expanded = webSheetOpen,
                    onToggle = { webSheetOpen = !webSheetOpen }
                ) {
                    ToolField(
                        label = "Target domain (e.g. target.com). Only *.domain is probed; .gov/.mil refused.",
                        value = webDomain,
                        onChange = { webDomain = it },
                        onRun = null
                    )
                    ToolField(
                        label = "Subdomains (crt.sh)",
                        value = null,
                        onChange = {},
                        onRun = { onWebSubdomains(webDomain) { statusMessage = it } }
                    )
                    ToolField(
                        label = "DNS records (DoH)",
                        value = null,
                        onChange = {},
                        onRun = { onWebDns(webDomain) { statusMessage = it } }
                    )
                    ToolField(
                        label = "Header audit",
                        value = null,
                        onChange = {},
                        onRun = { onWebHeaders(webDomain) { statusMessage = it } }
                    )
                    ToolField(
                        label = "Directory busting",
                        value = null,
                        onChange = {},
                        onRun = { onWebDirs(webDomain) { statusMessage = it } }
                    )
                    ToolField(
                        label = "URL for reflection triage (optional; uses domain above for scope)",
                        value = webTestUrl,
                        onChange = { webTestUrl = it },
                        onRun = { onWebReflections(webDomain, webTestUrl) { statusMessage = it } }
                    )
                }
            } else {
                Spacer(Modifier.height(24.dp))
                Text(
                    "Start monitoring to unlock scans and begin collecting findings.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }

}

/**
 * Expandable tool sheet for the multi-tool scan families (OSINT / web recon):
 * one collapsed row with title + summary; tapping expands EVERY tool inline —
 * one tap shows all the info and each sub-tool runs individually, no dialogs.
 */
@Composable
private fun ToolSheet(
    title: String,
    summary: String,
    expanded: Boolean,
    onToggle: () -> Unit,
    content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit
) {
    OutlinedCard(
        onClick = onToggle,
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
        ) {
            Icon(
                if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                contentDescription = if (expanded) "Collapse" else "Expand",
                tint = SignalYellow
            )
            Spacer(Modifier.width(8.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleSmall, color = TerminalGreen)
                Text(
                    summary,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        if (expanded) {
            Column(
                modifier = Modifier.padding(horizontal = 12.dp),
                content = content
            )
            Spacer(Modifier.height(8.dp))
        }
    }
}

/**
 * One tool row inside a ToolSheet: an inline input (when the tool takes a
 * target) with a RUN action on the trailing edge; value-less tools render as
 * a plain run button.
 */
@Composable
private fun ToolField(
    label: String,
    value: String?,
    onChange: (String) -> Unit,
    onRun: (() -> Unit)?
) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (value != null) {
                OutlinedTextField(
                    value = value,
                    onValueChange = onChange,
                    label = { Text(label, style = MaterialTheme.typography.bodySmall) },
                    singleLine = true,
                    modifier = Modifier.weight(1f)
                )
                Spacer(Modifier.width(8.dp))
            } else {
                Text(
                    label,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f)
                )
                Spacer(Modifier.width(8.dp))
            }
            if (onRun != null) {
                Button(
                    onClick = { onRun?.invoke() },
                    enabled = value == null || value.isNotBlank() || !label.startsWith("Subdomains (")
                ) {
                    Text("Run", style = MaterialTheme.typography.labelLarge)
                }
            }
        }
    }
}


/** Hardware/software identifier for tap-to-copy from device rows. */
private fun deviceAddressOf(type: String, payloadJson: String): String? {
    val field = when (type) {
        "BLE", "GATT" -> "address"
        "WIFI_AP" -> "bssid"
        "HOST" -> "ip"
        else -> return null
    }
    return Regex("\"$field\"\\s*:\\s*\"([^\"]+)\"").find(payloadJson)?.groupValues?.get(1)
}

@Composable
private fun SettingsDialog(
    savedHibpKey: String,
    savedGithubToken: String,
    onDismiss: () -> Unit,
    onSave: (String, String) -> Unit
) {
    var hibp by remember { mutableStateOf(savedHibpKey) }
    var gh by remember { mutableStateOf(savedGithubToken) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Settings") },
        text = {
            Column {
                OutlinedTextField(
                    value = hibp,
                    onValueChange = { hibp = it },
                    label = { Text("HaveIBeenPwned API key") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = gh,
                    onValueChange = { gh = it },
                    label = { Text("GitHub token (code-search dorks)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "Keys are stored in the app's private shared prefs and never appear in reports.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = { TextButton(onClick = { onSave(hibp, gh) }) { Text("Save") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

/**
 * Grouped live view of the radio environment. ONE unified device
 * classification across all sources (BLE, WiFi APs, mDNS/SSDP/LAN hosts):
 * every device lands in a category bucket (Flipper, Trackers, Glasses,
 * Audio, TV/Media, Wearables, HID, Vehicle, Dev Boards, Computers,
 * Hidden, Other).
 *
 * WiFi anomalies split into their own groups — Possible Evil Twins in RED
 * at the top (always visible, shows "none detected" when empty), then
 * other anomalies (congestion/open nets) in yellow.
 */
@Composable
private fun NearbyTab(
    database: NetGuardDatabase,
    activeSessionId: String?,
    onBleScan: ((String) -> Unit) -> Unit,
    onScanWifi: ((String) -> Unit) -> Unit
) {
    var status by remember { mutableStateOf<String?>(null) }

    val findings by database.findingDao()
        .observeForSession(activeSessionId ?: "")
        .collectAsStateWithLifecycle(initialValue = emptyList())

    val wifiAps = findings.filter { it.type == "WIFI_AP" }
    val wifiAnomalies = findings.filter { it.type == "WIFI_ANOMALY" }
    // EVIL_TWIN + DOWNGRADE both count as "possible evil twin" (a downgrade
    // decoy IS the possible twin case) — kind lives in the payload JSON.
    val wifiEvilTwin = wifiAnomalies.filter { f ->
        f.flagged && (f.payloadJson.contains("EVIL_TWIN") || f.payloadJson.contains("DOWNGRADE"))
    }
    val wifiOtherAnomalies = wifiAnomalies.filter { it !in wifiEvilTwin }
    val bleDevices = findings.filter { it.type == "BLE" }
    val lanHosts = findings.filter { it.type == "HOST" }

    // ---- unified category buckets: decode once, dedupe per device, group ----
    data class Dev(
        val f: FindingEntity,
        val name: String?,
        val detail: String,
        val flagged: Boolean,
        val copyable: String? // MAC/BSSID/BLE address/IP — tap row to copy
    )

    // Latest-finding-wins per physical device: APs by BSSID, BLE by MAC,
    // LAN hosts by IP — several sweeps in one session shouldn't stack rows.
    fun dedupeKey(type: String, payload: String): String {
        val field = when (type) {
            "WIFI_AP" -> "bssid"
            "BLE" -> "address"
            "HOST" -> "ip"
            else -> return payload
        }
        return type + ":" + (Regex("\"$field\"\\s*:\\s*\"([^\"]+)\"").find(payload)?.groupValues?.get(1)
            ?: payload.take(40))
    }

    val latestByKey = LinkedHashMap<String, FindingEntity>()
    (wifiAps.asReversed() + bleDevices.asReversed() + lanHosts.asReversed()).forEach { f ->
        latestByKey[dedupeKey(f.type, f.payloadJson)] = f // reversed feed: last write = newest row
    }

    val devs = mutableListOf<Dev>()
    latestByKey.values.forEach { f ->
        val s = FindingFormatter.summarize(f)
        val cat = DeviceClassifier.categoryOfEntity(f.payloadJson) ?: DeviceClassifier.CAT_OTHER
        val prefix = if (f.type == "HOST") "LAN " else ""
        val flagged = when (f.type) {
            "BLE" -> f.flagged || DeviceClassifier.isAlertCategory(cat)
            else -> DeviceClassifier.isAlertCategory(cat)
        }
        devs += Dev(f, prefix + s.headline, s.detail, flagged = flagged,
            copyable = deviceAddressOf(f.type, f.payloadJson))
    }

    val groupedDevs = devs.groupBy { DeviceClassifier.categoryOfEntity(it.f.payloadJson) ?: DeviceClassifier.CAT_OTHER }

    Column(modifier = Modifier.fillMaxSize()) {
        // quick scan actions pinned at top
        Row(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp)) {
            OutlinedButton(onClick = { onScanWifi { status = it } }, enabled = activeSessionId != null) {
                Text("WiFi scan", style = MaterialTheme.typography.labelMedium)
            }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(onClick = { onBleScan { status = it } }, enabled = activeSessionId != null) {
                Text("BLE scan", style = MaterialTheme.typography.labelMedium)
            }
            Spacer(Modifier.weight(1f))
            status?.let {
                Text(
                    it, style = MaterialTheme.typography.bodySmall,
                    color = TerminalGreen, modifier = Modifier.weight(2f)
                )
            }
        }

        LazyColumn(modifier = Modifier.fillMaxSize().padding(horizontal = 12.dp)) {
            if (activeSessionId == null) {
                item { EmptyState("No session", "Start monitoring, then run a WiFi or BLE scan.") }
            }

            // ================= RED ALERTS (always on top) =================
            item { GroupHeader("⚠ Possible Evil Twins (${wifiEvilTwin.size})", AlertRed) }
            if (wifiEvilTwin.isEmpty()) {
                item {
                    Text(
                        "   none detected this session",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
                    )
                }
            } else {
                items(wifiEvilTwin) { f ->
                    val summary = remember(f.id) { FindingFormatter.summarize(f) }
                    RedFindingRow(summary.headline, summary.detail, copyable = deviceAddressOf(f.type, f.payloadJson))
                }
            }

            val alertDevs = devs.filter { it.f.type == "BLE" && it.flagged }
            if (alertDevs.isNotEmpty()) {
                item { GroupHeader("⚠ Trackers / Flipper Alerts (${alertDevs.size})", AlertRed) }
                items(alertDevs) { d -> RedFindingRow(d.name ?: "?", d.detail, copyable = d.copyable) }
            }

            // ================= BLUETOOTH SECTION =================
            item { SectionHeader("BLUETOOTH", bleDevices.size) }
            val bleGroups = groupedDevs.filter { it.value.any { d -> d.f.type == "BLE" } }
            val bleNonAlertGroups = bleGroups
                .mapValues { (_, list) -> list.filter { d -> d.f.type == "BLE" && !d.flagged } }
                .filter { it.value.isNotEmpty() }
            if (bleNonAlertGroups.isEmpty()) {
                item {
                    Text(
                        "   no devices yet — run a BLE scan",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
                    )
                }
            } else {
                DeviceClassifier.CATEGORY_ORDER.forEach { category ->
                    val devices = bleNonAlertGroups[category].orEmpty()
                    if (devices.isNotEmpty()) {
                        item { GroupHeader("$category (${devices.size})", SignalYellow) }
                        items(devices) { d -> DeviceRow(d.name ?: "?", d.detail, copyable = d.copyable) }
                    }
                }
            }

            // ================= WI-FI SECTION =================
            item { SectionHeader("WI-FI", wifiAps.size + wifiAnomalies.size) }

            // anomalies first (congestion/open nets — evil twins already above)
            if (wifiOtherAnomalies.isNotEmpty()) {
                item { GroupHeader("WiFi anomalies (${wifiOtherAnomalies.size})", SignalYellow) }
                items(wifiOtherAnomalies) { f ->
                    val summary = remember(f.id) { FindingFormatter.summarize(f) }
                    DeviceRow(summary.headline, summary.detail, headlineColor = SignalYellow, copyable = deviceAddressOf(f.type, f.payloadJson))
                }
            }

            // APs grouped by classified device type
            val wifiGroups = groupedDevs
                .mapValues { (_, list) -> list.filter { d -> d.f.type == "WIFI_AP" } }
                .filter { it.value.isNotEmpty() }
            DeviceClassifier.CATEGORY_ORDER.forEach { category ->
                val devices = wifiGroups[category].orEmpty()
                if (devices.isNotEmpty()) {
                    item { GroupHeader("$category (${devices.size})", SignalYellow) }
                    items(devices) { d -> DeviceRow(d.name ?: "?", d.detail, copyable = d.copyable) }
                }
            }

            // LAN neighbors from ARP/active sweep live here too — same radio
            val lanDevs = devs.filter { it.f.type == "HOST" }
            if (lanDevs.isNotEmpty()) {
                item { GroupHeader("LAN neighbors (${lanDevs.size})", SignalYellow) }
                items(lanDevs) { d -> DeviceRow(d.name ?: "?", d.detail, copyable = d.copyable) }
            }

            if (wifiOtherAnomalies.isEmpty() && wifiGroups.isEmpty() && lanDevs.isEmpty()) {
                item {
                    Text(
                        "   no networks yet — run a WiFi scan",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
                    )
                }
            }

            if (findings.isEmpty() && activeSessionId != null) {
                item { EmptyState("Silence", "Run a WiFi scan or BLE scan to populate this tab.") }
            }
        }
    }
}

@Composable
private fun DeviceRow(
    headline: String,
    detail: String,
    headlineColor: androidx.compose.ui.graphics.Color = TerminalGreen,
    copyable: String? = null
) {
    val ctx = androidx.compose.ui.platform.LocalContext.current

    fun copyId() {
        if (copyable == null) return
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        cm.setPrimaryClip(android.content.ClipData.newPlainText("NetGuard", copyable))
        android.widget.Toast.makeText(ctx, "Copied $copyable", android.widget.Toast.LENGTH_SHORT).show()
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .then(
                if (copyable != null)
                    Modifier.combinedClickable(onClick = {}, onLongClick = { copyId() })
                else Modifier
            )
            .padding(horizontal = 10.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                ">> $headline",
                style = MaterialTheme.typography.titleSmall, color = headlineColor
            )
            Text(
                detail, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        if (copyable != null) {
            IconButton(onClick = { copyId() }, modifier = Modifier.size(28.dp)) {
                Icon(
                    Icons.Default.ContentCopy,
                    contentDescription = "Copy $copyable",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(15.dp)
                )
            }
        }
    }
    Divider(color = MaterialTheme.colorScheme.outline, thickness = 0.5.dp)
}

@Composable
private fun RedFindingRow(headline: String, detail: String, copyable: String? = null) {
    val ctx = androidx.compose.ui.platform.LocalContext.current

    fun copyId() {
        if (copyable == null) return
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        cm.setPrimaryClip(android.content.ClipData.newPlainText("NetGuard", copyable))
        android.widget.Toast.makeText(ctx, "Copied $copyable", android.widget.Toast.LENGTH_SHORT).show()
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .then(
                if (copyable != null)
                    Modifier.combinedClickable(onClick = {}, onLongClick = { copyId() })
                else Modifier
            )
            .background(AlertRed.copy(alpha = 0.10f))
            .padding(horizontal = 10.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                ">> $headline",
                style = MaterialTheme.typography.titleSmall, color = AlertRed
            )
            Text(
                detail, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        if (copyable != null) {
            IconButton(onClick = { copyId() }, modifier = Modifier.size(28.dp)) {
                Icon(
                    Icons.Default.ContentCopy,
                    contentDescription = "Copy $copyable",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(15.dp)
                )
            }
        }
    }
    Divider(color = MaterialTheme.colorScheme.outline, thickness = 0.5.dp)
}

@Composable
private fun GroupHeader(title: String, color: androidx.compose.ui.graphics.Color) {
    Text(
        title,
        style = MaterialTheme.typography.titleSmall,
        color = color,
        modifier = Modifier
            .fillMaxWidth()
            .background(androidx.compose.ui.graphics.Color(0xFF1A1A1A))
            .padding(horizontal = 10.dp, vertical = 5.dp)
    )
}

/** Big radio-type divider: BLUETOOTH / WI-FI sections at a glance. */
@Composable
private fun SectionHeader(title: String, count: Int) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(androidx.compose.ui.graphics.Color(0xFF111111))
            .padding(horizontal = 10.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            title, style = MaterialTheme.typography.titleMedium, color = SignalYellow
        )
        Spacer(Modifier.width(8.dp))
        Text(
            "($count)", style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun ScanRow(label: String, description: String, onClick: () -> Unit) {
    OutlinedCard(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(label, style = MaterialTheme.typography.titleSmall)
            Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun FindingsTab(database: NetGuardDatabase, sessionId: String?) {
    if (sessionId == null) {
        EmptyState("No active session", "Start monitoring from the Monitor tab to begin collecting findings.")
        return
    }

    // UI window: newest 300 rows only — the unbounded observe re-diffed the
    // whole session per insert and stalled the tab during scan bursts.
    val allFindings by database.findingDao()
        .observeForSessionLimited(sessionId, 300)
        .collectAsStateWithLifecycle(initialValue = emptyList())

    var flaggedOnly by remember { mutableStateOf(false) }
    var typeFilter by remember { mutableStateOf<String?>(null) }
    val openGroups = remember { mutableStateMapOf<String, Boolean>() } // intel targets + radio groups

    val types = remember(allFindings) { allFindings.map { it.type }.distinct() }
    val visible = allFindings
        .filter { !flaggedOnly || it.flagged }
        .filter { typeFilter == null || it.type == typeFilter }

    // ---- intel (recon) rows → one record per TARGET ----
    val intelFindings = visible.filter {
        it.type == "OSINT" || it.type == "WEB" || it.type == "ATTACKER_LOOKUP" || it.type == "PUBLIC_IP"
    }

    fun targetKeyOf(entity: FindingEntity): String {
        val raw = when (entity.type) {
            "WEB" -> Regex("\"target\"\\s*:\\s*\"([^\"]+)\"").find(entity.payloadJson)
                ?.groupValues?.get(1) ?: "?"
            "ATTACKER_LOOKUP" -> Regex("\"ip\"\\s*:\\s*\"([^\"]+)\"").find(entity.payloadJson)
                ?.groupValues?.get(1) ?: "?"
            "OSINT" -> Regex("\"identifier\"\\s*:\\s*\"([^\"]+)\"").find(entity.payloadJson)
                ?.groupValues?.get(1) ?: "?"
            else -> return "network's public IP"
        }
        // OSINT username-matrix rows carry "Platform:username" identifiers
        // (GitHub:nova, Reddit:nova...) — stack them under the USERNAME so
        // one username lookup = one record, same as recon stacking.
        if (entity.type == "OSINT" &&
            "\"kind\"\\s*:\\s*\"USERNAME\"".toRegex().containsMatchIn(entity.payloadJson)) {
            val user = raw.substringAfter(':', "").trim()
            if (user.isNotBlank()) return user
        }
        // WEB target shapes: "example.com TXT" (DNS_RECORD), "example.com/a"
        // (DIR), full URL (REFLECT/HEADER host), "vhost v @ host",
        // plain host (SUBDOMAIN/SUB rows). Normalize all to ONE base host so
        // every result of an example.com recon lands in ONE record.
        // WEB target shapes: "example.com TXT" (DNS_RECORD), "example.com/a"
        // (DIR), full URL (REFLECT/HEADER host), "vhost v @ host",
        // plain host (SUBDOMAIN/SUB rows). Normalize all to ONE base host so
        // every result of an example.com recon lands in ONE record.
        var t = raw.trim()
        if (t.contains("://")) {
            t = try { java.net.URI(t).host ?: t } catch (_: Exception) { t }
        }
        if (t.startsWith("vhost ")) {
            t = t.substringAfter("@").trim().ifBlank { t }
        }
        val spaceSplit = t.split(" ")
        val hostish = if (spaceSplit.size >= 2 && !spaceSplit[0].contains("/") &&
            spaceSplit[0].contains(".")) spaceSplit[0] else t.substringBefore("/")
        return hostish.trim('[', ']').lowercase().ifBlank { raw }
    }

    val intelGroups = LinkedHashMap<String, MutableList<FindingEntity>>()
    intelFindings.forEach { f ->
        intelGroups.getOrPut(targetKeyOf(f)) { mutableListOf() }.add(f)
    }

    // ---- device rows → collapsible radio sections ----
    val radioOf: (String) -> String = { type ->
        when (type) {
            "BLE", "GATT" -> "Bluetooth"
            "WIFI_AP" -> "WiFi"
            // anomalies get their OWN section below WI-FI — mixed in, the
            // band-wide congestion rows read as broken AP entries (crushed).
            "WIFI_ANOMALY" -> "WiFi Anomalies"
            "HOST", "OPEN_PORT" -> "LAN"
            else -> "Info"
        }
    }
    val deviceFindings = visible.filter {
        it.type != "OSINT" && it.type != "WEB" && it.type != "ATTACKER_LOOKUP" && it.type != "PUBLIC_IP"
    }
    val radioGroups = LinkedHashMap<String, List<FindingEntity>>()
    listOf("Bluetooth", "WiFi", "WiFi Anomalies", "LAN", "Info").forEach { radio ->
        deviceFindings.filter { radioOf(it.type) == radio }.takeIf { it.isNotEmpty() }?.let {
            radioGroups[radio] = it
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(horizontal = 12.dp, vertical = 8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            FilterChip(
                selected = flaggedOnly,
                onClick = { flaggedOnly = !flaggedOnly },
                label = { Text("Flagged only") },
                leadingIcon = if (flaggedOnly) { { Icon(Icons.Default.Check, null) } } else null
            )
            Spacer(Modifier.width(8.dp))
            Text("${visible.size} shown", style = MaterialTheme.typography.bodySmall)
        }
        Spacer(Modifier.height(4.dp))

        if (types.isNotEmpty()) {
            TypeFilterChips(types = types, selected = typeFilter, onSelect = { typeFilter = it })
            Spacer(Modifier.height(4.dp))
        }

        if (visible.isEmpty()) {
            EmptyState("Listening", "No findings match the current filters yet.")
        } else {
            LazyColumn {
                // ---- recon intel: one foldable record per target ----
                intelGroups.forEach { (target, rows) ->
                    val open = openGroups["intel:$target"] == true
                    item(key = "intel-$target") {
                        IntelRecordRow(
                            target = target,
                            count = rows.size,
                            hasFlagged = rows.any { it.flagged },
                            open = open,
                            onToggle = { openGroups["intel:$target"] = !open }
                        )
                    }
                    if (open) {
                        items(rows, key = { "i-${it.id}" }) { finding -> FindingRow(finding) }
                    }
                }

                // ---- radio sections: BLUETOOTH / WI-FI / LAN / INFO, folded ----
                radioGroups.forEach { (radio, rows) ->
                    val open = openGroups["radio:$radio"] == true
                    item(key = "radio-$radio") {
                        RadioGroupRow(
                            title = radio.uppercase(),
                            count = rows.size,
                            open = open,
                            onToggle = { openGroups["radio:$radio"] = !open }
                        )
                    }
                    if (open) {
                        items(rows, key = { "r-${it.id}" }) { finding -> FindingRow(finding) }
                    }
                }
            }
        }
    }
}

/**
 * Collapsible radio section header for the Findings tab (BLUETOOTH (13),
 * WI-FI (8)...): folded by default so scan bursts stay clean.
 */
@Composable
private fun RadioGroupRow(title: String, count: Int, open: Boolean, onToggle: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .background(androidx.compose.ui.graphics.Color(0xFF111111))
            .combinedClickable(onClick = onToggle)
            .padding(horizontal = 10.dp, vertical = 9.dp)
    ) {
        Icon(
            if (open) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
            contentDescription = if (open) "Collapse $title" else "Expand $title",
            tint = TerminalGreen,
            modifier = Modifier.size(18.dp)
        )
        Spacer(Modifier.width(6.dp))
        Text(
            "$title ($count)",
            style = MaterialTheme.typography.titleSmall,
            color = TerminalGreen
        )
        Spacer(Modifier.weight(1f))
        Text(
            if (open) "tap to fold" else "tap to open",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

/**
 * One recon record: [target] with its result count; tap expands every
 * finding the recon produced for that single target in one place.
 */
@Composable
private fun IntelRecordRow(
    target: String,
    count: Int,
    hasFlagged: Boolean,
    open: Boolean,
    onToggle: () -> Unit
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .background(
                if (open) AlertRed.copy(alpha = 0.06f)
                else androidx.compose.ui.graphics.Color(0xFF1A1A1A)
            )
            .combinedClickable(onClick = onToggle)
            .padding(horizontal = 10.dp, vertical = 9.dp)
    ) {
        Icon(
            if (open) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
            contentDescription = if (open) "Collapse $target intel" else "Expand $target intel",
            tint = SignalYellow,
            modifier = Modifier.size(18.dp)
        )
        Spacer(Modifier.width(6.dp))
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "🛰 $target",
                    style = MaterialTheme.typography.titleSmall,
                    color = if (hasFlagged) AlertRed else SignalYellow
                )
                if (hasFlagged) {
                    Spacer(Modifier.width(6.dp))
                    Text("⚠", color = AlertRed, style = MaterialTheme.typography.titleSmall)
                }
            }
            Text(
                "$count results — tap to ${if (open) "fold" else "open"}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
    Divider(color = MaterialTheme.colorScheme.outline, thickness = 0.5.dp)
}

@Composable
private fun TypeFilterChips(types: List<String>, selected: String?, onSelect: (String?) -> Unit) {
    // Horizontal slider: with WiFi/BLE/OSINT/web active in one session the
    // chips overflow a fixed Row and the last ones (OSINT) render OFF-SCREEN,
    // unreachable — the fixed Row clipped them instead of scrolling.
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(androidx.compose.foundation.rememberScrollState())
    ) {
        FilterChip(selected = selected == null, onClick = { onSelect(null) }, label = { Text("All") })
        Spacer(Modifier.width(6.dp))
        types.forEach { type ->
            FilterChip(selected = selected == type, onClick = { onSelect(if (selected == type) null else type) }, label = { Text(type) })
            Spacer(Modifier.width(6.dp))
        }
    }
}

/**
 * Styled after the reference scan-log mockup: `>>` prompt prefix, monospace,
 * flagged rows get a red "!" badge instead of a generic warning glyph.
 * Deliberately terse — this is a log you scan quickly, not prose.
 */
@Composable
private fun FindingRow(finding: FindingEntity) {
    val summary = remember(finding.id) { FindingFormatter.summarize(finding) }
    val ctx = androidx.compose.ui.platform.LocalContext.current
    val copyable = remember(finding.id) { deviceAddressOf(finding.type, finding.payloadJson) }

    fun copyId() {
        if (copyable == null) return
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        cm.setPrimaryClip(android.content.ClipData.newPlainText("NetGuard", copyable))
        android.widget.Toast.makeText(ctx, "Copied $copyable", android.widget.Toast.LENGTH_SHORT).show()
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .then(
                if (copyable != null)
                    Modifier.combinedClickable(onClick = {}, onLongClick = { copyId() })
                else Modifier
            )
            .background(if (finding.flagged) AlertRed.copy(alpha = 0.08f) else androidx.compose.ui.graphics.Color.Transparent)
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.Top
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    ">> ",
                    style = MaterialTheme.typography.bodySmall,
                    color = SignalYellow
                )
                // Source badge: Bluetooth / WiFi / LAN scan / OSINT / Web recon…
                Box(
                    modifier = Modifier
                        .background(
                            when (FindingFormatter.sourceLabel(finding)) {
                                "Bluetooth" -> androidx.compose.ui.graphics.Color(0xFF1D3A53)
                                "WiFi", "LAN scan", "Network info" -> androidx.compose.ui.graphics.Color(0xFF2A3A1D)
                                "OSINT", "Web recon" -> androidx.compose.ui.graphics.Color(0xFF3A2A1D)
                                else -> androidx.compose.ui.graphics.Color(0xFF222222)
                            },
                            shape = androidx.compose.foundation.shape.RoundedCornerShape(4.dp)
                        )
                        .padding(horizontal = 5.dp, vertical = 1.dp)
                ) {
                    Text(
                        FindingFormatter.sourceLabel(finding),
                        style = MaterialTheme.typography.labelSmall,
                        color = SignalYellow
                    )
                }
                Spacer(Modifier.width(6.dp))
                Text(
                    summary.headline,
                    style = MaterialTheme.typography.titleSmall,
                    color = if (finding.flagged) AlertRed else TerminalGreen
                )
            }
            Text(
                summary.detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 20.dp, top = 2.dp)
            )
        }
        if (copyable != null) {
            IconButton(onClick = { copyId() }, modifier = Modifier.size(28.dp)) {
                Icon(
                    Icons.Default.ContentCopy,
                    contentDescription = "Copy $copyable",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(15.dp)
                )
            }
        }
        if (finding.flagged) {
            Box(
                modifier = Modifier
                    .padding(start = 8.dp)
                    .background(AlertRed, shape = androidx.compose.foundation.shape.RoundedCornerShape(3.dp))
                    .padding(horizontal = 6.dp, vertical = 2.dp)
            ) {
                Text("!", color = androidx.compose.ui.graphics.Color.White, style = MaterialTheme.typography.labelLarge)
            }
        }
    }
    Divider(color = MaterialTheme.colorScheme.outline, thickness = 0.5.dp)
}

@Composable
private fun GattTab(database: NetGuardDatabase, activeSessionId: String?, onGattProbe: (String, (String) -> Unit) -> Unit) {
    var address by remember { mutableStateOf("") }
    var status by remember { mutableStateOf<String?>(null) }

    val findings by database.findingDao()
        .observeForSession(activeSessionId ?: "")
        .collectAsStateWithLifecycle(initialValue = emptyList())
    val gattFindings = findings.filter { it.type == "GATT" }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("BLE GATT profiling", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = address,
                onValueChange = { address = it },
                label = { Text("MAC from Findings (BLE)") },
                singleLine = true,
                modifier = Modifier.weight(1f)
            )
            Spacer(Modifier.width(8.dp))
            Button(
                onClick = { onGattProbe(address) { status = it } },
                enabled = activeSessionId != null && address.isNotBlank()
            ) { Text("Probe") }
        }
        if (activeSessionId == null) {
            Spacer(Modifier.height(4.dp))
            Text(
                "Start a session first (probes file under the session).",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        status?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, style = MaterialTheme.typography.bodySmall, color = TerminalGreen)
        }

        Spacer(Modifier.height(16.dp))
        Text("Profiles this session (${gattFindings.size})", style = MaterialTheme.typography.titleSmall)
        Spacer(Modifier.height(4.dp))
        LazyColumn {
            items(gattFindings.asReversed()) { f ->
                val summary = remember(f.id) { FindingFormatter.summarize(f) }
                Card(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Text(
                            summary.headline,
                            style = MaterialTheme.typography.titleSmall,
                            color = if (f.flagged) AlertRed else TerminalGreen
                        )
                        Text(summary.detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
    }
}

@Composable
private fun FoxHuntTab(
    activeSessionId: String?,
    onHuntStart: (String, (String) -> Unit) -> Unit,
    onHuntStop: () -> Unit,
    huntState: kotlinx.coroutines.flow.StateFlow<FoxHuntUi?>,
    prefillMac: String?
) {
    var mac by remember(prefillMac) { mutableStateOf(prefillMac ?: "") }
    val hunt by huntState.collectAsStateWithLifecycle()

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text("🦊 BLE Fox Hunt", style = MaterialTheme.typography.titleMedium)
        Text(
            "Lock onto a tracker (AirTag/Tile/Flipper...) and walk — warmer/colder by signal.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(10.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = mac,
                onValueChange = { mac = it },
                label = { Text("Target MAC (AA:BB:CC:DD:EE:FF)") },
                singleLine = true,
                modifier = Modifier.weight(1f)
            )
            Spacer(Modifier.width(8.dp))
            val hunting = hunt?.running == true
            Button(
                onClick = {
                    if (hunting) onHuntStop()
                    else onHuntStart(mac) { }
                },
                enabled = !hunting && mac.isNotBlank() && activeSessionId != null ||
                    hunting // allow stop regardless
            ) {
                Text(if (hunting) "Stop" else "Hunt")
            }
        }
        if (activeSessionId == null) {
            Spacer(Modifier.height(4.dp))
            Text(
                "Start a session first (hunt ticks log under it).",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        Spacer(Modifier.height(18.dp))

        val h = hunt
        if (h == null || !h.running && h.rssi == Int.MIN_VALUE) {
            EmptyState(
                "Not hunting",
                "Enter the MAC of the device you're hunting (from Findings — BLE rows, long-press to copy), then press Hunt and walk slowly."
            )
        } else {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = if (h.rssi >= -64) AlertRed.copy(alpha = 0.18f)
                    else MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        h.estimate,
                        style = MaterialTheme.typography.headlineMedium,
                        color = when {
                            h.rssi >= -64 -> AlertRed
                            h.rssi >= -75 -> SignalYellow
                            else -> TerminalGreen
                        }
                    )
                    Spacer(Modifier.height(6.dp))
                    Text("RSSI now: ${h.rssi} dBm", style = MaterialTheme.typography.bodyMedium)
                    Text(
                        "Best signal seen: ${if (h.bestRssi == Int.MIN_VALUE) "—" else "${h.bestRssi} dBm"}" +
                            (if (h.bestRssi != Int.MIN_VALUE) " — walk back to where that was" else ""),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        "Packets from target: ${h.observations}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            Spacer(Modifier.height(10.dp))
            Text(
                "Every packet also lands in Findings (BLE rows tagged foxhunt) as a hunt log.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun ReportsTab(

    database: NetGuardDatabase,
    activeSessionId: String?,
    onExportAndShare: (String, ExportFormat, (String) -> Unit) -> Unit,
    onDeleteSession: (String, (String) -> Unit) -> Unit,
    onOpenReport: (String, ExportFormat, (ReportViewerPayload?) -> Unit) -> Unit,
    onShowViewer: (ReportViewerPayload) -> Unit,
    onSaveAllToDownloads: (String, (String) -> Unit) -> Unit
) {
    val sessions by database.sessionDao().observeAll().collectAsStateWithLifecycle(initialValue = emptyList())
    var statusMessage by remember { mutableStateOf<String?>(null) }
    var confirmDeleteFor by remember { mutableStateOf<SessionEntity?>(null) }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Reports", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.width(8.dp))
            Text(
                "— kept on this phone until deleted",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(Modifier.height(8.dp))

        statusMessage?.let {
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer)) {
                Text(it, modifier = Modifier.padding(12.dp), style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.height(8.dp))
        }

        if (sessions.isEmpty()) {
            EmptyState("No sessions yet", "Start and stop a monitoring session to generate your first report.")
            return
        }

        LazyColumn {
            items(sessions) { session ->
                SessionReportCard(
                    session = session,
                    isActive = session.id == activeSessionId,
                    onOpen = { format -> onOpenReport(session.id, format) { payload ->
                        if (payload == null) statusMessage = "Couldn't open report — no data for that session?"
                        else onShowViewer(payload)
                    } },
                    onExport = { format -> onExportAndShare(session.id, format) { statusMessage = it } },
                    onSaveAll = { onSaveAllToDownloads(session.id) { statusMessage = it } },
                    onDelete = { confirmDeleteFor = session }
                )
            }
        }
    }

    confirmDeleteFor?.let { session ->
        AlertDialog(
            onDismissRequest = { confirmDeleteFor = null },
            title = { Text("Delete this report?") },
            text = {
                Text("Removes '${session.label}' and all its findings + exported files from this phone. Export/share first if you still need it — this cannot be undone.")
            },
            confirmButton = {
                TextButton(onClick = {
                    confirmDeleteFor = null
                    onDeleteSession(session.id) { statusMessage = it }
                }) { Text("Delete", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmDeleteFor = null }) { Text("Cancel") } }
        )
    }
}

@Composable
private fun SessionReportCard(
    session: SessionEntity,
    isActive: Boolean,
    onOpen: (ExportFormat) -> Unit,
    onExport: (ExportFormat) -> Unit,
    onSaveAll: () -> Unit,
    onDelete: () -> Unit
) {
    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(session.label, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                if (isActive) {
                    Spacer(Modifier.width(8.dp))
                    AssistChip(onClick = {}, label = { Text("active") })
                }
                IconButton(onClick = onDelete, modifier = Modifier.size(28.dp)) {
                    Icon(
                        Icons.Default.Delete, contentDescription = "Delete report",
                        tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(18.dp)
                    )
                }
            }
            Text(
                "Scope: ${session.scopeDeclaration}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(8.dp))
            // Open (in-app viewer)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("Open:", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                TextButton(onClick = { onOpen(ExportFormat.MARKDOWN) }, contentPadding = PaddingValues(horizontal = 8.dp)) { Text(".md") }
                TextButton(onClick = { onOpen(ExportFormat.PDF) }, contentPadding = PaddingValues(horizontal = 8.dp)) { Text(".pdf") }
                TextButton(onClick = { onOpen(ExportFormat.JSON) }, contentPadding = PaddingValues(horizontal = 8.dp)) { Text(".json") }
            }
            // Share (system share sheet)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("Share:", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                OutlinedButton(onClick = { onExport(ExportFormat.MARKDOWN) }, contentPadding = PaddingValues(horizontal = 10.dp)) { Text(".md") }
                OutlinedButton(onClick = { onExport(ExportFormat.PDF) }, contentPadding = PaddingValues(horizontal = 10.dp)) { Text(".pdf") }
                OutlinedButton(onClick = { onExport(ExportFormat.JSON) }, contentPadding = PaddingValues(horizontal = 10.dp)) { Text(".json") }
            }
            // Save all to Downloads
            TextButton(onClick = onSaveAll) {
                Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(6.dp))
                Text("Save all to Downloads")
            }
        }
    }
}

/**
 * Full-screen report viewer: monospace text (md/json) or rendered PDF pages
 * (PdfRenderer), back gesture/button closes, sticky "Close" bar on top.
 */
@Composable
private fun ReportViewerScreen(payload: ReportViewerPayload, onClose: () -> Unit) {
    BackHandler { onClose() }

    Surface(modifier = Modifier.fillMaxSize(), color = NetBlack) {
        Column(modifier = Modifier.fillMaxSize()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(androidx.compose.ui.graphics.Color(0xFF141414))
                    .padding(horizontal = 12.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    payload.title,
                    style = MaterialTheme.typography.titleSmall,
                    color = SignalYellow,
                    modifier = Modifier.weight(1f),
                    maxLines = 1
                )
                TextButton(onClick = onClose) { Text("Close") }
            }

            if (payload.isPdf) {
                PdfPager(file = payload.file)
            } else {
                val text = payload.text ?: "(unreadable report)"
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .padding(12.dp)
                ) {
                    Text(
                        text,
                        style = MaterialTheme.typography.bodySmall,
                        color = androidx.compose.ui.graphics.Color(0xFFD6D6D6)
                    )
                }
            }
        }
    }
}

/** Renders every PDF page via PdfRenderer as a lazily-allocated bitmap. */
@Composable
private fun PdfPager(file: File) {
    val context = LocalContext.current
    val pages = remember(file.path) {
        runCatching {
            ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY).use { pfd ->
                PdfRenderer(pfd).use { r -> r.pageCount }
            }
        }.getOrDefault(0)
    }
    if (pages == 0) {
        EmptyState("PDF error", "Couldn't render this report — file may be corrupt.")
        return
    }

    val listState = rememberLazyListState()
    LazyColumn(state = listState, modifier = Modifier.fillMaxSize()) {
        items(pages) { index ->
            PdfPageImage(file = file, index = index)
            Text(
                "page ${index + 1} / $pages",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                textAlign = androidx.compose.ui.text.style.TextAlign.Center
            )
        }
    }
}

@Composable
private fun PdfPageImage(file: File, index: Int) {
    val context = LocalContext.current
    val density = LocalDensity.current
    var bitmap by remember(file.path, index) { mutableStateOf<android.graphics.Bitmap?>(null) }
    var widthRatio by remember(file.path, index) { mutableStateOf(1f) }

    LaunchedEffect(file.path, index) {
        withContext(Dispatchers.IO) {
            runCatching {
                ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY).use { pfd ->
                    PdfRenderer(pfd).use { renderer ->
                        val page = renderer.openPage(index)
                        try {
                            val targetW = minOf(
                                2048,
                                (context.resources.displayMetrics.widthPixels * 1.6f).toInt()
                            )
                            val targetH = (targetW * page.height.toFloat() / page.width).toInt().coerceAtLeast(1)
                            val bmp = android.graphics.Bitmap.createBitmap(targetW, targetH, Bitmap.Config.ARGB_8888)
                            bmp.eraseColor(android.graphics.Color.WHITE)
                            page.render(bmp, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                            bmp to (page.width.toFloat() / page.height)
                        } finally {
                            page.close()
                        }
                    }
                }
            }.onSuccess { (bmp, ratio) ->
                bitmap = bmp
                widthRatio = ratio
            }
        }
    }

    bitmap?.let { bmp ->
        Image(
            bitmap = bmp.asImageBitmap(),
            contentDescription = "report page ${index + 1}",
            modifier = Modifier.fillMaxWidth(),
            contentScale = ContentScale.FillWidth
        )
    } ?: Box(
        modifier = Modifier.fillMaxWidth().height(240.dp),
        contentAlignment = Alignment.Center
    ) { CircularProgressIndicator(modifier = Modifier.size(28.dp)) }
}

@Composable
private fun EmptyState(title: String, body: String) {
    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(title, style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(4.dp))
        Text(body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}