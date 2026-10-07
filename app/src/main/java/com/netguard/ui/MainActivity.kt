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
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
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
    private lateinit var webRecon: WebReconModule
    private lateinit var reportExporter: ReportExporter
    private var activeSessionId: String? = null

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result -> if (result.resultCode == RESULT_OK) startVpnService() }

    private val runtimePermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { /* each module fails soft without permission; nothing to react to here */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        trackerScanner = TrackerScanner(this)
        hostDiscovery = HostDiscovery()
        passiveDiscovery = PassiveDiscovery(applicationContext)
        wifiAuditor = WifiAuditor(this)
        bleDiscovery = BleDiscovery(this)
        webRecon = WebReconModule()
        val app = application as NetGuardApp
        reportExporter = ReportExporter(app.database.sessionDao(), app.database.findingDao())

        // OSINT keys persist across launches; loaded into the module on start.
        val prefs = getSharedPreferences("netguard-config", Context.MODE_PRIVATE)
        OsintModule.hibpKey = prefs.getString("hibp_key", null)
        OsintModule.githubToken = prefs.getString("github_token", null)

        requestRuntimePermissions()

        setContent {
            NetGuardTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    NetGuardScreen(
                        database = app.database,
                        onStartSession = { scope, sessionId -> startSession(scope, sessionId) },
                        onStopSession = ::stopSession,
                        onScanHostsArp = ::runArpScan,
                        onScanHostsActive = ::runActiveSweep,
                        onScanWifi = ::runFullWifiSweep,
                        onBleScan = ::runBleScan,
                        onWebRecon = ::runWebRecon,
                        onOsint = ::runOsint,
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
        val sessionId = activeSessionId ?: return onStatus("Start a session first")
        val subnet = subnetBase() ?: return onStatus("Couldn't determine your subnet — are you on WiFi?")
        val app = application as NetGuardApp
        onStatus("Sweeping $subnet.0/24 — this takes a bit...")
        app.appScope.launchSafely {
            hostDiscovery.activeSweep(sessionId, subnet)
            passiveDiscovery.listenMdns(sessionId)
            passiveDiscovery.listenSsdp(sessionId)
            onStatus("Active sweep + mDNS/SSDP listen complete")
        }
    }

    /**
     * Full WiFi sweep: every visible AP recorded (airspace listing) PLUS the
     * anomaly analyzers. Works with the VPN stopped too — WiFi scans don't
     * need the tunnel.
     */
    private fun runFullWifiSweep(onStatus: (String) -> Unit) {
        val sessionId = activeSessionId ?: return onStatus("Start a session first (WiFi sweep files findings under the session)")
        val app = application as NetGuardApp
        onStatus("Full WiFi sweep running (4 passes, ~10s)...")
        app.appScope.launchSafely {
            val result = wifiAuditor.sweep(sessionId)
            val flagged = result.anomalies.count { it.flagged }
            onStatus("WiFi sweep: ${result.aps.size} APs listed, ${result.anomalies.size} anomalies ($flagged flagged)")
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
        startService(intent)
    }

    private fun stopSession() {
        stopService(Intent(this, NetGuardVpnService::class.java))
        trackerScanner.stopScanning()
        val sessionId = activeSessionId ?: return
        val app = application as NetGuardApp
        app.appScope.launchSafely {
            app.database.sessionDao().markEnded(sessionId, System.currentTimeMillis())
        }
        activeSessionId = null
    }
}

private fun kotlinx.coroutines.CoroutineScope.launchSafely(block: suspend () -> Unit) {
    launch { block() }
}

// ================= UI =================

private enum class Tab(val label: String, val icon: androidx.compose.ui.graphics.vector.ImageVector) {
    MONITOR("Monitor", Icons.Default.PlayArrow),
    NEARBY("Nearby", Icons.Default.Wifi),
    FINDINGS("Findings", Icons.Default.List),
    REPORTS("Reports", Icons.Default.Share),
    GATT("GATT", Icons.Default.Bluetooth)
}

@Composable
fun NetGuardScreen(
    database: NetGuardDatabase,
    onStartSession: (String, String) -> Unit,
    onStopSession: () -> Unit,
    onScanHostsArp: ((String) -> Unit) -> Unit,
    onScanHostsActive: ((String) -> Unit) -> Unit,
    onScanWifi: ((String) -> Unit) -> Unit,
    onBleScan: ((String) -> Unit) -> Unit,
    onWebRecon: (String, String?, (String) -> Unit) -> Unit,
    onOsint: (String, String, String, (String) -> Unit) -> Unit,
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
                    onScanHostsArp = onScanHostsArp,
                    onScanHostsActive = onScanHostsActive,
                    onScanWifi = onScanWifi,
                    onBleScan = onBleScan,
                    onWebRecon = onWebRecon,
                    onOsint = onOsint
                )
                Tab.FINDINGS -> FindingsTab(database = database, sessionId = activeSessionId)
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
    onScanHostsArp: ((String) -> Unit) -> Unit,
    onScanHostsActive: ((String) -> Unit) -> Unit,
    onScanWifi: ((String) -> Unit) -> Unit,
    onBleScan: ((String) -> Unit) -> Unit,
    onWebRecon: (String, String?, (String) -> Unit) -> Unit,
    onOsint: (String, String, String, (String) -> Unit) -> Unit
) {
    var scopeText by remember { mutableStateOf("My home network / own devices only") }
    var statusMessage by remember { mutableStateOf<String?>(null) }
    var showWebDialog by remember { mutableStateOf(false) }
    var showOsintDialog by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxSize()) {
        if (sessionActive) {
            Row(
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
                Text(
                    "MONITORING ACTIVE",
                    style = MaterialTheme.typography.bodySmall,
                    color = SignalYellow,
                    letterSpacing = 1.sp
                )
            }
        }

        // Pinned completion strip — sits directly under MONITORING ACTIVE so
        // a finished scan "pops up to the top" instead of scrolling away
        // with the rest of the controls.
        statusMessage?.let {
            Card(
                colors = CardDefaults.cardColors(
                    containerColor = if (it.startsWith("BLE scan:") || it.startsWith("WiFi sweep:") ||
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
                    label = "Active sweep",
                    description = "Slower — TCP-probes your whole /24 + mDNS/SSDP listen",
                    onClick = { onScanHostsActive { statusMessage = it } }
                )
                ScanRow(
                    label = "Full WiFi sweep",
                    description = "ALL visible APs listed + congestion, evil-twin & downgrade detection",
                    onClick = { onScanWifi { statusMessage = it } }
                )
                ScanRow(
                    label = "BLE device scan",
                    description = "Nearby devices grouped: headphones, Meta glasses, TVs, Flipper, trackers",
                    onClick = { onBleScan { statusMessage = it } }
                )
                ScanRow(
                    label = "Web recon (bug bounty)",
                    description = "crt.sh subdomains, DoH records, header audit, dir busting — target-scoped",
                    onClick = { showWebDialog = true }
                )
                ScanRow(
                    label = "OSINT",
                    description = "Username/IP/domain matrix, RDAP, Wayback, breaches (HIBP key), GitHub dorks",
                    onClick = { showOsintDialog = true }
                )
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

    if (showWebDialog) {
        WebReconDialog(
            onDismiss = { showWebDialog = false },
            onRun = { domain, testUrl ->
                showWebDialog = false
                onWebRecon(domain, testUrl.takeIf { it.isNotBlank() }) { statusMessage = it }
            }
        )
    }
    if (showOsintDialog) {
        OsintDialog(
            onDismiss = { showOsintDialog = false },
            onRun = { user, breach, domain ->
                showOsintDialog = false
                onOsint(user, breach, domain) { statusMessage = it }
            }
        )
    }
}

@Composable
private fun WebReconDialog(onDismiss: () -> Unit, onRun: (String, String) -> Unit) {
    var domain by remember { mutableStateOf("") }
    var testUrl by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Web recon target") },
        text = {
            Column {
                OutlinedTextField(
                    value = domain,
                    onValueChange = { domain = it },
                    label = { Text("target domain (e.g. target.com)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = testUrl,
                    onValueChange = { testUrl = it },
                    label = { Text("optional: URL with params for reflection triage") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "Only *.target.com is probed. .gov/.mil refused by design.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { if (domain.isNotBlank()) onRun(domain.trim(), testUrl.trim()) }) { Text("Run") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
}

@Composable
private fun OsintDialog(onDismiss: () -> Unit, onRun: (String, String, String) -> Unit) {
    var username by remember { mutableStateOf("") }
    var breachAccount by remember { mutableStateOf("") }
    var domain by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("OSINT targets") },
        text = {
            Column {
                OutlinedTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = { Text("username (platform matrix)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = breachAccount,
                    onValueChange = { breachAccount = it },
                    label = { Text("email/account (HIBP — needs key in Settings)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = domain,
                    onValueChange = { domain = it },
                    label = { Text("domain — or an IP address (RDAP/AbuseIPDB)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "Entering a target here = declaring authorization for it. IPs get RDAP + abuse intel; domains get RDAP/Wayback/GitHub. .gov/.mil refused.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { onRun(username.trim(), breachAccount.trim(), domain.trim()) }) { Text("Run") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
    )
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
    data class Dev(val f: FindingEntity, val name: String?, val detail: String, val flagged: Boolean)

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
        devs += Dev(f, prefix + s.headline, s.detail, flagged = flagged)
    }

    val groupedDevs = devs.groupBy { DeviceClassifier.categoryOfEntity(it.f.payloadJson) ?: DeviceClassifier.CAT_OTHER }

    Column(modifier = Modifier.fillMaxSize()) {
        // quick scan actions pinned at top
        Row(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp)) {
            OutlinedButton(onClick = { onScanWifi { status = it } }, enabled = activeSessionId != null) {
                Text("WiFi sweep", style = MaterialTheme.typography.labelMedium)
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
                    RedFindingRow(summary.headline, summary.detail)
                }
            }

            val alertDevs = devs.filter { it.f.type == "BLE" && it.flagged }
            if (alertDevs.isNotEmpty()) {
                item { GroupHeader("⚠ Trackers / Flipper Alerts (${alertDevs.size})", AlertRed) }
                items(alertDevs) { d -> RedFindingRow(d.name ?: "?", d.detail) }
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
                        items(devices) { d -> DeviceRow(d.name ?: "?", d.detail) }
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
                    DeviceRow(summary.headline, summary.detail, headlineColor = SignalYellow)
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
                    items(devices) { d -> DeviceRow(d.name ?: "?", d.detail) }
                }
            }

            // LAN neighbors from ARP/active sweep live here too — same radio
            val lanDevs = devs.filter { it.f.type == "HOST" }
            if (lanDevs.isNotEmpty()) {
                item { GroupHeader("LAN neighbors (${lanDevs.size})", SignalYellow) }
                items(lanDevs) { d -> DeviceRow(d.name ?: "?", d.detail) }
            }

            if (wifiOtherAnomalies.isEmpty() && wifiGroups.isEmpty() && lanDevs.isEmpty()) {
                item {
                    Text(
                        "   no networks yet — run a WiFi sweep",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
                    )
                }
            }

            if (findings.isEmpty() && activeSessionId != null) {
                item { EmptyState("Silence", "Run a WiFi sweep or BLE scan to populate this tab.") }
            }
        }
    }
}

@Composable
private fun DeviceRow(headline: String, detail: String, headlineColor: androidx.compose.ui.graphics.Color = TerminalGreen) {
    Row(modifier = Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 6.dp)) {
        Text(
            ">> $headline",
            style = MaterialTheme.typography.titleSmall, color = headlineColor
        )
        Spacer(Modifier.width(8.dp))
        Text(
            detail, style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
    Divider(color = MaterialTheme.colorScheme.outline, thickness = 0.5.dp)
}

@Composable
private fun RedFindingRow(headline: String, detail: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(AlertRed.copy(alpha = 0.10f))
            .padding(horizontal = 10.dp, vertical = 6.dp)
    ) {
        Text(
            ">> $headline",
            style = MaterialTheme.typography.titleSmall, color = AlertRed
        )
        Spacer(Modifier.width(8.dp))
        Text(
            detail, style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
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

    val allFindings by database.findingDao()
        .observeForSession(sessionId)
        .collectAsStateWithLifecycle(initialValue = emptyList())

    var flaggedOnly by remember { mutableStateOf(false) }
    var typeFilter by remember { mutableStateOf<String?>(null) }

    val types = remember(allFindings) { allFindings.map { it.type }.distinct() }
    val visible = allFindings
        .filter { !flaggedOnly || it.flagged }
        .filter { typeFilter == null || it.type == typeFilter }
        .asReversed()

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
                items(visible) { finding -> FindingRow(finding) }
            }
        }
    }
}

@Composable
private fun TypeFilterChips(types: List<String>, selected: String?, onSelect: (String?) -> Unit) {
    Row(modifier = Modifier.fillMaxWidth()) {
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

    Row(
        modifier = Modifier
            .fillMaxWidth()
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
                Text(
                    summary.headline,
                    style = MaterialTheme.typography.titleSmall,
                    color = if (finding.flagged) AlertRed else TerminalGreen
                )
            }
            Text(
                "[${finding.type}] ${summary.detail}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 20.dp, top = 2.dp)
            )
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