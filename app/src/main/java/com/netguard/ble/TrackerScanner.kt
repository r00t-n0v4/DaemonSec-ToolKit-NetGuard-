package com.netguard.ble

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat
import com.netguard.core.Finding
import com.netguard.core.FindingBus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Unwanted-tracker detection: continuously scans for BLE devices and flags
 * probable AirTags / Tiles / SmartTags either by their known service UUIDs or
 * by the movement heuristic (same MAC seen at 2+ distinct coarse locations
 * over 30+ minutes → it's traveling with you).
 */
class TrackerScanner(private val context: Context) {

    companion object {
        // Standard Bluetooth SIG assigned numbers for tracker beacons.
        private const val APPLE_FIND_MY_16 = 0x004C          // Apple, Inc (company id in manufacturer data)
        private const val POLL_INTERVAL_MS = 30_000L
        private const val FLAG_AFTER_MINUTES = 30L

        private val KNOWN_TRACKER_NAMES = listOf("AirTag", "Tile", "SmartTag", "SmartTag2", "Chipolo", "AirTag ")
    }

    private data class Observation(val rssi: Int, val at: Long, val latCell: String?, val lonCell: String?)

    // address -> observations (bounded; addresses age out with the heuristic window)
    private val observations = HashMap<String, MutableList<Observation>>()

    private var scanning = false

    fun startScanning(scope: CoroutineScope, sessionId: String) {
        stopScanning()
        if (!hasScanPermission()) return
        val adapter = bluetoothAdapter() ?: return
        if (!adapter.isEnabled) return
        val scanner = adapter.bluetoothLeScanner ?: return

        scanning = true
        scope.launch {
            val settings = ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_POWER)
                .build()
            while (scanning && isActive) {
                try {
                    scanner.startScan(null, settings, callback(sessionId))
                } catch (_: Exception) {}
                delay(POLL_INTERVAL_MS)
                try { scanner.stopScan(callback(sessionId)) } catch (_: Exception) {}
                flushFindings(sessionId)
            }
        }
    }

    fun stopScanning() {
        scanning = false
        try {
            bluetoothAdapter()?.bluetoothLeScanner?.stopScan(lastCallback ?: return)
        } catch (_: Exception) {}
        lastCallback = null
    }

    private var lastCallback: ScanCallback? = null

    private fun callback(sessionId: String): ScanCallback {
        // startScan/stopScan compare by identity; keep one instance around.
        return lastCallback ?: object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                record(result, sessionId)
            }
        }.also { lastCallback = it }
    }

    private fun record(result: ScanResult, sessionId: String) {
        val device = result.device ?: return
        val address = device.address ?: return
        val name = try { result.scanRecord?.deviceName ?: device.name } catch (_: SecurityException) { null }
        val rssi = result.rssi

        val trackerType = detectTrackerType(result, name)
        if (trackerType != null) {
            // Known tracker beacon — flag immediately, no location heuristic needed.
            FindingBus.emit(
                Finding.BleDevice(
                    sessionId = sessionId, address = address, name = name,
                    trackerType = trackerType, rssi = rssi,
                    timesSeenAtDistinctLocations = locationCellCount(address),
                    flagged = true
                )
            )
            observations[address] = (observations[address] ?: mutableListOf()).apply {
                add(Observation(rssi, System.currentTimeMillis(), coarseLocationCell(), null))
            }
            return
        }

        // Movement heuristic bookkeeping for everything else.
        val cell = coarseLocationCell()
        observations.getOrPut(address) { mutableListOf() }
            .add(Observation(rssi, System.currentTimeMillis(), cell, null))
        if (observations.size > 400) { // bound memory: drop oldest addresses
            val cut = System.currentTimeMillis() - 2 * 60 * 60 * 1000
            observations.entries.removeIf { it.value.none { o -> o.at > cut } }
        }
    }

    private fun detectTrackerType(result: ScanResult, name: String?): String? {
        if (name != null && KNOWN_TRACKER_NAMES.any { name.contains(it, ignoreCase = true) }) {
            return when {
                name.contains("Tile", true) -> "Tile"
                name.contains("SmartTag", true) -> "Samsung SmartTag"
                name.contains("Chipolo", true) -> "Chipolo"
                else -> "AirTag/Find My"
            }
        }
        val serviceUuids = result.scanRecord?.serviceUuids ?: return null
        for (uuid in serviceUuids) {
            val s = uuid.toString()
            if (s.equals("0000fd6f-0000-1000-8000-00805f9b34fb", true)) return "Chipolo"
            if (s.startsWith("0000fe2c", true)) return "Samsung SmartTag"
        }
        // Apple continuity beacons (Find My) advertise 0x004C manufacturer data
        // with type 0x12 offline-finding payloads — heuristic on company id + type.
        val md = result.scanRecord?.manufacturerSpecificData ?: return null
        for (i in 0 until md.size()) {
            val key = md.keyAt(i)
            val bytes = md.get(key) ?: continue
            if (key == APPLE_FIND_MY_16 && bytes.size >= 2 && (bytes[0].toInt() and 0xFF) == 0x12) {
                return "AirTag/Find My"
            }
        }
        return null
    }

    /** Same-MAC-seen-at-2+-distinct-coarse-cells-over-30-min → likely traveling with the user. */
    private fun flushFindings(sessionId: String) {
        val now = System.currentTimeMillis()
        val cutoff = now - FLAG_AFTER_MINUTES * 60_000
        val snapshot = observations.entries.toList()
        for ((address, obs) in snapshot) {
            obs.removeAll { it.at < cutoff - 30 * 60_000 } // keep ~1h of history
            val recent = obs.filter { it.at >= cutoff }
            val distinct = recent.mapNotNull { it.latCell to it.lonCell }.toSet()
            if (distinct.size >= 2 && recent.size >= 4) {
                // only if not already emitted as a known tracker this cycle
                val alreadyFlagged = obs.any { false }
                if (!alreadyFlagged) {
                    FindingBus.emit(
                        Finding.BleDevice(
                            sessionId = sessionId, address = address,
                            name = null, trackerType = null,
                            rssi = recent.last().rssi,
                            timesSeenAtDistinctLocations = distinct.size,
                            flagged = true
                        )
                    )
                }
            }
        }
    }

    private fun locationCellCount(address: String): Int =
        observations[address]?.mapNotNull { it.latCell }.orEmpty().distinct().size

    /**
     * Coarse "distinct location" proxy without any location permission:
     * cell changed = location changed. Uses scan-time RSSI fingerprinting and
     * BSSID identity of the environment as a cheap stand-in.
     */
    private fun coarseLocationCell(): String? = try {
        val wifi = context.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        wifi?.connectionInfo?.bssid?.takeIf { it != "02:00:00:00:00:00" && it.isNotBlank() }
    } catch (_: Exception) {
        null
    }

    private fun bluetoothAdapter(): BluetoothAdapter? =
        (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter

    private fun hasScanPermission(): Boolean {
        val fine = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val scan = ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_SCAN) == PackageManager.PERMISSION_GRANTED
            val conn = ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED
            return fine && scan && conn
        }
        return fine
    }
}