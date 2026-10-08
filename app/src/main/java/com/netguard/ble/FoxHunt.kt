package com.netguard.ble

import android.Manifest
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import com.netguard.core.DeviceClassifier
import com.netguard.core.Finding
import com.netguard.core.FindingBus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * BLE Fox Hunt — "warmer/colder" proximity hunting for TRACKER-class devices
 * (AirTags, Tiles, SmartTags, Chipolos) plus any device the classifier is
 * alerting on (Flipper's 80:E1:26 OUI...). One RSSI tick per device per
 * second: each tick EMITS a Finding.BleDevice row so the Findings feed
 * becomes a hunt log, and the UI status line shows the strongest tracker:
 *
 *     🦊 HOT (~1.2m) AirTag/Find My F7:6C:A4:AE:2F:17 -58dBm
 *
 * The scan runs low-latency for [durationMs]; use the returned [Tick] list
 * to render the final proximity ranking.
 */
class FoxHunt(private val context: Context) {

    /**
     * @param rssiDbm   raw signal of this observation
     * @param estimated short human range estimate ("~1.2m", "3-5m", "far")
     */
    data class Tick(
        val address: String,
        val name: String?,
        val trackerType: String?,
        val rssiDbm: Int,
        val estimated: String
    )

    suspend fun hunt(sessionId: String, durationMs: Long = 30_000): List<Tick> =
        withContext(Dispatchers.Main) {
            val adapter = (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter
            val scanner = adapter?.bluetoothLeScanner
            if (adapter?.isEnabled != true || scanner == null || !hasPermission())
                return@withContext emptyList()

            // Latest observation per device (the ranking is by RSSI — newest wins)
            val ticks = ConcurrentHashMap<String, Tick>()
            val settings = ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .setReportDelay(0)
                .build()
            val filters = listOf<ScanFilter>() // all advertisements; we filter by classifier

            val callback = object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult) {
                    val device = result.device ?: return
                    val address = device.address ?: return
                    val record = result.scanRecord

                    val name = try { record?.deviceName ?: device.name } catch (_: SecurityException) { null }
                    val companies = mutableListOf<Int>()
                    var appleFindMy = false
                    record?.manufacturerSpecificData?.let { md ->
                        for (i in 0 until md.size()) {
                            val companyId = md.keyAt(i)
                            companies += companyId
                            if (companyId == BleDiscovery.COMPANY_APPLE) {
                                val data = md.get(companyId)
                                if (data != null && data.size >= 2 &&
                                    (data[0].toInt() and 0xFF) == BleDiscovery.APPLE_FIND_MY_TYPE_BYTE)
                                    appleFindMy = true
                            }
                        }
                    }
                    val uuids = record?.serviceUuids?.map { it.toString().lowercase() } ?: emptyList()

                    val trackerType = BleDiscovery.trackerTypeFor(name)
                        ?: if (appleFindMy) "AirTag/Find My" else null
                    val category = DeviceClassifier.categorize(
                        name = name, serviceUuids = uuids,
                        companies = companies, appleFindMyBeacon = appleFindMy, mac = address
                    )

                    // Fox hunt targets: known trackers OR alert-class BLE
                    // (Flipper = red row for the user too).
                    val isTarget = trackerType != null || DeviceClassifier.isAlertCategory(category)
                    if (!isTarget) return

                    val tick = Tick(address, name, trackerType, result.rssi, estimate(result.rssi))
                    ticks[address] = tick

                    // Every observation lands in the feed as one row — a hunt
                    // log you can replay later (findings timestamp = hunt time).
                    FindingBus.emit(
                        Finding.BleDevice(
                            sessionId = sessionId, address = address, name = name,
                            trackerType = trackerType, rssi = result.rssi,
                            category = category, flagged = true,
                            source = "foxhunt"
                        )
                    )
                }
            }

            try {
                scanner.startScan(filters, settings, callback)
            } catch (_: SecurityException) {
                return@withContext emptyList()
            }
            try {
                delay(durationMs)
            } finally {
                try { scanner.stopScan(callback) } catch (_: Exception) {}
            }
            ticks.values.sortedByDescending { it.rssiDbm }
        }

    // ---------------- continuous MAC-targeted hunt (tab mode) ----------------

    private val activeHuntJobs = java.util.concurrent.ConcurrentHashMap<String, kotlinx.coroutines.Job>()
    private val huntScope = kotlinx.coroutines.CoroutineScope(
        kotlinx.coroutines.SupervisorJob() + kotlinx.coroutines.Dispatchers.Main
    )

    /**
     * Continuous hunt for ONE MAC (AA:BB:CC:DD:EE:FF). Low-latency scan runs
     * until [stopHunt]; every advertisement from the target fires [onTick]
     * with the fresh RSSI, its warm/cold estimate, the running best (max)
     * RSSI and the observation count. Restarting the same MAC re-hunts.
     */
    fun startTargetedHunt(
        targetAddress: String,
        onTick: (Int, String, Int, Int) -> Unit
    ): String {
        val norm = targetAddress.trim().uppercase().replace('-', ':')
        val key = "hunt-" + norm
        stopHunt(key)
        var best = Int.MIN_VALUE
        var count = 0
        val adapter = (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter
        val callback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val dev = result.device ?: return
                if (!dev.address.equals(norm, ignoreCase = true)) return
                count++
                if (result.rssi > best || best == Int.MIN_VALUE) best = result.rssi
                onTick(result.rssi, estimate(result.rssi), best, count)
            }
        }
        val job = huntScope.launch {
            try {
                val leScanner = adapter?.bluetoothLeScanner
                if (leScanner == null || !hasPermission()) {
                    onTick(Int.MIN_VALUE, "NO-BLE (radio off or permission missing)", Int.MIN_VALUE, 0)
                    return@launch
                }
                val settings = ScanSettings.Builder()
                    .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                    .setReportDelay(0)
                    .build()
                // ScanFilter on the MAC: platform pre-filters to our target.
                val filter = ScanFilter.Builder().setDeviceAddress(norm).build()
                try { leScanner.startScan(listOf(filter), settings, callback) }
                catch (_: SecurityException) {
                    onTick(Int.MIN_VALUE, "NO-BLE (permission)", Int.MIN_VALUE, 0)
                    return@launch
                }
                // keep the coroutine alive until cancelled
                kotlinx.coroutines.awaitCancellation()
            } finally {
                try {
                    (adapter?.bluetoothLeScanner)?.stopScan(callback)
                } catch (_: Exception) {}
            }
        }
        activeHuntJobs[key] = job
        return key
    }

    /** Stops a targeted hunt (or all when the key is null). */
    fun stopHunt(key: String? = null) {
        if (key == null) {
            activeHuntJobs.values.forEach { it.cancel() }
            activeHuntJobs.clear()
        } else {
            activeHuntJobs.remove(key)?.cancel()
        }
    }

    val activeHuntKey: String? get() = activeHuntJobs.keys.firstOrNull()
    companion object {
        /**
         * RSSI → rough BLE range. Using the log-distance path-loss model with
         * a typical tracker beacon (~ -59 dBm @ 1m reference, n≈2.0-2.5
         * indoors). Coarse on purpose: labels, not meters of truth.
         */
        fun estimate(rssi: Int): String {
            if (rssi >= -55) return "HOT — right here (<1m)"
            val est = Math.pow(10.0, (-59.0 - rssi) / (10.0 * 2.2))
            return when {
                rssi >= -70 -> "WARM (~%.1fm)".format(est)
                rssi >= -85 -> "COOL (~%.0fm)".format(est)
                else -> "COLD (5m+)"
            }
        }
    }

    private fun hasPermission(): Boolean {
        val scan = ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_SCAN) ==
            PackageManager.PERMISSION_GRANTED
        val conn = ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) ==
            PackageManager.PERMISSION_GRANTED
        return scan && conn
    }
}