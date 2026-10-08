package com.netguard.ble

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import com.netguard.core.DeviceClassifier
import com.netguard.core.Finding
import com.netguard.core.FindingBus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * Nearby-BLE discovery with classification via the shared DeviceClassifier
 * (same buckets as WiFi APs and LAN hosts, so all discovery surfaces agree).
 * Captures manufacturer-specific data — company IDs are what classify
 * nameless iPhones/AirPods/Pixels/Surfaces — plus Apple Find My beacon
 * detection for tracker flagging.
 */
class BleDiscovery(private val context: Context) {

    data class Entry(
        val address: String,
        val name: String?,
        val rssi: Int,
        val category: String,
        val trackerType: String?,
        val serviceUuids: List<String>
    )

    companion object {
        /** Display order + red styles come from the shared classifier. */
        val CATEGORY_ORDER get() = DeviceClassifier.CATEGORY_ORDER

        internal const val COMPANY_APPLE = 0x004C
        internal const val APPLE_FIND_MY_TYPE_BYTE = 0x12

        fun trackerTypeFor(name: String?): String? {
            val n = name?.lowercase() ?: ""
            return when {
                n.contains("airtag") -> "AirTag/Find My"
                n.contains("tile") -> "Tile"
                n.contains("smarttag") -> "Samsung SmartTag"
                n.contains("chipolo") -> "Chipolo"
                else -> null
            }
        }
    }

    /**
     * Low-latency scan for [durationMs]; emits one BleDevice finding per NEW
     * device as it appears (live feed), returns the final deduped list.
     */
    suspend fun scan(sessionId: String, durationMs: Long = 15_000): List<Entry> =
        withContext(Dispatchers.Main) {
            val adapter = (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter
            val scanner = adapter?.bluetoothLeScanner
            if (adapter?.isEnabled != true || scanner == null || !hasPermission()) return@withContext emptyList()

            val found = ConcurrentHashMap<String, Entry>()
            val settings = ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .setReportDelay(0)
                .build()

            val callback = object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult) {
                    val device = result.device ?: return
                    val address = device.address ?: return
                    val scanRecord = result.scanRecord
                    val uuids = scanRecord?.serviceUuids?.map { it.toString().lowercase() } ?: emptyList()
                    val name = try {
                        scanRecord?.deviceName ?: device.name
                    } catch (_: SecurityException) {
                        null
                    }
                    val rssi = result.rssi

                    // Company IDs from manufacturer-specific data (classification core)
                    val companies = mutableListOf<Int>()
                    var appleFindMy = false
                    scanRecord?.manufacturerSpecificData?.let { md ->
                        for (i in 0 until md.size()) {
                            val companyId = md.keyAt(i)
                            companies += companyId
                            if (companyId == COMPANY_APPLE) {
                                val data = md.get(companyId)
                                // Find My/continuity: type byte 0x12 = offline finding
                                if (data != null && data.size >= 2 && (data[0].toInt() and 0xFF) == APPLE_FIND_MY_TYPE_BYTE) {
                                    appleFindMy = true
                                }
                            }
                        }
                    }

                    val trackerType = trackerTypeFor(name) ?: if (appleFindMy) "AirTag/Find My" else null
                    val category = DeviceClassifier.categorize(
                        name = name,
                        serviceUuids = uuids,
                        companies = companies,
                        appleFindMyBeacon = appleFindMy,
                        mac = address
                    )

                    val isNew = !found.containsKey(address)
                    found[address] = Entry(address, name, rssi, category, trackerType, uuids)

                    if (isNew) {
                        FindingBus.emit(
                            Finding.BleDevice(
                                sessionId = sessionId,
                                address = address,
                                name = name,
                                trackerType = trackerType,
                                rssi = rssi,
                                category = category,
                                flagged = trackerType != null ||
                                    DeviceClassifier.isAlertCategory(category)
                            )
                        )
                    }
                }
            }

            try {
                scanner.startScan(null, settings, callback)
            } catch (_: SecurityException) {
                return@withContext emptyList()
            }
            try {
                delay(durationMs)
            } finally {
                try { scanner.stopScan(callback) } catch (_: Exception) {}
            }
            found.values.sortedByDescending { it.rssi }
        }

    private fun hasPermission(): Boolean {
        val fine = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED
        val scan = ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_SCAN) ==
            PackageManager.PERMISSION_GRANTED
        val conn = ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) ==
            PackageManager.PERMISSION_GRANTED
        return fine && scan && conn
    }
}