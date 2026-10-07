package com.netguard.ble

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothProfile
import android.content.Context
import com.netguard.core.Finding
import com.netguard.core.FindingBus
import com.netguard.core.GattService
import com.netguard.core.GattChar
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID
import kotlin.coroutines.resume

/**
 * GATT profiling (Module 5, the part beyond tracker detection): connects to a
 * peripheral, walks the service/characteristic tree, and flags writable
 * characteristics — the classic smart-lock/vulnerable-gadget pattern is a
 * write-capable characteristic with no auth/encryption gate.
 *
 * Android can't tell you "requires auth" directly, so the heuristic is:
 * writable && !(PERMISSION_WRITE_ENCRYPTED) → "writes unencrypted" (some
 * stacks set both bits; treat it as a hint for manual follow-up, not gospel).
 */
object GattProbe {

    private val SERVICE_NAMES = mapOf(
        "0000180a-0000-1000-8000-00805f9b34fb" to "Device Information",
        "0000180f-0000-1000-8000-00805f9b34fb" to "Battery",
        "00001800-0000-1000-8000-00805f9b34fb" to "Generic Access",
        "00001801-0000-1000-8000-00805f9b34fb" to "GATT",
        "0000fe2c-0000-1000-8000-00805f9b34fb" to "Samsung SmartTag",
        "0000fd6f-0000-1000-8000-00805f9b34fb" to "Chipolo"
    )

    private const val PROPERTY_READ = 0x02
    private const val PROPERTY_WRITE_NO_RSP = 0x04
    private const val PROPERTY_WRITE = 0x08
    private const val PROPERTY_NOTIFY = 0x10
    private const val PROPERTY_INDICATE = 0x20
    private const val PERMISSION_WRITE = 0x10
    private const val PERMISSION_WRITE_ENCRYPTED = 0x20

    suspend fun probe(
        context: Context,
        sessionId: String,
        address: String,
        timeoutMs: Long = 15_000
    ): Finding.GattDevice? {
        val adapter = (context.getSystemService(Context.BLUETOOTH_SERVICE) as? android.bluetooth.BluetoothManager)?.adapter
            ?: return null
        val device: BluetoothDevice = try {
            adapter.getRemoteDevice(address)
        } catch (_: Exception) {
            return null
        }

        val gatt = withTimeoutOrNull(timeoutMs) {
            suspendCancellableCoroutine<BluetoothGatt?> { cont ->
                val callback = object : BluetoothGattCallback() {
                    override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
                        when (newState) {
                            BluetoothProfile.STATE_CONNECTED -> g.discoverServices()
                            BluetoothProfile.STATE_DISCONNECTED -> {
                                if (cont.isActive) cont.resume(g)
                            }
                        }
                    }

                    override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
                        if (cont.isActive) cont.resume(g)
                    }
                }
                val g: BluetoothGatt? = try {
                    device.connectGatt(context, false, callback)
                } catch (_: SecurityException) {
                    cont.resume(null)
                    return@suspendCancellableCoroutine
                }
                cont.invokeOnCancellation { try { g?.disconnect(); g?.close() } catch (_: Exception) {} }
            }
        } ?: return null

        val services: List<BluetoothGattService> = try { gatt.services } catch (_: SecurityException) { emptyList() }
        val name = try { device.name } catch (_: SecurityException) { null }

        var writableCount = 0
        var unencryptedWrites = 0
        val serviceModels = services.map { svc ->
            val chars = svc.characteristics.map { c ->
                val p = c.properties
                val props = buildList {
                    if (p and PROPERTY_READ != 0) add("read")
                    if (p and PROPERTY_WRITE != 0) add("write")
                    if (p and PROPERTY_WRITE_NO_RSP != 0) add("writeNr")
                    if (p and PROPERTY_NOTIFY != 0) add("notify")
                    if (p and PROPERTY_INDICATE != 0) add("indicate")
                }.joinToString("|")
                val writable = (p and (PROPERTY_WRITE or PROPERTY_WRITE_NO_RSP)) != 0
                val unenc = try {
                    writable && (c.permissions and PERMISSION_WRITE) != 0 &&
                        (c.permissions and PERMISSION_WRITE_ENCRYPTED) == 0
                } catch (_: Exception) { false }
                if (writable) writableCount++
                if (unenc) unencryptedWrites++
                GattCharModel(uuid = c.uuid.toString().lowercase(), properties = props, writable = writable, writesUnencrypted = unenc)
            }
            GattServiceModel(
                uuid = svc.uuid.toString().lowercase(),
                name = SERVICE_NAMES[svc.uuid.toString().lowercase()],
                characteristics = chars
            )
        }

        try { gatt.disconnect(); gatt.close() } catch (_: Exception) {}

        val finding = Finding.GattDevice(
            sessionId = sessionId,
            address = address,
            name = name,
            services = serviceModels.map { s ->
                GattService(
                    uuid = s.uuid,
                    characteristics = s.characteristics.map { c ->
                        GattChar(uuid = c.uuid, properties = c.properties, writable = c.writable, writesUnencrypted = c.writesUnencrypted)
                    }
                )
            },
            writableUnencrypted = unencryptedWrites,
            flagged = unencryptedWrites > 0
        )
        FindingBus.emit(finding)
        return finding
    }

    private data class GattServiceModel(
        val uuid: String,
        val name: String?,
        val characteristics: List<GattCharModel>
    )

    private data class GattCharModel(
        val uuid: String,
        val properties: String,
        val writable: Boolean,
        val writesUnencrypted: Boolean
    )

    /** Renders a GattDevice finding to readable text for the UI/report. */
    fun summarize(f: Finding.GattDevice): String {
        val sb = StringBuilder()
        sb.append("${f.name ?: f.address} · ${f.services.size} services")
        if (f.writableUnencrypted > 0) sb.append(" · ${f.writableUnencrypted} writable-unencrypted chars ⚠")
        f.services.forEach { svc ->
            val label = SERVICE_NAMES[svc.uuid] ?: svc.uuid
            sb.append("\n  $label: ${svc.characteristics.size} chars")
        }
        return sb.toString()
    }
}