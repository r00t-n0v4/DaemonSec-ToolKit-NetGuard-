package com.netguard

import android.app.Application
import com.netguard.core.Finding
import com.netguard.core.FindingBus
import com.netguard.core.findingTypeOf
import com.netguard.db.FindingEntity
import com.netguard.db.NetGuardDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json

class NetGuardApp : Application() {

    lateinit var database: NetGuardDatabase
        private set

    /** Long-lived scope every module borrows for background work. */
    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private val payloadJson = Json { ignoreUnknownKeys = true; encodeDefaults = false }

    override fun onCreate() {
        super.onCreate()
        database = NetGuardDatabase.getInstance(this)

        // Track the WiFi Network for socket pinning (probes/HTTP must ride
        // wlan0, not the default-network choice — cellular can win).
        com.netguard.core.WifiPinner.refresh(this)

        // Single DB writer: everything every module emits lands here, stamped
        // with wall-clock time. Modules never touch Room directly.
        // Per-row try + retry: a single failed insert must NEVER kill the
        // collector — an exception inside collect{} cancels the coroutine
        // silently and every later scan writes nothing to the DB (observed
        // as a "dead" Findings tab after BLE→OSINT→WiFi in one session).
        appScope.launch {
            FindingBus.events.collect { finding ->
                val entity = FindingEntity(
                    sessionId = finding.sessionId,
                    type = findingTypeOf(finding),
                    payloadJson = payloadJson.encodeToString(Finding.serializer(), finding),
                    flagged = finding.flagged,
                    timestamp = System.currentTimeMillis()
                )
                var attempt = 0
                while (true) {
                    try {
                        database.findingDao().insert(entity)
                        break
                    } catch (e: Exception) {
                        attempt++
                        android.util.Log.e("NetGuardDB",
                            "insert failed (attempt $attempt) type=${entity.type}: ${e.message?.take(120)}")
                        if (attempt >= 3) break // drop the row, keep the bus alive
                        delay(50)
                    }
                }
            }
        }
    }
}