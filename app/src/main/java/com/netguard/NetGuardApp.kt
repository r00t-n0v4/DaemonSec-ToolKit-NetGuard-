package com.netguard

import android.app.Application
import com.netguard.core.Finding
import com.netguard.core.FindingBus
import com.netguard.core.findingTypeOf
import com.netguard.db.FindingEntity
import com.netguard.db.NetGuardDatabase
import kotlinx.coroutines.CoroutineScope
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

        // Single DB writer: everything every module emits lands here, stamped
        // with wall-clock time. Modules never touch Room directly.
        appScope.launch {
            FindingBus.events.collect { finding ->
                database.findingDao().insert(
                    FindingEntity(
                        sessionId = finding.sessionId,
                        type = findingTypeOf(finding),
                        payloadJson = payloadJson.encodeToString(Finding.serializer(), finding),
                        flagged = finding.flagged,
                        timestamp = System.currentTimeMillis()
                    )
                )
            }
        }
    }
}