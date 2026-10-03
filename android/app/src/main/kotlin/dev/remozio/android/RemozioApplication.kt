package dev.remozio.android

import android.app.Application
import dev.remozio.android.audit.androidStoredAuditReader
import dev.remozio.android.enrollment.AndroidEnrollmentStore
import dev.remozio.android.enrollment.StoredMacReader
import dev.remozio.android.updates.androidUpdateHost
import dev.remozio.android.requests.StoredCommandConnections
import dev.remozio.android.requests.androidCommandConnection
import dev.remozio.android.requests.commandRequestLimits
import dev.remozio.phone.requests.CommandMemoryBudget
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.sync.Mutex

class RemozioApplication : Application() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val enrollmentAccess = Mutex()
    internal val macs by lazy {
        StoredMacReader({ AndroidEnrollmentStore.openExisting(this, maximumRecords = 1024, maximumPlaintextBytes = 16_777_216) }, enrollmentAccess = enrollmentAccess)
    }
    private val commandMemory = CommandMemoryBudget(8_388_608, 262_144)
    internal val commands by lazy {
        StoredCommandConnections(
            { AndroidEnrollmentStore.openExisting(this, maximumRecords = 1024, maximumPlaintextBytes = 16_777_216) },
            { androidCommandConnection(this, it, commandRequestLimits(), commandMemory) }, enrollmentAccess,
        )
    }
    internal val audits by lazy { androidStoredAuditReader(this, enrollmentAccess) }
    internal val updates by lazy { androidUpdateHost(this, scope) }
}
