package dev.remozio.android

import android.app.Application
import dev.remozio.android.audit.androidStoredAuditReader
import dev.remozio.android.enrollment.AndroidEnrollmentStore
import dev.remozio.android.enrollment.StoredMacReader
import dev.remozio.android.updates.androidUpdateHost
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

class RemozioApplication : Application() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    internal val macs by lazy {
        StoredMacReader({ AndroidEnrollmentStore.openExisting(this, maximumRecords = 1024, maximumPlaintextBytes = 16_777_216) })
    }
    internal val audits by lazy { androidStoredAuditReader(this) }
    internal val updates by lazy { androidUpdateHost(this, scope) }
}
