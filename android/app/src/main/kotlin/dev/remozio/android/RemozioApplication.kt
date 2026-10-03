package dev.remozio.android

import android.app.Application
import dev.remozio.android.updates.androidUpdateHost
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

class RemozioApplication : Application() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    internal val updates by lazy { androidUpdateHost(this, scope) }
}
