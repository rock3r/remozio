package dev.remozio.android.requests

import dev.remozio.phone.requests.CommandRequestSession
import dev.remozio.phone.requests.CommandRequestSnapshot
import dev.remozio.phone.requests.ElapsedInstant

import android.os.SystemClock
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.produceState
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** Sessions and this epoch live only in this process; elapsedRealtime includes deep sleep. */
internal object RequestElapsedClock {
    fun now() = ElapsedInstant(0, SystemClock.elapsedRealtime().toULong())
}

/** Read-only integration. The caller owns the session and supplies trusted display names. */
@Composable
internal fun CommandRequestInspection(
    session: CommandRequestSession,
    macName: String,
    accountName: String,
    onDismiss: () -> Unit,
) {
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    key(session, lifecycle) {
        val snapshot by produceState<CommandRequestSnapshot?>(null, session, lifecycle) {
            lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
                try {
                    launch {
                        combine(session.revisions, session.closed) { _, _ -> session.snapshot(RequestElapsedClock.now()) }
                            .collect { value = it }
                    }
                    while (isActive) {
                        value = session.snapshot(RequestElapsedClock.now())
                        delay(1000)
                    }
                } finally {
                    // Stop retaining a UI capture while the host is not visible.
                    value = null
                }
            }
        }
        snapshot?.let {
            if (it.closed) {
                LaunchedEffect(session) { onDismiss() }
                return@let
            }
            CommandInspection(it.capture, macName, accountName, onDismiss, status = it.status, requestKey = session)
        }
    }
}
