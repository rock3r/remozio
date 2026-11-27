package dev.sebastiano.remozio.android.enrollment

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

internal val PairingPhase.displaysComparison: Boolean
    get() = this == PairingPhase.COMPARING || this == PairingPhase.PREPARING || this == PairingPhase.BIOMETRIC

internal fun requiresPairingWindowProtection(phase: PairingPhase, preview: Boolean): Boolean =
    !preview && phase.displaysComparison

/** One instance belongs to one comparison window. A disposed window cannot authorize actions. */
internal class PairingWindowProtection {
    enum class State { CHECKING, READY, UNAVAILABLE }

    var state by mutableStateOf(State.CHECKING)
        private set

    fun protect(secure: Boolean, hideOverlays: () -> Unit) {
        if (state != State.CHECKING) return
        state = if (!secure) State.UNAVAILABLE else try {
            hideOverlays()
            State.READY
        } catch (_: SecurityException) {
            State.UNAVAILABLE
        }
    }

    fun revoke() {
        state = State.UNAVAILABLE
    }

    fun canMatch(phase: PairingPhase, hasCode: Boolean): Boolean =
        state == State.READY && phase == PairingPhase.COMPARING && hasCode

    fun <Signer : Any, Prompt> startBiometrics(
        phase: PairingPhase, hasCode: Boolean, signer: Signer?, start: (Signer) -> Prompt,
    ): Prompt? = if (state == State.READY && phase == PairingPhase.BIOMETRIC && hasCode) signer?.let(start) else null
}
