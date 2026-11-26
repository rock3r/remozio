package dev.sebastiano.remozio.android.enrollment

import android.content.Context
import androidx.annotation.WorkerThread
import dev.sebastiano.remozio.android.biometrics.loadBiometricKey
import dev.sebastiano.remozio.android.decisions.loadDecisionKey
import dev.sebastiano.remozio.android.transport.AndroidTransportIdentities
import dev.remozio.phone.enrollment.PhoneEnrollment

/** Checks existing keys only. Missing or invalidated keys are never silently replaced. */
@WorkerThread
internal fun validatePairingKeys(context: Context, enrollment: PhoneEnrollment) {
    AndroidTransportIdentities.load(context, enrollment.transportKey).use {
        check(!it.requiresUnlockedDevice)
        loadDecisionKey(enrollment.decisionKey)
        loadBiometricKey(enrollment.biometricKey)
    }
}
