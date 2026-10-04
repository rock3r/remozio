package dev.remozio.android.enrollment

import androidx.annotation.WorkerThread
import dev.remozio.android.biometrics.loadBiometricKey
import dev.remozio.android.decisions.loadDecisionKey
import dev.remozio.android.transport.AndroidTransportIdentities
import dev.remozio.phone.enrollment.PhoneEnrollment

/** Checks existing keys only. Missing or invalidated keys are never silently replaced. */
@WorkerThread
internal fun validatePairingKeys(enrollment: PhoneEnrollment) {
    AndroidTransportIdentities.load(enrollment.transportKey.alias, enrollment.transportKey.publicKey.copyBytes()).use {
        check(!it.requiresUnlockedDevice)
        loadDecisionKey(enrollment.decisionKey)
        loadBiometricKey(enrollment.biometricKey)
    }
}
