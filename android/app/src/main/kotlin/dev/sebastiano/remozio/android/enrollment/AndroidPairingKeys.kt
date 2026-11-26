package dev.sebastiano.remozio.android.enrollment

import android.content.Context
import androidx.annotation.WorkerThread
import dev.sebastiano.remozio.android.biometrics.loadBiometricKey
import dev.sebastiano.remozio.android.decisions.loadDecisionKey
import dev.sebastiano.remozio.android.transport.AndroidTransportIdentities
import dev.remozio.phone.enrollment.EnrollmentKeyReference
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.PhoneEnrollment
import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.P256SignatureEncoding
import dev.remozio.protocol.PairingProofPurpose
import dev.remozio.protocol.PairingTranscript
import java.security.PrivateKey
import java.security.Signature

/** Checks existing keys only. Missing or invalidated keys are never silently replaced. */
@WorkerThread
internal fun validatePairingKeys(context: Context, enrollment: PhoneEnrollment) {
    AndroidTransportIdentities.load(context, enrollment.transportKey).use {
        check(!it.requiresUnlockedDevice)
        loadDecisionKey(enrollment.decisionKey)
        loadBiometricKey(enrollment.biometricKey)
    }
}

/** Signs only the confirmed transcript under the exact PREPARED enrollment's decision key. */
@WorkerThread
internal fun signPairingDecisionProof(
    access: PreparedPairingAccess,
    transcript: PairingTranscript,
    biometricProof: ByteArray,
    deadline: PairingDeadline,
    now: () -> ElapsedInstant,
    loadKey: (EnrollmentKeyReference) -> PrivateKey = { loadDecisionKey(it).key },
): ByteArray {
    val record = access.record
    require(record.phase == EnrollmentPhase.PREPARED && deadline.matches(transcript))
    require(checkNotNull(record.pairing).transcript.encode().contentEquals(transcript.encode()))
    val decision = record.enrollment.decisionKey
    val biometric = record.enrollment.biometricKey
    require(transcript.decisionKey.keyID == decision.keyID && transcript.decisionKey.publicKey == decision.publicKey)
    require(transcript.biometricKey.keyID == biometric.keyID && transcript.biometricKey.publicKey == biometric.publicKey)
    require(transcript.verify(biometricProof, biometric.publicKey.copyBytes(), PairingProofPurpose.PHONE_BIOMETRIC))

    check(access.lease.isCurrent())
    deadline.requireOpen(now())
    val signer = Signature.getInstance("SHA256withECDSA").apply { initSign(loadKey(decision)) }
    check(access.lease.isCurrent())
    deadline.requireOpen(now())
    signer.update(transcript.signingInput(PairingProofPurpose.PHONE_DECISION))
    val proof = P256SignatureEncoding.fromDer(signer.sign())
    check(access.lease.isCurrent())
    deadline.requireOpen(now())
    check(transcript.verify(proof, decision.publicKey.copyBytes(), PairingProofPurpose.PHONE_DECISION))
    return proof
}
