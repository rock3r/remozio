package dev.sebastiano.remozio.android.requests

import dev.remozio.protocol.ApprovalMessage
import dev.sebastiano.remozio.android.R
import dev.sebastiano.remozio.android.biometrics.BiometricRecoveryReason
import dev.remozio.protocol.ApprovalMessageType
import dev.remozio.protocol.SigningPurpose
import java.io.IOException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertSame

class CommandApprovalDeliveryTest {
    private val approval = ApprovalMessage(1u, ApprovalMessageType.DECISION,
        SigningPurpose.BIOMETRIC_AUTHORIZATION, byteArrayOf(1), ByteArray(64))
    private val decline = ApprovalMessage(1u, ApprovalMessageType.DECISION,
        SigningPurpose.CANCELLATION, byteArrayOf(2), ByteArray(64))

    @Test fun firstFailureBeforeWriteReleasesTheChoice() = runBlocking<Unit> {
        val state = CommandApprovalViewState()
        state.deliver(state.attempts.begin(), approval) { throw CommandDecisionNotSent() }
        assertEquals(CommandActionStage.UNAVAILABLE, state.stage)
        assertNull(state.retained)
        state.deliver(state.attempts.begin(), decline) { assertSame(decline, it) }
        assertEquals(CommandActionStage.AWAITING, state.stage)
        assertSame(decline, state.retained)
    }

    @Test fun aRetryThatDoesNotStartKeepsTheEarlierUncertainty() = runBlocking<Unit> {
        val state = CommandApprovalViewState()
        state.deliver(state.attempts.begin(), approval) { throw IOException("Writer failed") }
        assertEquals(CommandActionStage.UNCERTAIN, state.stage)
        assertSame(approval, state.retained)
        state.deliver(state.attempts.begin(), approval) { throw CommandDecisionNotSent() }
        assertEquals(CommandActionStage.UNCERTAIN, state.stage)
        assertSame(approval, state.retained)
    }

    @Test fun cancellationRetainsTheOriginalCarrierAndPropagates() = runBlocking<Unit> {
        val state = CommandApprovalViewState()
        assertFailsWith<CancellationException> {
            state.deliver(state.attempts.begin(), approval) { throw CancellationException() }
        }
        assertEquals(CommandActionStage.UNCERTAIN, state.stage)
        assertSame(approval, state.retained)
    }

    @Test fun onlyTheCurrentAttemptShowsTheAppropriateRecoveryMessage() {
        val state = CommandApprovalViewState()
        val previous = state.attempts.begin()
        val current = state.attempts.begin()
        state.requireBiometricRecovery(previous, BiometricRecoveryReason.LEGACY_POLICY)
        assertNull(state.biometricRecovery)
        state.requireBiometricRecovery(current, BiometricRecoveryReason.BIOMETRIC_CHANGED)
        assertEquals(R.string.command_biometric_changed_recovery, biometricRecoveryMessage(checkNotNull(state.biometricRecovery)))
        assertEquals(R.string.command_biometric_legacy_recovery, biometricRecoveryMessage(BiometricRecoveryReason.LEGACY_POLICY))
    }

    @Test fun anInvalidatedAttemptCannotPublishALateResult() = runBlocking<Unit> {
        val state = CommandApprovalViewState()
        state.deliver(state.attempts.begin(), approval) { state.clear() }
        assertEquals(CommandActionStage.IDLE, state.stage)
        assertNull(state.retained)
    }
}
