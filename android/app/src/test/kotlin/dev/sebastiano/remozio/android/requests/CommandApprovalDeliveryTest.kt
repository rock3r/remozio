package dev.sebastiano.remozio.android.requests

import dev.remozio.protocol.ApprovalMessage
import dev.sebastiano.remozio.android.R
import dev.sebastiano.remozio.android.biometrics.BiometricRecoveryReason
import dev.remozio.protocol.ApprovalMessageType
import dev.remozio.protocol.DecisionRefusalFrame
import dev.remozio.protocol.PhoneRepairNoticeFrame
import dev.remozio.protocol.RequestDeliveryResult
import dev.remozio.protocol.SigningPurpose
import java.io.IOException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.test.fail

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

    @Test fun retryUsesAFreshTicketAndTheSameRetainedMessage() {
        val state = CommandApprovalViewState()
        state.stage = CommandActionStage.UNCERTAIN
        state.retained = approval
        val previous = state.attempts.begin()
        var deliveries = 0

        state.retry(foreground = true, connected = { true }) { ticket, message ->
            assertTrue(state.attempts.owns(ticket), "Retry must use a current ticket")
            assertFalse(state.attempts.owns(previous), "Retry must invalidate the previous ticket")
            assertSame(approval, message, "Retry must use the retained message")
            deliveries++
        }
        assertEquals(1, deliveries)
    }

    @Test fun ineligibleRetryLeavesTheCurrentTicketAndMessageInPlace() {
        fun assertBlocked(foreground: Boolean = true, connected: Boolean = true,
                          stage: CommandActionStage = CommandActionStage.UNCERTAIN, message: ApprovalMessage? = approval) {
            val state = CommandApprovalViewState()
            state.stage = stage
            state.retained = message
            val ticket = state.attempts.begin()

            state.retry(foreground, { connected }) { _, _ -> fail("An ineligible retry reached delivery") }
            assertTrue(state.attempts.owns(ticket), "An ineligible retry replaced the ticket")
            assertSame(message, state.retained)
            assertEquals(stage, state.stage)
        }

        assertBlocked(foreground = false)
        assertBlocked(connected = false)
        assertBlocked(stage = CommandActionStage.AWAITING)
        assertBlocked(message = null)
    }

    @Test fun staleTicketCannotEnterDeliveryOrReplaceTheCurrentChoice() = runBlocking<Unit> {
        val state = CommandApprovalViewState()
        val stale = state.attempts.begin()
        val current = state.attempts.begin()
        state.stage = CommandActionStage.UNCERTAIN
        state.retained = decline

        state.deliver(stale, approval) { fail("A stale ticket reached the sender") }
        assertTrue(state.attempts.owns(current))
        assertSame(decline, state.retained)
        assertEquals(CommandActionStage.UNCERTAIN, state.stage)
    }

    @Test fun lateWriteCompletionCannotReplaceTheStageOfANewerTicket() = runBlocking<Unit> {
        val state = CommandApprovalViewState()
        val first = state.attempts.begin()
        state.deliver(first, approval) {
            state.attempts.begin()
            state.stage = CommandActionStage.PREPARING
        }
        assertEquals(CommandActionStage.PREPARING, state.stage, "A stale write replaced the current stage")
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

    @Test fun verifiedRefusalInsideTheWriteClearsRetryAndSurvivesCompletion() = runBlocking<Unit> {
        val state = CommandApprovalViewState()
        val reason = DecisionRefusalFrame.Reason.REQUEST_CHANGED
        val ticket = state.attempts.begin()
        state.deliver(ticket, approval) { state.refuse(ticket, approval, reason) }
        assertEquals(CommandActionStage.REFUSED, state.stage)
        assertEquals(reason, state.refusal)
        assertNull(state.retained)
    }

    @Test fun lateRefusalForAnOlderAttemptCannotClearTheNewChoice() = runBlocking<Unit> {
        val state = CommandApprovalViewState()
        val first = state.attempts.begin()
        state.deliver(first, approval) {}
        val next = state.attempts.begin()
        state.deliver(next, approval) {}
        state.refuse(first, approval, DecisionRefusalFrame.Reason.ACTION_UNAVAILABLE)
        assertEquals(CommandActionStage.AWAITING, state.stage)
        assertSame(approval, state.retained)
        state.refuse(next, approval, DecisionRefusalFrame.Reason.ACTION_UNAVAILABLE)
        assertEquals(CommandActionStage.REFUSED, state.stage)
    }

    @Test fun liveCapabilityAdvertisingRespectsFrameBudgetAndLeavesInspectionUnchanged() {
        val original = commandInspectionCapabilities()
        val expected = setOf(RequestDeliveryResult.CAPABILITY, DecisionRefusalFrame.CAPABILITY, PhoneRepairNoticeFrame.CAPABILITY)
        assertEquals(original.map { it.schemaVersion }, liveCommandCapabilities(65536).map { it.schemaVersion })
        assertEquals(setOf(expected), liveCommandCapabilities(65536).map { it.features }.toSet())
        assertEquals(setOf(setOf(RequestDeliveryResult.CAPABILITY)), liveCommandCapabilities(128).map { it.features }.toSet())
        assertEquals(setOf(emptySet<ULong>()), commandInspectionCapabilities().map { it.features }.toSet())
    }

    @Test fun anInvalidatedAttemptCannotPublishALateResult() = runBlocking<Unit> {
        val state = CommandApprovalViewState()
        state.deliver(state.attempts.begin(), approval) { state.clear() }
        assertEquals(CommandActionStage.IDLE, state.stage)
        assertNull(state.retained)
    }
}
