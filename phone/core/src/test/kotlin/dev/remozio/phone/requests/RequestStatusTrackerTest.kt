package dev.remozio.phone.requests

import dev.remozio.protocol.*
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class RequestStatusTrackerTest {
    private val limits = CborLimits(2048, 8, 128)
    private val key = newKey()
    private val id = ByteArray(16) { 1 }
    private val phone = ByteArray(16) { 2 }
    private val request = IssuedRequestPayload(RequestContract(RequestKind.COMMAND, 1u, 1u), id, id, id,
        ByteArray(32) { 3 }, emptySet(), 1u, 10u, byteArrayOf(0xa0.toByte()),
        listOf(CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)), limits, limits)
    private fun tracker(publicKey: ByteArray = publicKey(key)) = RequestStatusTracker(request, publicKey, limits, limits, limits)
    private fun time(ms: ULong, epoch: Long = 1) = ElapsedInstant(epoch, ms)
    private fun status(revision: ULong = 1u, age: ULong = 1000u, phase: RequestPhase = RequestPhase.QUEUED,
        reason: RequestStatusReason = RequestStatusReason.NONE, remaining: ULong? = if (phase in listOf(RequestPhase.QUEUED, RequestPhase.PRESENTED)) 9000u else null,
        estimate: ULong? = 60_000u, late: Boolean = false, terminal: ULong? = if (phase.isTerminal) age else null,
        deciding: ByteArray? = if (phase in listOf(RequestPhase.QUEUED, RequestPhase.PRESENTED)) null else phone,
        observation: ByteArray = id) = RequestStatusPayload(request.macID, request.accountID, request.requestID,
            request.requestDigest(limits, limits), request.challenge, revision, phase, reason, observation, age,
            remaining, estimate, late, terminal, deciding)
    private fun observe(tracker: RequestStatusTracker, status: RequestStatusPayload, at: ULong = 100u, epoch: Long = 1): StatusAcceptance {
        val bytes = status.encode(limits)
        return tracker.observe(bytes, sign(bytes), time(at, epoch))
    }
    private fun rejected(reason: StatusRejection, block: () -> Unit) = assertEquals(reason, assertFailsWith<StatusTrackingException>(block = block).reason)

    @Test fun rejectsWrongKeysSignaturesDomainsAndEachRequestBinding() {
        val tracker = tracker()
        val body = status().encode(limits)
        rejected(StatusRejection.INVALID_SIGNATURE) { tracker.observe(body, sign(body, newKey()), time(100u)) }
        rejected(StatusRejection.INVALID_SIGNATURE) { tracker.observe(body, ByteArray(64), time(100u)) }
        rejected(StatusRejection.INVALID_SIGNATURE) { tracker.observe(body, ByteArray(63), time(100u)) }
        rejected(StatusRejection.INVALID_SIGNATURE) { tracker.observe(body, sign(body, type = ApprovalMessageType.REQUEST, purpose = SigningPurpose.ISSUED_REQUEST), time(100u)) }
        val original = (DeterministicCbor.decode(body, limits) as CborValue.Fields).values
        for (field in 1uL..5uL) {
            val changed = original.toMutableMap()
            val bytes = (changed.getValue(field) as CborValue.Bytes).copyBytes().apply { this[0] = (this[0].toInt() xor 1).toByte() }
            changed[field] = CborValue.Bytes(bytes)
            val encoded = DeterministicCbor.encode(CborValue.Fields(changed), limits)
            rejected(StatusRejection.WRONG_REQUEST) { tracker.observe(encoded, sign(encoded), time(100u)) }
        }
        assertNull(tracker.snapshot(time(100u)))
        assertEquals(StatusAcceptance.APPLIED, observe(tracker, status()))
    }

    @Test fun duplicatesAndOldRevisionsCannotReanchorCountdowns() {
        val tracker = tracker()
        val first = status(revision = 2u)
        assertEquals(StatusAcceptance.APPLIED, observe(tracker, first))
        assertEquals(StatusAcceptance.DUPLICATE, observe(tracker, first, at = 1100u))
        assertEquals(StatusAcceptance.OLDER, observe(tracker, status(), at = 2100u))
        rejected(StatusRejection.REVISION_CONFLICT) { observe(tracker, status(revision = 2u, age = 1001u), at = 2100u) }
        val snapshot = assertNotNull(tracker.snapshot(time(3100u)))
        assertEquals(4000uL, snapshot.timing.ageLowerBoundMs)
        assertEquals(6000uL, snapshot.timing.authorizationRemainingUpperBoundMs)
        assertEquals(2uL, snapshot.status.revision)
    }

    @Test fun delayedUpdatesAndSleepKeepAgeAndCountdownMonotonic() {
        val tracker = tracker()
        observe(tracker, status())
        assertEquals(6000uL, tracker.snapshot(time(5100u))!!.timing.ageLowerBoundMs)
        observe(tracker, status(revision = 2u, age = 2000u, remaining = 8000u), at = 5100u)
        val projected = tracker.snapshot(time(61_100u))!!
        assertEquals(62_000uL, projected.timing.ageLowerBoundMs)
        assertEquals(0uL, projected.timing.authorizationRemainingUpperBoundMs)
        assertEquals(0uL, projected.timing.estimatedTargetRemainingMs)
        assertFalse(projected.status.phase.isTerminal)
        assertTrue(projected.timing.deliveryDelayUnknown)
    }

    @Test fun clockChangesPreserveBoundsAndReportUncertainty() {
        val tracker = tracker()
        observe(tracker, status())
        val before = tracker.snapshot(time(1100u))!!.timing
        val regressed = tracker.snapshot(time(1000u))!!.timing
        assertTrue(regressed.clockUncertain)
        assertEquals(before.ageLowerBoundMs, regressed.ageLowerBoundMs)
        assertEquals(before.authorizationRemainingUpperBoundMs, regressed.authorizationRemainingUpperBoundMs)
        assertTrue(tracker.snapshot(time(1100u))!!.timing.clockUncertain)
        assertEquals(StatusAcceptance.DUPLICATE, observe(tracker, status(), at = 1200u))
        assertTrue(tracker.snapshot(time(1200u))!!.timing.clockUncertain)
        assertTrue(tracker.snapshot(time(10u, 2))!!.timing.clockUncertain)
        assertTrue(tracker.snapshot(time(5000u))!!.timing.clockUncertain)
        assertEquals(before.ageLowerBoundMs, tracker.snapshot(time(5000u))!!.timing.ageLowerBoundMs)
        observe(tracker, status(revision = 2u, age = 1500u), at = 10u, epoch = 2)
        val resumed = tracker.snapshot(time(1010u, 2))!!.timing
        assertFalse(resumed.clockUncertain)
        assertEquals(3000uL, resumed.ageLowerBoundMs)
    }

    @Test fun epochMismatchCannotRecoverByReturningToTheOldEpoch() {
        val tracker = tracker()
        observe(tracker, status())
        assertTrue(tracker.snapshot(time(10u, 2))!!.timing.clockUncertain)
        val oldEpoch = tracker.snapshot(time(5100u))!!.timing
        assertTrue(oldEpoch.clockUncertain)
        assertEquals(1000uL, oldEpoch.ageLowerBoundMs)
        observe(tracker, status(revision = 2u, age = 6000u, remaining = 4000u), at = 5100u)
        val resumed = tracker.snapshot(time(6100u))!!.timing
        assertFalse(resumed.clockUncertain)
        assertEquals(7000uL, resumed.ageLowerBoundMs)
    }

    @Test fun regressedReceiptCannotDoubleCountElapsedTime() {
        val tracker = tracker()
        observe(tracker, status())
        tracker.snapshot(time(1100u))
        observe(tracker, status(revision = 2u, age = 1100u), at = 1000u)
        val uncertain = tracker.snapshot(time(1100u))!!.timing
        assertTrue(uncertain.clockUncertain)
        assertEquals(2000uL, uncertain.ageLowerBoundMs)
        observe(tracker, status(revision = 3u, age = 1200u), at = 1200u)
        assertEquals(2100uL, tracker.snapshot(time(1300u))!!.timing.ageLowerBoundMs)
    }

    @Test fun validatesObservationAgeAndTimingContinuityWithoutReplacingState() {
        val tracker = tracker()
        observe(tracker, status())
        rejected(StatusRejection.CHANGED_OBSERVATION) { observe(tracker, status(revision = 2u, observation = phone)) }
        rejected(StatusRejection.REGRESSING_AGE) { observe(tracker, status(revision = 2u, age = 999u)) }
        rejected(StatusRejection.CHANGED_TIMING) { observe(tracker, status(revision = 2u, late = true)) }
        rejected(StatusRejection.CHANGED_TIMING) { observe(tracker, status(revision = 2u, estimate = null)) }
        rejected(StatusRejection.CHANGED_TIMING) { observe(tracker, status(revision = 2u, remaining = 10_000u)) }
        rejected(StatusRejection.CHANGED_TIMING) { observe(tracker, status(revision = 2u, phase = RequestPhase.EXPIRED,
            reason = RequestStatusReason.TARGET_TIMED_OUT, terminal = 999u)) }
        assertEquals(1uL, tracker.snapshot(time(100u))!!.status.revision)
    }

    @Test fun terminalResultsAndWinningPhoneCannotChange() {
        val tracker = tracker()
        observe(tracker, status())
        observe(tracker, status(revision = 2u, phase = RequestPhase.EXECUTING))
        rejected(StatusRejection.CHANGED_DECIDING_PHONE) { observe(tracker, status(revision = 3u, phase = RequestPhase.EXECUTING, deciding = id)) }
        rejected(StatusRejection.CHANGED_DECIDING_PHONE) { observe(tracker, status(revision = 3u, phase = RequestPhase.EXECUTING, deciding = null)) }
        observe(tracker, status(revision = 3u, phase = RequestPhase.UNKNOWN, reason = RequestStatusReason.OUTCOME_UNAVAILABLE))
        rejected(StatusRejection.INVALID_TRANSITION) { observe(tracker, status(revision = 4u, phase = RequestPhase.SUCCEEDED, reason = RequestStatusReason.VERIFIED_RESULT)) }
        rejected(StatusRejection.INVALID_TRANSITION) { observe(tracker, status(revision = 4u, phase = RequestPhase.UNKNOWN,
            reason = RequestStatusReason.OUTCOME_UNAVAILABLE, age = 1100u, terminal = 1100u)) }
        observe(tracker, status(revision = 4u, phase = RequestPhase.UNKNOWN, reason = RequestStatusReason.OUTCOME_UNAVAILABLE, age = 1100u, terminal = 1000u))
        assertEquals(RequestPhase.UNKNOWN, tracker.snapshot(time(100u))!!.status.phase)
    }

    @Test fun afterDispatchDisappearanceAndExpiryCannotMasqueradeAsCancellation() {
        for (initial in listOf(RequestPhase.AUTHORIZED, RequestPhase.EXECUTING)) {
            val tracker = tracker()
            observe(tracker, status(phase = initial))
            rejected(StatusRejection.INVALID_TRANSITION) { observe(tracker, status(revision = 2u, phase = RequestPhase.EXPIRED, reason = RequestStatusReason.TARGET_TIMED_OUT)) }
            rejected(StatusRejection.INVALID_TRANSITION) { observe(tracker, status(revision = 2u, phase = RequestPhase.CANCELLED, reason = RequestStatusReason.TARGET_DISAPPEARED)) }
            if (initial == RequestPhase.AUTHORIZED) {
                observe(tracker, status(revision = 2u, phase = RequestPhase.CANCELLED, reason = RequestStatusReason.NO_DISPATCH_PROVED))
            } else rejected(StatusRejection.INVALID_TRANSITION) {
                observe(tracker, status(revision = 2u, phase = RequestPhase.CANCELLED, reason = RequestStatusReason.NO_DISPATCH_PROVED))
            }
        }
        val pending = tracker()
        observe(pending, status(phase = RequestPhase.PRESENTED))
        rejected(StatusRejection.INVALID_TRANSITION) { observe(pending, status(revision = 2u)) }
        observe(pending, status(revision = 2u, phase = RequestPhase.CANCELLED, reason = RequestStatusReason.TARGET_DISAPPEARED, deciding = null))
    }

    @Test fun saturatesArithmeticAndRetainsNoAuthorityFromAnEstimate() {
        val tracker = tracker()
        observe(tracker, status(age = ULong.MAX_VALUE - 10u, remaining = ULong.MAX_VALUE, estimate = ULong.MAX_VALUE))
        val snapshot = tracker.snapshot(time(1000u))!!
        assertEquals(ULong.MAX_VALUE, snapshot.timing.ageLowerBoundMs)
        assertEquals(0uL, snapshot.timing.estimatedTargetRemainingMs)
        assertFalse(snapshot.status.phase.isTerminal)
    }

    @Test fun copiesIncomingBytesAndKeyAndHonorsLimits() {
        val public = publicKey(key)
        val tracker = tracker(public)
        public.fill(0)
        val bytes = status().encode(limits)
        val signature = sign(bytes)
        tracker.observe(bytes, signature, time(100u))
        bytes.fill(0); signature.fill(0)
        assertEquals(StatusAcceptance.DUPLICATE, observe(tracker, status()))
        assertFailsWith<CborException> { tracker.observe(ByteArray(2049), ByteArray(64), time(100u)) }
        assertEquals(1uL, tracker.snapshot(time(100u))!!.status.revision)
    }

    private fun newKey(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun publicKey(pair: KeyPair): ByteArray {
        val point = (pair.public as ECPublicKey).w
        fun coordinate(value: java.math.BigInteger) = value.toByteArray().let { bytes -> ByteArray(32 - minOf(bytes.size, 32)) + bytes.takeLast(32).toByteArray() }
        return byteArrayOf(4) + coordinate(point.affineX) + coordinate(point.affineY)
    }
    private fun sign(bytes: ByteArray, pair: KeyPair = key, type: ApprovalMessageType = ApprovalMessageType.STATUS,
        purpose: SigningPurpose = SigningPurpose.STATUS): ByteArray = Signature.getInstance("SHA256withECDSAinP1363Format").run {
        initSign(pair.private)
        update(SigningInput.make(1u, type, purpose, bytes, limits, limits))
        sign()
    }
}
