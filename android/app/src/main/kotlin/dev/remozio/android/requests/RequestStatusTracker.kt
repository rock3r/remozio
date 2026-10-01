package dev.remozio.android.requests

import dev.remozio.protocol.ApprovalMessageType
import dev.remozio.protocol.ApprovalSignature
import dev.remozio.protocol.CborFailure
import dev.remozio.protocol.CborException
import dev.remozio.protocol.CborLimits
import dev.remozio.protocol.CborValue
import dev.remozio.protocol.IssuedRequestPayload
import dev.remozio.protocol.RequestPhase
import dev.remozio.protocol.RequestStatusPayload
import dev.remozio.protocol.RequestStatusReason
import dev.remozio.protocol.SigningPurpose

/** The caller supplies an elapsed clock that includes sleep and a new epoch whenever its origin changes. */
internal data class ElapsedInstant(val epoch: Long, val milliseconds: ULong)

internal enum class StatusRejection {
    INVALID_SIGNATURE, WRONG_REQUEST, REVISION_CONFLICT, INVALID_TRANSITION,
    CHANGED_OBSERVATION, REGRESSING_AGE, CHANGED_TIMING, CHANGED_DECIDING_PHONE,
}
internal class StatusTrackingException(val reason: StatusRejection) : IllegalArgumentException(reason.name)
internal enum class StatusAcceptance { APPLIED, DUPLICATE, OLDER }

internal data class RequestTiming(
    val ageLowerBoundMs: ULong,
    val authorizationRemainingUpperBoundMs: ULong?,
    val estimatedTargetRemainingMs: ULong?,
    val clockUncertain: Boolean,
) {
    // There is no authority-authenticated delivery-delay measurement in this layer yet.
    val deliveryDelayUnknown: Boolean get() = true
}

internal data class TrackedRequestStatus(val status: RequestStatusPayload, val timing: RequestTiming)

/**
 * Tracks signed status for an already authenticated issued request. It grants no action authority or freshness.
 * Discard the tracker when the trusted Mac key or enrollment changes. The caller owns that trust lifecycle.
 */
internal class RequestStatusTracker(
    request: IssuedRequestPayload,
    trustedAuthorityPublicKey: ByteArray,
    private val statusLimits: CborLimits,
    private val signingLimits: CborLimits,
    requestLimits: CborLimits,
) {
    private val bindings = listOf(request.macID, request.accountID, request.requestID,
        request.requestDigest(requestLimits, signingLimits), request.challenge).map(CborValue::Bytes)
    private val authorityKey = trustedAuthorityPublicKey.copyOf()
    private var current: RequestStatusPayload? = null
    private var canonical: ByteArray? = null
    private var anchor: ElapsedInstant? = null
    private var lastElapsed: ULong = 0u
    private var anchorClockValid = true
    private var anchorAge: ULong = 0u
    private var ageFloor: ULong = 0u
    private var anchorRemaining: ULong? = null
    private var remainingCeiling: ULong? = null

    init { require(authorityKey.size == 65 && authorityKey[0] == 4.toByte()) }

    /** Checks and commits one snapshot under the same monitor. Failed or stale input cannot replace state. */
    @Synchronized
    fun observe(canonicalStatus: ByteArray, signature: ByteArray, receivedAt: ElapsedInstant): StatusAcceptance {
        if (canonicalStatus.size > statusLimits.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
        if (signature.size != 64) reject(StatusRejection.INVALID_SIGNATURE)
        val bytes = canonicalStatus.copyOf()
        val signed = signature.copyOf()
        if (!ApprovalSignature.verify(signed, authorityKey, 1u, ApprovalMessageType.STATUS, SigningPurpose.STATUS,
                bytes, statusLimits, signingLimits)) reject(StatusRejection.INVALID_SIGNATURE)
        val incoming = RequestStatusPayload.decode(bytes, statusLimits)
        val supplied = listOf(incoming.macID, incoming.accountID, incoming.requestID, incoming.requestDigest, incoming.challenge)
        if (supplied.indices.any { CborValue.Bytes(supplied[it]) != bindings[it] }) reject(StatusRejection.WRONG_REQUEST)
        val previous = current
        if (previous != null) {
            if (incoming.revision < previous.revision) return StatusAcceptance.OLDER
            if (incoming.revision == previous.revision) {
                if (!bytes.contentEquals(canonical)) reject(StatusRejection.REVISION_CONFLICT)
                return StatusAcceptance.DUPLICATE
            }
            checkProgress(previous, incoming)
        }
        // Project the old anchor before replacement so delayed updates cannot move the visible clock backwards.
        val oldTiming = project(receivedAt)
        anchorAge = maxOf(oldTiming?.ageLowerBoundMs ?: 0u, incoming.observedAgeMs)
        anchorRemaining = incoming.authorizationRemainingMs?.let { remaining ->
            oldTiming?.authorizationRemainingUpperBoundMs?.let { minOf(it, remaining) } ?: remaining
        }
        ageFloor = anchorAge
        remainingCeiling = anchorRemaining
        anchorClockValid = anchor == null || anchor?.epoch != receivedAt.epoch || receivedAt.milliseconds >= lastElapsed
        if (anchorClockValid) lastElapsed = receivedAt.milliseconds
        anchor = receivedAt
        current = incoming
        canonical = bytes
        return StatusAcceptance.APPLIED
    }

    @Synchronized
    fun snapshot(now: ElapsedInstant): TrackedRequestStatus? {
        val status = current ?: return null
        return TrackedRequestStatus(status, checkNotNull(project(now)))
    }

    private fun project(now: ElapsedInstant): RequestTiming? {
        val status = current ?: return null
        val start = checkNotNull(anchor)
        val clockUsable = anchorClockValid && now.epoch == start.epoch && now.milliseconds >= lastElapsed
        if (clockUsable) lastElapsed = now.milliseconds
        val elapsed = if (clockUsable) now.milliseconds - start.milliseconds else 0uL
        ageFloor = maxOf(ageFloor, addSaturated(anchorAge, elapsed))
        val remaining = anchorRemaining?.let { subtractFloored(it, elapsed) }
        remainingCeiling = remaining?.let { minOf(remainingCeiling ?: it, it) }
        return RequestTiming(ageFloor, remainingCeiling,
            status.estimatedLifetimeMs?.let { subtractFloored(it, ageFloor) }, !clockUsable)
    }

    private fun checkProgress(old: RequestStatusPayload, next: RequestStatusPayload) {
        if (!old.observationID.contentEquals(next.observationID)) reject(StatusRejection.CHANGED_OBSERVATION)
        if (next.observedAgeMs < old.observedAgeMs) reject(StatusRejection.REGRESSING_AGE)
        if (old.lateObservation != next.lateObservation || old.estimatedLifetimeMs != next.estimatedLifetimeMs) {
            reject(StatusRejection.CHANGED_TIMING)
        }
        val oldRemaining = old.authorizationRemainingMs
        val nextRemaining = next.authorizationRemainingMs
        if (oldRemaining != null && nextRemaining != null && nextRemaining > oldRemaining) reject(StatusRejection.CHANGED_TIMING)
        if (old.decisionPhoneID != null && !old.decisionPhoneID.contentEquals(next.decisionPhoneID)) {
            reject(StatusRejection.CHANGED_DECIDING_PHONE)
        }
        if (old.phase.isTerminal) {
            if (old.phase != next.phase || old.reason != next.reason || old.terminalAgeMs != next.terminalAgeMs ||
                !old.decisionPhoneID.contentEquals(next.decisionPhoneID)) reject(StatusRejection.INVALID_TRANSITION)
            return
        }
        val terminalAge = next.terminalAgeMs
        if (terminalAge != null && terminalAge < old.observedAgeMs) reject(StatusRejection.CHANGED_TIMING)
        val allowed = when (old.phase) {
            RequestPhase.QUEUED -> true
            RequestPhase.PRESENTED -> next.phase != RequestPhase.QUEUED
            RequestPhase.AUTHORIZED -> when (next.phase) {
                RequestPhase.AUTHORIZED, RequestPhase.EXECUTING, RequestPhase.SUCCEEDED, RequestPhase.FAILED, RequestPhase.UNKNOWN -> true
                RequestPhase.CANCELLED -> next.reason == RequestStatusReason.NO_DISPATCH_PROVED
                else -> false
            }
            RequestPhase.EXECUTING -> next.phase in setOf(RequestPhase.EXECUTING, RequestPhase.SUCCEEDED, RequestPhase.FAILED, RequestPhase.UNKNOWN)
            else -> false
        }
        if (!allowed) reject(StatusRejection.INVALID_TRANSITION)
    }

    private fun addSaturated(left: ULong, right: ULong): ULong = if (ULong.MAX_VALUE - left < right) ULong.MAX_VALUE else left + right
    private fun subtractFloored(left: ULong, right: ULong): ULong = if (left > right) left - right else 0u
    private fun reject(reason: StatusRejection): Nothing = throw StatusTrackingException(reason)
}
