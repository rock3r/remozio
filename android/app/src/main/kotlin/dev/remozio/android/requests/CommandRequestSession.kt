package dev.remozio.android.requests

import dev.remozio.protocol.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

internal enum class CommandSessionRejection { INVALID_SIGNATURE, WRONG_AUTHORITY }
internal class CommandSessionException(val reason: CommandSessionRejection) : IllegalArgumentException(reason.name)

internal data class RequestLimits(
    val body: CborLimits,
    val capture: CborLimits,
    val status: CborLimits,
    val signing: CborLimits,
)

internal data class CommandRequestSnapshot(val capture: CommandCapture?, val status: TrackedRequestStatus?)

/**
 * Owns one authenticated command capture in memory. A signature establishes origin, not current validity.
 * The enrollment owner must discard this session when its trusted authority changes.
 */
internal class CommandRequestSession private constructor(
    capture: CommandCapture,
    private val tracker: RequestStatusTracker,
) {
    private var capture: CommandCapture? = capture
    private val revision = MutableStateFlow(0uL)
    val revisions: StateFlow<ULong> = revision.asStateFlow()

    /** Removes the owned capture before notifying observers of a terminal update. */
    @Synchronized
    fun observe(body: ByteArray, signature: ByteArray, receivedAt: ElapsedInstant): StatusAcceptance {
        val result = tracker.observe(body, signature, receivedAt)
        if (result == StatusAcceptance.APPLIED) {
            val status = checkNotNull(tracker.snapshot(receivedAt)).status
            if (status.phase.isTerminal) capture = null
            revision.value = status.revision
        }
        return result
    }

    /** Callers must replace old snapshots; clearing this owner cannot erase references held elsewhere. */
    @Synchronized
    fun snapshot(now: ElapsedInstant) = CommandRequestSnapshot(capture, tracker.snapshot(now))

    companion object {
        private val capabilities = ContractCapabilities(mapOf(RequestContract(RequestKind.COMMAND, 1u, 1u) to emptySet()))

        /** The expected IDs and public key must come from a trusted enrollment, never from the message. */
        fun open(
            body: ByteArray,
            signature: ByteArray,
            expectedMacID: ByteArray,
            expectedAccountID: ByteArray,
            trustedAuthorityPublicKey: ByteArray,
            limits: RequestLimits,
        ): CommandRequestSession {
            require(expectedMacID.size == 16 && expectedAccountID.size == 16)
            if (body.size > limits.body.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
            if (signature.size != 64) throw CommandSessionException(CommandSessionRejection.INVALID_SIGNATURE)
            val canonical = body.copyOf()
            val key = trustedAuthorityPublicKey.copyOf()
            if (!ApprovalSignature.verify(signature.copyOf(), key, 1u, ApprovalMessageType.REQUEST,
                    SigningPurpose.ISSUED_REQUEST, canonical, limits.body, limits.signing)) {
                throw CommandSessionException(CommandSessionRejection.INVALID_SIGNATURE)
            }
            val request = IssuedRequestPayload.decode(canonical, limits.body, limits.capture, capabilities)
            if (!request.macID.contentEquals(expectedMacID) || !request.accountID.contentEquals(expectedAccountID)) {
                throw CommandSessionException(CommandSessionRejection.WRONG_AUTHORITY)
            }
            val capture = CommandCapture(request.canonicalCapture, limits.capture)
            return CommandRequestSession(capture,
                RequestStatusTracker(request, key, limits.status, limits.signing, limits.body))
        }
    }
}
