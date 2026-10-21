package dev.remozio.protocol

enum class RoutingStatusMode(val tag: ULong) { AUTOMATIC(0u), PRESENT(1u), AWAY(2u) }
enum class RoutingStatusDestination(val tag: ULong) { LOCAL_MAC(0u), PHONES(1u) }
enum class RoutingStatusReason(val tag: ULong) {
    MANUAL_PRESENT(0u), MANUAL_AWAY(1u), REMOTE_DESKTOP(2u), LOCKED(3u), DISPLAYS_OFF(4u),
    DISPLAYS_DARK(5u), IDLE(6u), ACTIVE(7u), DETECTOR_UNAVAILABLE(8u),
}
enum class RoutingStatusOutcome(val tag: ULong) { STATUS(0u), CHALLENGE(1u), APPLIED(2u), CONFLICT(3u) }

/** Coarse authority state. Connection loss and elapsed response age still determine whether it is current. */
class RoutingStatusState(val mode: RoutingStatusMode, val revision: ULong, val destination: RoutingStatusDestination,
                         val reason: RoutingStatusReason, val detectionLimited: Boolean) {
    init {
        require(when (mode) {
            RoutingStatusMode.PRESENT -> destination == RoutingStatusDestination.LOCAL_MAC && reason == RoutingStatusReason.MANUAL_PRESENT && !detectionLimited
            RoutingStatusMode.AWAY -> destination == RoutingStatusDestination.PHONES && reason == RoutingStatusReason.MANUAL_AWAY && !detectionLimited
            RoutingStatusMode.AUTOMATIC -> when (reason) {
                RoutingStatusReason.MANUAL_PRESENT, RoutingStatusReason.MANUAL_AWAY -> false
                RoutingStatusReason.REMOTE_DESKTOP -> destination == RoutingStatusDestination.LOCAL_MAC && !detectionLimited
                RoutingStatusReason.ACTIVE -> destination == RoutingStatusDestination.LOCAL_MAC
                RoutingStatusReason.LOCKED, RoutingStatusReason.DISPLAYS_OFF, RoutingStatusReason.DISPLAYS_DARK, RoutingStatusReason.IDLE -> destination == RoutingStatusDestination.PHONES
                RoutingStatusReason.DETECTOR_UNAVAILABLE -> detectionLimited
            }
        })
    }
    override fun toString() = "RoutingStatusState(redacted)"
}

/** A parsed claim. Verify its authority signature, live scope, query nonce and elapsed deadline before use. */
class RoutingStatusResponse(
    val scope: ChannelScope, queryNonce: ByteArray, val outcome: RoutingStatusOutcome, clockEpoch: ByteArray,
    val sampledAtMilliseconds: ULong, val state: RoutingStatusState, canonicalChallenge: ByteArray? = null,
    controlDigest: ByteArray? = null, val appliedRevision: ULong? = null,
) {
    val queryNonce = CborValue.Bytes(queryNonce)
    val clockEpoch = CborValue.Bytes(clockEpoch)
    val canonicalChallenge = canonicalChallenge?.let { CborValue.Bytes(it) }
    val controlDigest = controlDigest?.let { CborValue.Bytes(it) }
    init {
        require(this.queryNonce.size == 32 && this.clockEpoch.size == 16 && (this.controlDigest?.size ?: 32) == 32)
        when (outcome) {
            RoutingStatusOutcome.STATUS -> require(canonicalChallenge == null && controlDigest == null && appliedRevision == null)
            RoutingStatusOutcome.CHALLENGE -> {
                require(canonicalChallenge != null && controlDigest == null && appliedRevision == null && state.revision < ULong.MAX_VALUE)
                val control = RoutingAwayControl.decode(checkNotNull(this.canonicalChallenge).copyBytes(), CHALLENGE_LIMITS)
                require(ChannelScope(control.macID, control.accountID, control.phoneID, control.enrollmentEpoch) == scope && control.expectedRevision == state.revision)
            }
            RoutingStatusOutcome.APPLIED -> require(canonicalChallenge == null && controlDigest != null && appliedRevision != null && appliedRevision > 0uL && appliedRevision <= state.revision)
            RoutingStatusOutcome.CONFLICT -> require(canonicalChallenge == null && appliedRevision == null)
        }
    }
    fun encode(): ByteArray {
        val ids = scope.value.values
        return DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Unsigned(1u), 1uL to ids[0], 2uL to ids[1], 3uL to ids[2], 4uL to ids[3],
            5uL to queryNonce, 6uL to CborValue.Unsigned(outcome.tag), 7uL to clockEpoch, 8uL to CborValue.Unsigned(sampledAtMilliseconds),
            9uL to CborValue.Unsigned(state.mode.tag), 10uL to CborValue.Unsigned(state.revision), 11uL to CborValue.Unsigned(state.destination.tag),
            12uL to CborValue.Unsigned(state.reason.tag), 13uL to CborValue.Unsigned(if (state.detectionLimited) 1u else 0u),
            14uL to (canonicalChallenge ?: CborValue.Null), 15uL to (controlDigest ?: CborValue.Null),
            16uL to (appliedRevision?.let { CborValue.Unsigned(it) } ?: CborValue.Null),
        )), LIMITS)
    }
    override fun toString() = "RoutingStatusResponse(redacted)"
    companion object {
        const val MAXIMUM_BYTES = 3072
        val LIMITS = CborLimits(MAXIMUM_BYTES, 2, 40)
        private val CHALLENGE_LIMITS = CborLimits(1024, 2, 32)
        fun decode(bytes: ByteArray): RoutingStatusResponse {
            val f = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values ?: throw IllegalArgumentException("Invalid routing status")
            require(f.keys == (0uL..16uL).toSet() && f[0u] == CborValue.Unsigned(1u))
            fun data(n: ULong) = (f[n] as? CborValue.Bytes)?.copyBytes() ?: throw IllegalArgumentException("Invalid routing bytes")
            fun uint(n: ULong) = (f[n] as? CborValue.Unsigned)?.value ?: throw IllegalArgumentException("Invalid routing number")
            require(uint(13u) <= 1uL)
            val state = RoutingStatusState(RoutingStatusMode.entries.single { it.tag == uint(9u) }, uint(10u),
                RoutingStatusDestination.entries.single { it.tag == uint(11u) }, RoutingStatusReason.entries.single { it.tag == uint(12u) }, uint(13u) == 1uL)
            val result = RoutingStatusResponse(ChannelScope(data(1u), data(2u), data(3u), data(4u)), data(5u),
                RoutingStatusOutcome.entries.single { it.tag == uint(6u) }, data(7u), uint(8u), state,
                if (f[14u] == CborValue.Null) null else data(14u), if (f[15u] == CborValue.Null) null else data(15u),
                if (f[16u] == CborValue.Null) null else uint(16u))
            require(result.encode().contentEquals(bytes)); return result
        }
    }
}

/** Root responses use a distinct type and purpose from the existing phone Away signature. */
object RoutingStatusSigningInput {
    fun make(wireVersion: ULong, canonicalPayload: ByteArray, inputLimits: CborLimits): ByteArray {
        if (wireVersion != 1uL) throw SigningInputException(SigningInputFailure.UNSUPPORTED_VERSION)
        val payload = canonicalPayload.copyOf()
        RoutingStatusResponse.decode(payload)
        return DeterministicCbor.encode(CborValue.Fields(mapOf(0uL to CborValue.Text("dev.remozio.routing"),
            1uL to CborValue.Unsigned(wireVersion), 2uL to CborValue.Unsigned(2u), 3uL to CborValue.Unsigned(2u),
            4uL to CborValue.Bytes(payload))), inputLimits)
    }
}

object RoutingStatusSignature {
    fun verify(signature: ByteArray, publicKey: ByteArray, wireVersion: ULong, canonicalPayload: ByteArray, inputLimits: CborLimits): Boolean =
        P256Verification.verify(signature, publicKey, RoutingStatusSigningInput.make(wireVersion, canonicalPayload, inputLimits))
}
