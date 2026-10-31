package dev.remozio.protocol

enum class UpdateSchedulingProgressPhase(val tag: ULong) {
    UNKNOWN(0u), READY(1u), DRAINING(2u), ACTIVATING(3u), CHECKING_RESTART(4u), FINISHING(5u), COMPLETED(6u), CANCELLED(7u);
    val irreversible: Boolean get() = this in setOf(ACTIVATING, CHECKING_RESTART, FINISHING, COMPLETED)
}
enum class UpdateSchedulingDesignation(val tag: ULong) { UNKNOWN(0u), UNASSIGNED(1u), THIS_ACCOUNT(2u), OTHER_ACCOUNT(3u) }
enum class UpdateSchedulingSecurityStatus(val tag: ULong) { UNKNOWN(0u), NOT_SECURITY(1u), SECURITY(2u) }
enum class UpdateSchedulingAdmissionState(val tag: ULong) { UNKNOWN(0u), OPEN(1u), CLOSED(2u) }

data class UpdateSchedulingBlocker(val kind: Kind, val count: ULong?, val oldestAgeMilliseconds: ULong?) {
    enum class Kind(val tag: ULong) { PENDING_REQUESTS(0u), ACTIVE_COMMANDS(1u), LIVE_GUI_PERMITS(2u), OTHER_ACCOUNTS(3u) }
    init {
        if (kind == Kind.OTHER_ACCOUNTS) require(count == null && oldestAgeMilliseconds == null)
        else require(count != null && count > 0u)
    }
    fun oldestAgeMillisecondsAfterObservation(elapsed: ULong?): ULong? = advanceUpdateAge(oldestAgeMilliseconds, elapsed)
    override fun toString() = "UpdateSchedulingBlocker(redacted)"
}

/** A signed observation. Each action still needs its current Root challenge and decision signature. */
class UpdateSchedulingProgressResponse(
    val status: UpdateSchedulingStatusResponse,
    val phase: UpdateSchedulingProgressPhase,
    val designation: UpdateSchedulingDesignation,
    val security: UpdateSchedulingSecurityStatus,
    val readyAgeMilliseconds: ULong?,
    val availableActions: ULong,
    blockers: List<UpdateSchedulingBlocker>,
    val admission: UpdateSchedulingAdmissionState,
) {
    private val capturedBlockers = blockers.toList()
    val blockers: List<UpdateSchedulingBlocker> get() = capturedBlockers.toList()
    init {
        require(status.controlDigest == null && availableActions <= 7u && capturedBlockers.size <= 4)
        require(capturedBlockers.zipWithNext().all { (first, second) -> first.kind.tag < second.kind.tag })
        if (phase == UpdateSchedulingProgressPhase.UNKNOWN || phase.irreversible || admission == UpdateSchedulingAdmissionState.UNKNOWN)
            require(availableActions == 0uL)
        if (canInstallWhenCurrentWorkFinishes) require(
            phase in setOf(UpdateSchedulingProgressPhase.READY, UpdateSchedulingProgressPhase.CANCELLED) &&
                admission == UpdateSchedulingAdmissionState.OPEN,
        )
        if (canDeferUpdate) require(designation == UpdateSchedulingDesignation.THIS_ACCOUNT)
        if (canCancelDrain) require(admission == UpdateSchedulingAdmissionState.CLOSED &&
            status.requestedAction == UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES)
    }
    val canInstallWhenCurrentWorkFinishes: Boolean get() = availableActions and 1uL != 0uL
    val canDeferUpdate: Boolean get() = availableActions and 2uL != 0uL
    val canCancelDrain: Boolean get() = availableActions and 4uL != 0uL
    fun readyAgeMillisecondsAfterObservation(elapsed: ULong?): ULong? = advanceUpdateAge(readyAgeMilliseconds, elapsed)
    fun encode(): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to CborValue.Bytes(status.encode()),
        2uL to CborValue.Unsigned(phase.tag), 3uL to CborValue.Unsigned(designation.tag),
        4uL to CborValue.Unsigned(security.tag),
        5uL to (readyAgeMilliseconds?.let { CborValue.Unsigned(it) } ?: CborValue.Null),
        6uL to CborValue.Unsigned(availableActions),
        7uL to CborValue.ArrayValue(capturedBlockers.map { CborValue.ArrayValue(listOf(
            CborValue.Unsigned(it.kind.tag), it.count?.let { n -> CborValue.Unsigned(n) } ?: CborValue.Null,
            it.oldestAgeMilliseconds?.let { n -> CborValue.Unsigned(n) } ?: CborValue.Null,
        )) }),
        8uL to CborValue.Unsigned(admission.tag),
    )), LIMITS)
    override fun toString() = "UpdateSchedulingProgressResponse(redacted)"
    companion object {
        const val MAXIMUM_BYTES = 4096
        val LIMITS = CborLimits(MAXIMUM_BYTES, 3, 64)
        fun decode(bytes: ByteArray): UpdateSchedulingProgressResponse {
            val fields = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values
                ?: throw IllegalArgumentException("Invalid update progress")
            require(fields.keys == (0uL..8uL).toSet() && fields[0uL] == CborValue.Unsigned(1u))
            fun uint(value: CborValue?): ULong = (value as? CborValue.Unsigned)?.value
                ?: throw IllegalArgumentException("Invalid update progress number")
            fun optional(value: CborValue?): ULong? = if (value == CborValue.Null) null else uint(value)
            val statusBytes = (fields[1uL] as? CborValue.Bytes)?.copyBytes()
                ?: throw IllegalArgumentException("Invalid update progress status")
            val entries = (fields[7uL] as? CborValue.ArrayValue)?.values
                ?: throw IllegalArgumentException("Invalid update blockers")
            val value = UpdateSchedulingProgressResponse(
                UpdateSchedulingStatusResponse.decode(statusBytes),
                UpdateSchedulingProgressPhase.entries.single { it.tag == uint(fields[2uL]) },
                UpdateSchedulingDesignation.entries.single { it.tag == uint(fields[3uL]) },
                UpdateSchedulingSecurityStatus.entries.single { it.tag == uint(fields[4uL]) }, optional(fields[5uL]),
                uint(fields[6uL]), entries.map {
                    val parts = (it as? CborValue.ArrayValue)?.values ?: throw IllegalArgumentException("Invalid update blocker")
                    require(parts.size == 3)
                    UpdateSchedulingBlocker(UpdateSchedulingBlocker.Kind.entries.single { kind -> kind.tag == uint(parts[0]) },
                        optional(parts[1]), optional(parts[2]))
                }, UpdateSchedulingAdmissionState.entries.single { it.tag == uint(fields[8uL]) },
            )
            require(value.encode().contentEquals(bytes)); return value
        }
    }
}

private fun advanceUpdateAge(age: ULong?, elapsed: ULong?): ULong? =
    if (age == null || elapsed == null || elapsed > ULong.MAX_VALUE - age) null else age + elapsed

object UpdateSchedulingProgressSigningInput {
    fun make(wireVersion: ULong, canonicalPayload: ByteArray, inputLimits: CborLimits): ByteArray {
        if (wireVersion != 1uL) throw SigningInputException(SigningInputFailure.UNSUPPORTED_VERSION)
        UpdateSchedulingProgressResponse.decode(canonicalPayload)
        return DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Text("dev.remozio.update-scheduling-progress"), 1uL to CborValue.Unsigned(1u),
            2uL to CborValue.Unsigned(1u), 3uL to CborValue.Unsigned(1u), 4uL to CborValue.Bytes(canonicalPayload),
        )), inputLimits)
    }
}
object UpdateSchedulingProgressSignature {
    fun verify(signature: ByteArray, authorityPublicKey: ByteArray, wireVersion: ULong,
               canonicalPayload: ByteArray, inputLimits: CborLimits): Boolean =
        P256Verification.verify(signature, authorityPublicKey,
            UpdateSchedulingProgressSigningInput.make(wireVersion, canonicalPayload, inputLimits))
}
