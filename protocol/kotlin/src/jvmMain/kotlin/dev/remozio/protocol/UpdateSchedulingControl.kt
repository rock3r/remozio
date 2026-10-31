package dev.remozio.protocol

enum class UpdateSchedulingAction(val tag: ULong) {
    INSTALL_WHEN_CURRENT_WORK_FINISHES(0u), DEFER_UPDATE(1u), CANCEL_DRAIN(2u)
}
enum class UpdateSchedulingControlFailure { INVALID_FIELDS, UNSUPPORTED_SCHEMA, INVALID_BYTES, INVALID_CONTROL, UNSUPPORTED_ACTION }
class UpdateSchedulingControlException(val reason: UpdateSchedulingControlFailure) : IllegalArgumentException(reason.name)

/** A scheduling claim for one verified release. It cannot select artifacts, change floors, or authorize target actions. */
class UpdateSchedulingControl(
    macID: ByteArray, accountID: ByteArray, phoneID: ByteArray, enrollmentEpoch: ByteArray, operationID: ByteArray,
    challenge: ByteArray, keyID: ByteArray, updateID: ByteArray, val expectedGeneration: ULong, val expectedRevision: ULong,
    val issuedAtUnixMillis: ULong, val expiresAtUnixMillis: ULong, val action: UpdateSchedulingAction,
) {
    init {
        updateRequire(listOf(macID, accountID, phoneID, enrollmentEpoch, operationID, keyID).all { it.size == 16 } &&
            challenge.size == 32 && updateID.size == 32, UpdateSchedulingControlFailure.INVALID_BYTES)
        updateRequire(expectedGeneration > 0uL && expiresAtUnixMillis > issuedAtUnixMillis, UpdateSchedulingControlFailure.INVALID_CONTROL)
    }
    private val bytes = listOf(macID, accountID, phoneID, enrollmentEpoch, operationID, challenge, keyID, updateID).map { CborValue.Bytes(it) }
    val macID: ByteArray get() = bytes[0].copyBytes()
    val accountID: ByteArray get() = bytes[1].copyBytes()
    val phoneID: ByteArray get() = bytes[2].copyBytes()
    val enrollmentEpoch: ByteArray get() = bytes[3].copyBytes()
    val operationID: ByteArray get() = bytes[4].copyBytes()
    val challenge: ByteArray get() = bytes[5].copyBytes()
    val keyID: ByteArray get() = bytes[6].copyBytes()
    val updateID: ByteArray get() = bytes[7].copyBytes()
    override fun toString(): String = "UpdateSchedulingControl(redacted)"
    fun encode(limits: CborLimits): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to bytes[0], 2uL to bytes[1], 3uL to bytes[2], 4uL to bytes[3],
        5uL to bytes[4], 6uL to bytes[5], 7uL to bytes[6], 8uL to bytes[7],
        9uL to CborValue.Unsigned(expectedGeneration), 10uL to CborValue.Unsigned(expectedRevision),
        11uL to CborValue.Unsigned(issuedAtUnixMillis), 12uL to CborValue.Unsigned(expiresAtUnixMillis),
        13uL to CborValue.Unsigned(action.tag),
    )), limits)
    companion object {
        fun decode(payload: ByteArray, limits: CborLimits): UpdateSchedulingControl {
            val fields = (DeterministicCbor.decode(payload, limits) as? CborValue.Fields)?.values
                ?: updateFail(UpdateSchedulingControlFailure.INVALID_FIELDS)
            updateRequire(fields.keys == (0uL..13uL).toSet(), UpdateSchedulingControlFailure.INVALID_FIELDS)
            updateRequire(fields[0u] == CborValue.Unsigned(1u), UpdateSchedulingControlFailure.UNSUPPORTED_SCHEMA)
            fun bytes(key: ULong): ByteArray = (fields[key] as? CborValue.Bytes)?.copyBytes()
                ?: updateFail(UpdateSchedulingControlFailure.INVALID_BYTES)
            fun uint(key: ULong): ULong = (fields[key] as? CborValue.Unsigned)?.value
                ?: updateFail(UpdateSchedulingControlFailure.INVALID_CONTROL)
            val tag = (fields[13u] as? CborValue.Unsigned)?.value ?: updateFail(UpdateSchedulingControlFailure.UNSUPPORTED_ACTION)
            val action = UpdateSchedulingAction.entries.firstOrNull { it.tag == tag }
                ?: updateFail(UpdateSchedulingControlFailure.UNSUPPORTED_ACTION)
            return UpdateSchedulingControl(bytes(1u), bytes(2u), bytes(3u), bytes(4u), bytes(5u), bytes(6u), bytes(7u), bytes(8u),
                uint(9u), uint(10u), uint(11u), uint(12u), action)
        }
    }
}

object UpdateSchedulingSigningInput {
    fun make(wireVersion: ULong, canonicalPayload: ByteArray, payloadLimits: CborLimits, inputLimits: CborLimits): ByteArray {
        if (wireVersion != 1uL) throw SigningInputException(SigningInputFailure.UNSUPPORTED_VERSION)
        if (canonicalPayload.size > payloadLimits.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
        val payload = canonicalPayload.copyOf()
        UpdateSchedulingControl.decode(payload, payloadLimits)
        return DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Text("dev.remozio.update-scheduling"), 1uL to CborValue.Unsigned(wireVersion),
            2uL to CborValue.Unsigned(1u), 3uL to CborValue.Unsigned(1u), 4uL to CborValue.Bytes(payload),
        )), inputLimits)
    }
}

/** The authority must select the current enrolled decision key and consume the matching scheduling challenge once. */
object UpdateSchedulingSignature {
    fun verify(signature: ByteArray, publicKey: ByteArray, wireVersion: ULong, canonicalPayload: ByteArray,
               payloadLimits: CborLimits, inputLimits: CborLimits): Boolean = P256Verification.verify(
        signature, publicKey, UpdateSchedulingSigningInput.make(wireVersion, canonicalPayload, payloadLimits, inputLimits))
}

private fun updateRequire(condition: Boolean, failure: UpdateSchedulingControlFailure) { if (!condition) updateFail(failure) }
private fun updateFail(failure: UpdateSchedulingControlFailure): Nothing = throw UpdateSchedulingControlException(failure)
