package dev.remozio.protocol

/** A signed scheduling observation. It grants no admission, dispatch or activation authority. */
class UpdateSchedulingStatusResponse(
    val scope: ChannelScope, queryNonce: ByteArray, updateID: ByteArray,
    val generation: ULong, val revision: ULong, val requestedAction: UpdateSchedulingAction?, controlDigest: ByteArray? = null,
) {
    val queryNonce = CborValue.Bytes(queryNonce)
    val updateID = CborValue.Bytes(updateID)
    val controlDigest = controlDigest?.let { CborValue.Bytes(it) }
    init {
        require(this.queryNonce.size == 32 && this.updateID.size == 32 && generation > 0uL && ((revision == 0uL) == (requestedAction == null)))
        require(this.controlDigest == null || (this.controlDigest.size == 32 && requestedAction != null && revision > 0uL))
    }
    fun encode(): ByteArray {
        val ids = scope.value.values
        return DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Unsigned(1u), 1uL to ids[0], 2uL to ids[1], 3uL to ids[2], 4uL to ids[3],
            5uL to queryNonce, 6uL to updateID, 7uL to CborValue.Unsigned(generation), 8uL to CborValue.Unsigned(revision),
            9uL to (requestedAction?.let { CborValue.Unsigned(it.tag) } ?: CborValue.Null),
            10uL to (controlDigest ?: CborValue.Null),
        )), LIMITS)
    }
    override fun toString() = "UpdateSchedulingStatusResponse(redacted)"
    companion object {
        const val MAXIMUM_BYTES = 2048
        val LIMITS = CborLimits(MAXIMUM_BYTES, 2, 32)
        fun decode(bytes: ByteArray): UpdateSchedulingStatusResponse {
            val f = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values
                ?: throw IllegalArgumentException("Invalid update scheduling status")
            require(f.keys == (0uL..10uL).toSet() && f[0uL] == CborValue.Unsigned(1u))
            fun data(n: ULong) = (f[n] as? CborValue.Bytes)?.copyBytes() ?: throw IllegalArgumentException("Invalid status bytes")
            fun uint(n: ULong) = (f[n] as? CborValue.Unsigned)?.value ?: throw IllegalArgumentException("Invalid status number")
            val action = if (f[9uL] == CborValue.Null) null else UpdateSchedulingAction.entries.single { it.tag == uint(9u) }
            val result = UpdateSchedulingStatusResponse(ChannelScope(data(1u), data(2u), data(3u), data(4u)), data(5u), data(6u),
                uint(7u), uint(8u), action, if (f[10uL] == CborValue.Null) null else data(10u))
            require(result.encode().contentEquals(bytes)); return result
        }
    }
}

object UpdateSchedulingStatusSigningInput {
    fun make(wireVersion: ULong, canonicalPayload: ByteArray, inputLimits: CborLimits): ByteArray {
        if (wireVersion != 1uL) throw SigningInputException(SigningInputFailure.UNSUPPORTED_VERSION)
        UpdateSchedulingStatusResponse.decode(canonicalPayload)
        return DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Text("dev.remozio.update-scheduling-status"), 1uL to CborValue.Unsigned(1u),
            2uL to CborValue.Unsigned(1u), 3uL to CborValue.Unsigned(1u), 4uL to CborValue.Bytes(canonicalPayload),
        )), inputLimits)
    }
}

object UpdateSchedulingStatusSignature {
    fun verify(signature: ByteArray, authorityPublicKey: ByteArray, wireVersion: ULong,
               canonicalPayload: ByteArray, inputLimits: CborLimits): Boolean =
        P256Verification.verify(signature, authorityPublicKey,
            UpdateSchedulingStatusSigningInput.make(wireVersion, canonicalPayload, inputLimits))
}
