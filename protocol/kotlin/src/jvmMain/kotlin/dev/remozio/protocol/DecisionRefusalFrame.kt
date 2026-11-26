package dev.remozio.protocol

/** Authority evidence that one authenticated decision did not reach consumption. */
class DecisionRefusalFrame(val payload: Payload, signature: ByteArray) {
    enum class Reason(val tag: ULong) { REQUEST_CHANGED(1u), ACTION_UNAVAILABLE(2u) }

    class Payload(
        val scope: ChannelScope,
        sessionID: ByteArray,
        val sequence: ULong,
        requestID: ByteArray,
        requestDigest: ByteArray,
        decisionFrameDigest: ByteArray,
        val reason: Reason,
    ) {
        val sessionID = CborValue.Bytes(sessionID)
        val requestID = CborValue.Bytes(requestID)
        val requestDigest = CborValue.Bytes(requestDigest)
        val decisionFrameDigest = CborValue.Bytes(decisionFrameDigest)

        init {
            require(sessionID.size == 32 && requestID.size == 16 && requestDigest.size == 32 && decisionFrameDigest.size == 32)
        }

        internal fun encode(): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Unsigned(1u), 1uL to scope.value, 2uL to sessionID,
            3uL to CborValue.Unsigned(sequence), 4uL to requestID, 5uL to requestDigest,
            6uL to decisionFrameDigest, 7uL to CborValue.Unsigned(reason.tag),
        )), bodyLimits)

        fun signingInput(): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Text("dev.remozio.decision-refusal"), 1uL to CborValue.Unsigned(1u),
            2uL to CborValue.Bytes(encode()),
        )), limits)
    }

    val signature = CborValue.Bytes(signature)
    init { require(signature.size == 64) }

    fun verify(authorityPublicKey: ByteArray): Boolean =
        P256Verification.verify(signature.copyBytes(), authorityPublicKey, payload.signingInput())

    fun encode(): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to CborValue.Text("decision-refusal"),
        2uL to CborValue.Bytes(payload.encode()), 3uL to signature,
    )), limits)

    override fun toString() = "DecisionRefusalFrame(redacted)"

    companion object {
        const val CAPABILITY = 129uL
        const val MAXIMUM_BYTES = 384
        private val limits = CborLimits(MAXIMUM_BYTES, 1, 9)
        private val bodyLimits = CborLimits(256, 2, 21)

        fun decode(bytes: ByteArray): DecisionRefusalFrame {
            val fields = decodeFields(bytes, limits, 3u)
            require(fields[1u] == CborValue.Text("decision-refusal"))
            val body = decodeFields(data(fields[2u]), bodyLimits, 7u)
            val scope = (body[1u] as? CborValue.ArrayValue)?.values ?: invalid()
            require(scope.size == 4)
            val sequence = (body[3u] as? CborValue.Unsigned)?.value ?: invalid()
            val tag = (body[7u] as? CborValue.Unsigned)?.value
            val reason = Reason.entries.singleOrNull { it.tag == tag } ?: invalid()
            val payload = Payload(ChannelScope(data(scope[0]), data(scope[1]), data(scope[2]), data(scope[3])),
                data(body[2u]), sequence, data(body[4u]), data(body[5u]), data(body[6u]), reason)
            return DecisionRefusalFrame(payload, data(fields[3u])).also { require(it.encode().contentEquals(bytes)) }
        }

        private fun decodeFields(bytes: ByteArray, limits: CborLimits, lastKey: ULong): Map<ULong, CborValue> {
            val fields = (DeterministicCbor.decode(bytes, limits) as? CborValue.Fields)?.values ?: invalid()
            require(fields.keys == (0uL..lastKey).toSet() && fields[0u] == CborValue.Unsigned(1u))
            return fields
        }

        private fun data(value: CborValue?) = (value as? CborValue.Bytes)?.copyBytes() ?: invalid()
        private fun invalid(): Nothing = throw IllegalArgumentException("Invalid decision refusal")
    }
}
