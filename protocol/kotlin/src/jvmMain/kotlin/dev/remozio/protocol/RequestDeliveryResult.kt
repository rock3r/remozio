package dev.remozio.protocol

/** An advisory capture refusal on the live enrolled connection. It carries no request state. */
class RequestDeliveryResult(requestID: ByteArray, requestDigest: ByteArray, val reason: Reason) {
    enum class Reason(val tag: ULong) { UNREADABLE_CAPTURE(1u), CAPTURE_LIMIT(2u) }

    val requestID = CborValue.Bytes(requestID)
    val requestDigest = CborValue.Bytes(requestDigest)

    init { require(requestID.size == 16 && requestDigest.size == 32) }

    fun encode(): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to CborValue.Text("request-delivery-result"),
        2uL to requestID, 3uL to requestDigest, 4uL to CborValue.Unsigned(reason.tag),
    )), limits)

    override fun toString() = "RequestDeliveryResult(redacted)"

    companion object {
        /** Negotiated only in the live command offer. This is separate from issued request requirements. */
        const val CAPABILITY = 128uL
        const val MAXIMUM_BYTES = 128
        private val limits = CborLimits(MAXIMUM_BYTES, 1, 11)

        fun decode(bytes: ByteArray): RequestDeliveryResult {
            val fields = (DeterministicCbor.decode(bytes, limits) as? CborValue.Fields)?.values
                ?: throw IllegalArgumentException("Invalid request delivery result")
            require(fields.keys == (0uL..4uL).toSet() && fields[0u] == CborValue.Unsigned(1u) &&
                fields[1u] == CborValue.Text("request-delivery-result"))
            val id = (fields[2u] as? CborValue.Bytes)?.copyBytes()
                ?: throw IllegalArgumentException("Invalid request delivery result")
            val digest = (fields[3u] as? CborValue.Bytes)?.copyBytes()
                ?: throw IllegalArgumentException("Invalid request delivery result")
            val tag = (fields[4u] as? CborValue.Unsigned)?.value
            val reason = Reason.entries.singleOrNull { it.tag == tag }
                ?: throw IllegalArgumentException("Invalid request delivery result")
            return RequestDeliveryResult(id, digest, reason).also { require(it.encode().contentEquals(bytes)) }
        }
    }
}
