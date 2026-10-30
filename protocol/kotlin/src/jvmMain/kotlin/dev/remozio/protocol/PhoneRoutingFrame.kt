package dev.remozio.protocol

enum class PhoneRoutingFailure(val tag: ULong) { UNAVAILABLE(0u), INCOMPATIBLE(1u) }

/** Bounded carrier for the dedicated enrolled channel. Parsing never establishes current routing or action authority. */
sealed class PhoneRoutingFrame(queryNonce: ByteArray) {
    val queryNonce = CborValue.Bytes(queryNonce)
    init { require(this.queryNonce.size == 32) }
    class Status(queryNonce: ByteArray) : PhoneRoutingFrame(queryNonce)
    class Challenge(queryNonce: ByteArray, val expectedRevision: ULong) : PhoneRoutingFrame(queryNonce)
    class Apply(queryNonce: ByteArray, canonicalControl: ByteArray, signature: ByteArray) : PhoneRoutingFrame(queryNonce) {
        val canonicalControl = CborValue.Bytes(canonicalControl)
        val signature = CborValue.Bytes(signature)
        init { require(this.signature.size == 64); RoutingAwayControl.decode(this.canonicalControl.copyBytes(), CONTROL_LIMITS) }
    }
    class Response(queryNonce: ByteArray, canonicalPayload: ByteArray, signature: ByteArray) : PhoneRoutingFrame(queryNonce) {
        val canonicalPayload = CborValue.Bytes(canonicalPayload)
        val signature = CborValue.Bytes(signature)
        init { require(this.signature.size == 64 && RoutingStatusResponse.decode(this.canonicalPayload.copyBytes()).queryNonce == this.queryNonce) }
    }
    class Failure(queryNonce: ByteArray, val reason: PhoneRoutingFailure) : PhoneRoutingFrame(queryNonce)
    fun encode(): ByteArray {
        val (kind, payload) = when (this) {
            is Status -> 0uL to CborValue.Null
            is Challenge -> 1uL to CborValue.Unsigned(expectedRevision)
            is Apply -> 2uL to CborValue.ArrayValue(listOf(canonicalControl, signature))
            is Response -> 3uL to CborValue.ArrayValue(listOf(canonicalPayload, signature))
            is Failure -> 4uL to CborValue.Unsigned(reason.tag)
        }
        return DeterministicCbor.encode(CborValue.Fields(mapOf(0uL to CborValue.Text(DOMAIN), 1uL to CborValue.Unsigned(1u),
            2uL to CborValue.Unsigned(kind), 3uL to queryNonce, 4uL to payload)), LIMITS)
    }
    override fun toString() = "PhoneRoutingFrame(redacted)"
    companion object {
        const val APPLICATION_PROTOCOL = "remozio-routing/1"
        const val MAXIMUM_BYTES = 4096
        private const val DOMAIN = "dev.remozio.phone.routing"
        private val LIMITS = CborLimits(MAXIMUM_BYTES, 3, 20)
        private val CONTROL_LIMITS = CborLimits(1024, 2, 32)
        fun decode(bytes: ByteArray): PhoneRoutingFrame {
            val f = (DeterministicCbor.decode(bytes, LIMITS) as? CborValue.Fields)?.values ?: throw IllegalArgumentException("Invalid routing frame")
            require(f.keys == (0uL..4uL).toSet() && f[0u] == CborValue.Text(DOMAIN) && f[1u] == CborValue.Unsigned(1u))
            val nonce = (f[3u] as CborValue.Bytes).copyBytes(); val payload = f.getValue(4u)
            fun pair(): List<ByteArray> {
                val fields = (payload as CborValue.ArrayValue).values; require(fields.size == 2)
                return fields.map { (it as CborValue.Bytes).copyBytes() }
            }
            val frame = when ((f[2u] as CborValue.Unsigned).value) {
                0uL -> { require(payload == CborValue.Null); Status(nonce) }
                1uL -> Challenge(nonce, (payload as CborValue.Unsigned).value)
                2uL -> pair().let { Apply(nonce, it[0], it[1]) }
                3uL -> pair().let { Response(nonce, it[0], it[1]) }
                4uL -> Failure(nonce, PhoneRoutingFailure.entries.single { CborValue.Unsigned(it.tag) == payload })
                else -> throw IllegalArgumentException("Unsupported routing frame")
            }
            require(frame.encode().contentEquals(bytes)); return frame
        }
    }
}
