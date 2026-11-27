package dev.remozio.protocol

/** A phone report for Setup. Only the enrolled decision key can authenticate it. */
class PhoneRepairNoticeFrame(val scope: ChannelScope, val reason: Reason, signature: ByteArray) {
    enum class Reason(val tag: ULong) { LEGACY_POLICY(1u), BIOMETRIC_CHANGED(2u) }

    val signature = CborValue.Bytes(signature)
    init { require(signature.size == 64) }

    fun encode(): ByteArray = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u),
        1uL to CborValue.Text("phone-repair-notice"),
        2uL to scope.value,
        3uL to CborValue.Unsigned(reason.tag),
        4uL to signature,
    )), limits)

    fun verify(decisionPublicKey: ByteArray): Boolean =
        P256Verification.verify(signature.copyBytes(), decisionPublicKey, signingInput(scope, reason))

    override fun toString() = "PhoneRepairNoticeFrame(redacted)"

    companion object {
        const val CAPABILITY = 130uL
        const val MAXIMUM_BYTES = 256
        private val limits = CborLimits(MAXIMUM_BYTES, 2, 16)

        fun signingInput(scope: ChannelScope, reason: Reason): ByteArray =
            DeterministicCbor.encode(CborValue.Fields(mapOf(
                0uL to CborValue.Text("dev.remozio.phone-repair-notice"),
                1uL to CborValue.Unsigned(1u),
                2uL to scope.value,
                3uL to CborValue.Unsigned(reason.tag),
            )), limits)

        fun decode(bytes: ByteArray): PhoneRepairNoticeFrame {
            val fields = (DeterministicCbor.decode(bytes, limits) as? CborValue.Fields)?.values
                ?: throw IllegalArgumentException("Invalid phone repair notice")
            require(fields.keys == (0uL..4uL).toSet() && fields[0u] == CborValue.Unsigned(1u) &&
                fields[1u] == CborValue.Text("phone-repair-notice"))
            val values = (fields[2u] as? CborValue.ArrayValue)?.values
                ?: throw IllegalArgumentException("Invalid phone repair notice scope")
            require(values.size == 4)
            fun id(index: Int) = (values[index] as? CborValue.Bytes)?.copyBytes()
                ?: throw IllegalArgumentException("Invalid phone repair notice scope")
            val scope = ChannelScope(id(0), id(1), id(2), id(3))
            val reason = Reason.entries.singleOrNull { fields[3u] == CborValue.Unsigned(it.tag) }
                ?: throw IllegalArgumentException("Invalid phone repair notice reason")
            val signature = (fields[4u] as? CborValue.Bytes)?.copyBytes()
                ?: throw IllegalArgumentException("Invalid phone repair notice signature")
            return PhoneRepairNoticeFrame(scope, reason, signature).also { require(it.encode().contentEquals(bytes)) }
        }
    }
}
