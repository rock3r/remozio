package dev.remozio.phone.enrollment

import dev.remozio.phone.transport.RelayAccessCredential
import dev.remozio.phone.transport.RelayEndpoint
import dev.remozio.phone.transport.p256TransportPin
import dev.remozio.protocol.CborValue

/** Local references only. Private keys never enter an enrollment archive. */
enum class EnrollmentKeyRole(val aliasPart: String) { TRANSPORT("transport"), DECISION("decision"), BIOMETRIC("biometric") }
class EnrollmentKeyReference(val role: EnrollmentKeyRole, keyID: ByteArray, val alias: String, publicKey: ByteArray) {
    val keyID = id(keyID)
    val publicKey = CborValue.Bytes(if (role == EnrollmentKeyRole.TRANSPORT) p256TransportPin(publicKey) else point(publicKey))
    init { require(Regex("remozio\\.${role.aliasPart}\\.v1\\.[0-9a-f]{32}").matches(alias)) }
    internal fun pointBytes() = publicKey.copyBytes().takeLast(65).toByteArray()
    override fun toString() = "EnrollmentKeyReference(redacted)"
}

/** Construct only from an authorized setup flow. Deserialization does not authenticate a peer or prove freshness. */
class PhoneEnrollment(
    recordID: ByteArray, macID: ByteArray, accountID: ByteArray, phoneID: ByteArray, epoch: ByteArray,
    val label: String, authorityPublicKey: ByteArray, transportPublicKey: ByteArray,
    val transportKey: EnrollmentKeyReference, val decisionKey: EnrollmentKeyReference, val biometricKey: EnrollmentKeyReference,
    enrollmentTag: ByteArray, val relayCredential: RelayAccessCredential?,
) {
    val recordID = id(recordID)
    val macID = id(macID)
    val accountID = id(accountID)
    val phoneID = id(phoneID)
    val epoch = id(epoch)
    val authorityPublicKey = CborValue.Bytes(point(authorityPublicKey))
    val transportPublicKey = CborValue.Bytes(p256TransportPin(transportPublicKey))
    val enrollmentTag = CborValue.Bytes(enrollmentTag)
    internal val scope get() = macID to accountID
    internal val keys get() = listOf(transportKey, decisionKey, biometricKey)
    init {
        require(label.length in 1..200 && label.none { it.code < 32 || it.code == 127 })
        require(enrollmentTag.size == 32)
        require(transportKey.role == EnrollmentKeyRole.TRANSPORT && decisionKey.role == EnrollmentKeyRole.DECISION && biometricKey.role == EnrollmentKeyRole.BIOMETRIC)
        require(keys.map { it.keyID }.toSet().size == 3 && keys.map { CborValue.Bytes(it.pointBytes()) }.toSet().size == 3)
        require(!authorityPublicKey.contentEquals(transportPublicKey.takeLast(65).toByteArray()))
    }
    override fun toString() = "PhoneEnrollment(redacted)"
}

enum class EnrollmentPhase { PREPARED, ACTIVE, REMOVED }
class StoredPhoneEnrollment(val enrollment: PhoneEnrollment, val phase: EnrollmentPhase) {
    /** Compares all connection material without exposing relay credentials. A display rename is not a trust change. */
    fun sameConnectionAs(other: StoredPhoneEnrollment): Boolean =
        (EnrollmentEncoding.encode(this) as CborValue.Fields).values.filterKeys { it != 5uL } ==
            (EnrollmentEncoding.encode(other) as CborValue.Fields).values.filterKeys { it != 5uL }

    override fun toString() = "StoredPhoneEnrollment($phase)"
}

internal fun id(bytes: ByteArray): CborValue.Bytes { require(bytes.size == 16); return CborValue.Bytes(bytes) }
private fun point(bytes: ByteArray): ByteArray {
    require(bytes.size == 65 && bytes[0] == 4.toByte())
    val prefix = byteArrayOf(0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86.toByte(),0x48,0xce.toByte(),0x3d,0x02,0x01,0x06,0x08,0x2a,0x86.toByte(),0x48,0xce.toByte(),0x3d,0x03,0x01,0x07,0x03,0x42,0x00)
    p256TransportPin(prefix + bytes)
    return bytes.copyOf()
}

internal object EnrollmentEncoding {
    fun encode(row: StoredPhoneEnrollment): CborValue {
        val e = row.enrollment
        fun key(k: EnrollmentKeyReference) = CborValue.Fields(mapOf(0uL to k.keyID, 1uL to CborValue.Text(k.alias), 2uL to k.publicKey))
        val relay = e.relayCredential?.let { c -> CborValue.Fields(mapOf(
            0uL to CborValue.Text(c.endpoint.host), 1uL to CborValue.Unsigned(c.endpoint.port.toULong()),
            2uL to CborValue.Text(c.endpoint.path), 3uL to CborValue.Text(c.clientId), 4uL to CborValue.Text(c.clientSecret))) } ?: CborValue.Null
        return CborValue.Fields(mapOf(
            0uL to e.recordID, 1uL to e.macID, 2uL to e.accountID, 3uL to e.phoneID, 4uL to e.epoch,
            5uL to CborValue.Text(e.label), 6uL to e.authorityPublicKey, 7uL to e.transportPublicKey,
            8uL to key(e.transportKey), 9uL to key(e.decisionKey), 10uL to key(e.biometricKey),
            11uL to e.enrollmentTag, 12uL to relay, 13uL to CborValue.Unsigned(when (row.phase) { EnrollmentPhase.PREPARED -> 0uL; EnrollmentPhase.ACTIVE -> 1uL; EnrollmentPhase.REMOVED -> 2uL }),
        ))
    }
    fun decode(value: CborValue): StoredPhoneEnrollment {
        val f = fields(value, 13)
        fun key(index: ULong, role: EnrollmentKeyRole): EnrollmentKeyReference {
            val k = fields(f.getValue(index), 2)
            return EnrollmentKeyReference(role, bytes(k, 0u), text(k, 1u), bytes(k, 2u))
        }
        val relay = if (f[12u] == CborValue.Null) null else {
            val r = fields(f.getValue(12u), 4)
            val port = uint(r, 1u); require(port in 1u..65_535u)
            RelayAccessCredential(RelayEndpoint(text(r, 0u), port.toInt(), text(r, 2u)), text(r, 3u), text(r, 4u))
        }
        val phase = when (uint(f, 13u)) { 0uL -> EnrollmentPhase.PREPARED; 1uL -> EnrollmentPhase.ACTIVE; 2uL -> EnrollmentPhase.REMOVED; else -> throw IllegalArgumentException() }
        return StoredPhoneEnrollment(PhoneEnrollment(bytes(f, 0u), bytes(f, 1u), bytes(f, 2u), bytes(f, 3u), bytes(f, 4u),
            text(f, 5u), bytes(f, 6u), bytes(f, 7u), key(8u, EnrollmentKeyRole.TRANSPORT), key(9u, EnrollmentKeyRole.DECISION),
            key(10u, EnrollmentKeyRole.BIOMETRIC), bytes(f, 11u), relay), phase)
    }
    internal fun fields(value: CborValue, last: Int): Map<ULong, CborValue> {
        val fields = (value as? CborValue.Fields)?.values ?: throw IllegalArgumentException()
        require(fields.keys == (0..last).map { it.toULong() }.toSet())
        return fields
    }
    internal fun uint(f: Map<ULong, CborValue>, k: ULong) = (f[k] as? CborValue.Unsigned)?.value ?: throw IllegalArgumentException()
    private fun bytes(f: Map<ULong, CborValue>, k: ULong) = (f[k] as? CborValue.Bytes)?.copyBytes() ?: throw IllegalArgumentException()
    private fun text(f: Map<ULong, CborValue>, k: ULong) = (f[k] as? CborValue.Text)?.value ?: throw IllegalArgumentException()
}
