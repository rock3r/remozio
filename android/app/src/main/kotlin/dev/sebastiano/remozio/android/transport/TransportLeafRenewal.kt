package dev.sebastiano.remozio.android.transport

import java.math.BigInteger
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import java.util.Date
import javax.security.auth.x500.X500Principal

internal const val TRANSPORT_LEAF_MAX_BYTES = 8192
internal const val TRANSPORT_LEAF_LIFETIME_DAYS = 365L
private const val RENEWAL_WINDOW_DAYS = 30L

/** A renewed leaf changes neither the enrolled key nor the Mac's revocation decision. */
internal fun selectTransportLeaf(
    original: Array<X509Certificate>,
    enrolledKey: PublicKey,
    now: Instant,
    read: () -> ByteArray?,
    issue: () -> ByteArray,
    write: (ByteArray) -> Unit,
): Array<X509Certificate> {
    val initial = original.first()
    require(initial.publicKey.encoded.contentEquals(enrolledKey.encoded))
    // A clock before creation cannot establish that the existing leaf has reached its renewal window.
    require(!now.isBefore(initial.notBefore.toInstant()))
    val retained = try { read()?.let { validatedTransportLeaf(it, enrolledKey, now) } }
        catch (_: Exception) { null }
    val current = if (retained != null && retained.notAfter.after(initial.notAfter)) arrayOf(retained) else original
    val cutoff = now.plus(RENEWAL_WINDOW_DAYS, ChronoUnit.DAYS)
    if (current.first().notAfter.toInstant().isAfter(cutoff)) return current
    return try {
        val encoded = issue()
        val leaf = validatedTransportLeaf(encoded, enrolledKey, now)
        require(leaf.notAfter.after(current.first().notAfter))
        write(encoded)
        arrayOf(leaf)
    } catch (failure: Exception) {
        if (now.isAfter(current.first().notAfter.toInstant())) throw failure
        current
    }
}

private fun validatedTransportLeaf(bytes: ByteArray, key: PublicKey, now: Instant): X509Certificate {
    require(bytes.size in 1..TRANSPORT_LEAF_MAX_BYTES)
    val cert = CertificateFactory.getInstance("X.509")
        .generateCertificate(bytes.inputStream()) as X509Certificate
    require(cert.encoded.contentEquals(bytes) && cert.publicKey.encoded.contentEquals(key.encoded))
    require(cert.version == 3 && cert.issuerX500Principal == cert.subjectX500Principal && cert.basicConstraints == -1)
    val usage = checkNotNull(cert.keyUsage)
    require(usage.firstOrNull() == true && usage.drop(1).none { it })
    require(cert.extendedKeyUsage == listOf("1.3.6.1.5.5.7.3.2"))
    require(cert.criticalExtensionOIDs == setOf("2.5.29.19", "2.5.29.15"))
    require(cert.sigAlgOID == "1.2.840.10045.4.3.2")
    cert.checkValidity(Date.from(now))
    cert.verify(key)
    return cert
}

/** Encodes a single self-signed TLS client leaf. The caller supplies the existing non-exportable signing key. */
internal fun issueTransportLeaf(
    key: PrivateKey,
    publicKey: PublicKey,
    now: Instant,
    serial: BigInteger = BigInteger(128, SecureRandom()).setBit(127),
): ByteArray {
    require(key.algorithm == "EC" && publicKey.algorithm == "EC" && publicKey.encoded.size == 91)
    require(serial.signum() > 0 && serial.toByteArray().size <= 20)
    val time = now.truncatedTo(ChronoUnit.SECONDS)
    val name = X500Principal("CN=Remozio Transport").encoded
    val algorithm = sequence(der(0x06, byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 4, 3, 2)))
    val restrictions = extension(byteArrayOf(0x55, 0x1d, 0x13), sequence(), critical = true)
    val usage = extension(byteArrayOf(0x55, 0x1d, 0x0f), der(0x03, byteArrayOf(7, 0x80.toByte())), critical = true)
    val clientAuth = sequence(der(0x06, byteArrayOf(0x2b, 6, 1, 5, 5, 7, 3, 2)))
    val extendedUsage = extension(byteArrayOf(0x55, 0x1d, 0x25), clientAuth, critical = false)
    val validity = sequence(certificateTime(time.minusSeconds(300)),
        certificateTime(time.plus(TRANSPORT_LEAF_LIFETIME_DAYS, ChronoUnit.DAYS)))
    val tbs = sequence(der(0xa0, der(0x02, byteArrayOf(2))), der(0x02, serial.toByteArray()),
        algorithm, name, validity, name, publicKey.encoded, der(0xa3, sequence(restrictions, usage, extendedUsage)))
    val signed = Signature.getInstance("SHA256withECDSA").run { initSign(key); update(tbs); sign() }
    return sequence(tbs, algorithm, der(0x03, byteArrayOf(0) + signed))
}

private fun extension(oid: ByteArray, value: ByteArray, critical: Boolean): ByteArray {
    val id = der(0x06, oid)
    val wrapped = der(0x04, value)
    return if (critical) sequence(id, der(0x01, byteArrayOf(-1)), wrapped) else sequence(id, wrapped)
}

private val utcTime = DateTimeFormatter.ofPattern("uuMMddHHmmss'Z'").withZone(ZoneOffset.UTC)
private val generalizedTime = DateTimeFormatter.ofPattern("uuuuMMddHHmmss'Z'").withZone(ZoneOffset.UTC)

private fun certificateTime(value: Instant): ByteArray {
    val utc = value.atZone(ZoneOffset.UTC).year in 1950..2049
    return der(if (utc) 0x17 else 0x18, (if (utc) utcTime else generalizedTime).format(value).encodeToByteArray())
}

private fun sequence(vararg fields: ByteArray): ByteArray {
    val bytes = ByteArray(fields.sumOf { it.size })
    var offset = 0
    for (field in fields) {
        field.copyInto(bytes, offset)
        offset += field.size
    }
    return der(0x30, bytes)
}

private fun der(tag: Int, value: ByteArray): ByteArray {
    val length = value.size
    require(length <= 65_535)
    val header = when {
        length < 128 -> byteArrayOf(tag.toByte(), length.toByte())
        length < 256 -> byteArrayOf(tag.toByte(), 0x81.toByte(), length.toByte())
        else -> byteArrayOf(tag.toByte(), 0x82.toByte(), (length shr 8).toByte(), length.toByte())
    }
    return header + value
}
