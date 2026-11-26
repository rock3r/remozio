package dev.sebastiano.remozio.android.transport

import dev.remozio.phone.transport.ClientTLSKeyManager
import java.io.IOException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.fail
import org.junit.Test

class TransportLeafRenewalTest {
    private val created = Instant.parse("2026-11-01T12:00:00Z")
    private val identity = pair()
    private val original = arrayOf(parse(issue(created)))
    private val expiry = original.first().notAfter.toInstant()

    private fun pair() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
    private fun issue(at: Instant, signer: KeyPair = identity) = issueTransportLeaf(signer.private, signer.public, at)
    private fun parse(bytes: ByteArray) = CertificateFactory.getInstance("X.509")
        .generateCertificate(bytes.inputStream()) as X509Certificate

    @Test fun aLeafOutsideTheRenewalWindowDoesNotWrite() {
        val now = expiry.minus(30, ChronoUnit.DAYS).minusSeconds(1)
        val chosen = selectTransportLeaf(original, identity.public, now, { null },
            issue = { fail("Renewal started too early") }, write = { fail("Storage changed too early") })
        assertSame(original, chosen)
    }

    @Test fun renewsAtTheBoundaryWithTheSamePublicKeyAndReusesTheRetainedLeaf() {
        val now = expiry.minus(30, ChronoUnit.DAYS)
        var stored: ByteArray? = null
        val renewed = selectTransportLeaf(original, identity.public, now, { stored }, { issue(now) }, { stored = it }).single()
        assertContentEquals(identity.public.encoded, renewed.publicKey.encoded)
        assertEquals(now.plus(365, ChronoUnit.DAYS), renewed.notAfter.toInstant())
        renewed.verify(identity.public)
        assertContentEquals(renewed.encoded, stored)
        val reopened = selectTransportLeaf(original, identity.public, now.plusSeconds(1), { stored },
            { fail("Renewed leaf was ignored") }, { fail("Renewed leaf was rewritten") })
        assertContentEquals(renewed.encoded, reopened.single().encoded)
    }

    @Test fun expiredCertificateCanRenewWithoutOfferingAnExpiredLeaf() {
        val now = Instant.now()
        val expired = arrayOf(parse(issue(now.minus(365, ChronoUnit.DAYS).minusSeconds(2))))
        val renewed = selectTransportLeaf(expired, identity.public, now, { null }, { issue(now) }, {})
        ClientTLSKeyManager(identity.private, expired).use { assertNull(it.getClientAliases("EC", null)) }
        ClientTLSKeyManager(identity.private, renewed).use { assertNotNull(it.getClientAliases("EC", null)) }
        assertContentEquals(identity.public.encoded, renewed.single().publicKey.encoded)
    }

    @Test fun onlyUnusableLeafIssuanceAfterExpiryRequiresRecovery() {
        val renewalFailure: () -> ByteArray = { throw IOException("Signer unavailable") }
        val before = expiry.minusSeconds(1)
        assertSame(original, selectTransportLeaf(original, identity.public, before, { null }, renewalFailure,
            { fail("Issuance failed before the write") }))
        assertFailsWith<TransportCertificateRecoveryRequired> {
            selectTransportLeaf(original, identity.public, expiry.plusSeconds(1), { null }, renewalFailure,
                { fail("Issuance failed before the write") })
        }
    }

    @Test fun renewalWriteFailurePreservesValidOriginalAndFailsAfterExpiry() {
        val rejectedWrite: (ByteArray) -> Unit = { throw IOException("Synthetic persistence failure") }
        val before = expiry.minusSeconds(1)
        assertSame(original, selectTransportLeaf(original, identity.public, before, { null }, { issue(before) }, rejectedWrite))
        val after = expiry.plusSeconds(1)
        assertFailsWith<IOException> {
            selectTransportLeaf(original, identity.public, after, { null }, { issue(after) }, rejectedWrite)
        }
    }

    @Test fun rejectsWrongPinAndTamperedSignatureBeforePersisting() {
        val now = expiry.minusSeconds(1)
        val tampered = issue(now).also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        for (untrusted in listOf(issue(now, pair()), tampered)) {
            val chosen = selectTransportLeaf(original, identity.public, now, { untrusted }, { untrusted },
                { fail("An invalid leaf was saved") })
            assertSame(original, chosen)
        }
    }

    @Test fun aSignedReplacementWithAnAdditionalNoncriticalExtensionIsRejected() {
        fun fixture(name: String) = checkNotNull(javaClass.getResourceAsStream("/transport-leaf/$name")).use { it.readBytes() }
        val original = arrayOf(parse(fixture("original.der")))
        val additional = fixture("extra.der")
        val cert = parse(additional)
        val publicKey = original.single().publicKey
        val now = cert.notBefore.toInstant().plusSeconds(300)
        cert.verify(publicKey)
        assertContentEquals(publicKey.encoded, cert.publicKey.encoded)
        assertEquals(setOf("2.5.29.37", "1.3.6.1.4.1.32473.1"), cert.nonCriticalExtensionOIDs)
        val fallback = selectTransportLeaf(original, publicKey, now, { additional }, { additional },
            { fail("The extra extension was persisted") })
        assertSame(original, fallback)
    }

    @Test fun rejectsRenewalWhenTheClockIsBeforeTheOriginalLeaf() {
        val earlier = original.single().notBefore.toInstant().minusSeconds(1)
        assertFailsWith<IllegalArgumentException> {
            selectTransportLeaf(original, identity.public, earlier, { fail("Read under an invalid clock") },
                { fail("Issued under an invalid clock") }, { fail("Wrote under an invalid clock") })
        }
    }

    @Test fun theLeafIsUsableAcrossTheUtcTimeEncodingBoundary() {
        val now = Instant.parse("2049-06-01T12:00:00Z")
        val audited = parse(issue(now))
        audited.checkValidity(java.util.Date.from(now))
        audited.verify(identity.public)
        assertEquals(now.plus(365, ChronoUnit.DAYS), audited.notAfter.toInstant())
    }
}
