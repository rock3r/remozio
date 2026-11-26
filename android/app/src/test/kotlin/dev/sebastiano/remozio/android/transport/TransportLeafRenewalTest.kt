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
