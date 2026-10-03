package dev.remozio.phone.transport

import okhttp3.tls.HeldCertificate
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import javax.security.auth.x500.X500Principal
import kotlin.test.*

class ClientTLSKeyManagerTest {
    private fun certificate(start: Long = System.currentTimeMillis() - 60_000, end: Long = System.currentTimeMillis() + 60_000): HeldCertificate {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        return HeldCertificate.Builder().keyPair(pair).commonName("synthetic-client").validityInterval(start, end).build()
    }

    @Test fun selectsOnlyAnEcClientIdentityForCompatibleIssuers() {
        val held = certificate()
        ClientTLSKeyManager(held.keyPair.private, arrayOf(held.certificate)).use { manager ->
            val alias = assertNotNull(manager.chooseEngineClientAlias(arrayOf("RSA", "EC"), null, null))
            assertEquals(alias, manager.chooseClientAlias(arrayOf("EC"), emptyArray(), null))
            assertContentEquals(arrayOf(alias), manager.getClientAliases("EC", arrayOf(held.certificate.issuerX500Principal)))
            assertNull(manager.getClientAliases("EC", arrayOf(X500Principal("CN=someone-else"))))
            assertNull(manager.chooseClientAlias(arrayOf("RSA"), null, null))
            assertNull(manager.chooseEngineClientAlias(null, null, null))
            assertNull(manager.getServerAliases("EC", null))
            assertNull(manager.chooseServerAlias("EC", null, null))
            assertNull(manager.chooseEngineServerAlias("EC", null, null))
            assertSame(held.keyPair.private, manager.getPrivateKey(alias))
            assertNull(manager.getPrivateKey("storage-alias"))
            assertNull(manager.getCertificateChain("storage-alias"))
        }
    }

    @Test fun copiesTheChainAndDropsReferencesOnClose() {
        val held = certificate()
        val other = certificate()
        val chain = arrayOf(held.certificate)
        val manager = ClientTLSKeyManager(held.keyPair.private, chain)
        val alias = assertNotNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
        chain[0] = other.certificate
        val returned = assertNotNull(manager.getCertificateChain(alias))
        assertContentEquals(held.certificate.encoded, returned[0].encoded)
        returned[0] = other.certificate
        assertContentEquals(held.certificate.encoded, assertNotNull(manager.getCertificateChain(alias))[0].encoded)
        manager.close(); manager.close()
        assertNull(manager.chooseClientAlias(arrayOf("EC"), null, null))
        assertNull(manager.chooseEngineClientAlias(arrayOf("EC"), null, null))
        assertNull(manager.getClientAliases("EC", null))
        assertNull(manager.getPrivateKey(alias))
        assertNull(manager.getCertificateChain(alias))
        assertEquals("ClientTLSKeyManager(redacted)", manager.toString())
    }

    @Test fun refusesExpiredAndFutureCertificates() {
        val now = System.currentTimeMillis()
        for (held in listOf(certificate(now - 120_000, now - 60_000), certificate(now + 60_000, now + 120_000))) {
            ClientTLSKeyManager(held.keyPair.private, arrayOf(held.certificate)).use {
                assertNull(it.chooseEngineClientAlias(arrayOf("EC"), null, null))
            }
        }
    }

    @Test fun rejectsInvalidChainsAndNonP256Keys() {
        val held = certificate()
        assertFailsWith<IllegalArgumentException> { ClientTLSKeyManager(held.keyPair.private, emptyArray()) }
        assertFailsWith<IllegalArgumentException> { ClientTLSKeyManager(held.keyPair.private, Array(9) { held.certificate }) }
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }.generateKeyPair()
        assertFailsWith<IllegalArgumentException> { p256TransportPin(pair.public.encoded) }
        val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        assertFailsWith<IllegalArgumentException> { ClientTLSKeyManager(rsa.private, arrayOf(held.certificate)) }
    }
}
