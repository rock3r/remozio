package dev.remozio.phone.transport

import java.net.Socket
import java.security.KeyPairGenerator
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLException
import javax.net.ssl.X509KeyManager
import org.junit.Assert.*
import org.junit.Test

class PinnedTLSClientTest {
    private val pin = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair().public.encoded
    private val noIdentity = object : X509KeyManager {
        override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null
        override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?): String? = null
        override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null
        override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String? = null
        override fun getCertificateChain(alias: String?): Array<X509Certificate>? = null
        override fun getPrivateKey(alias: String?): PrivateKey? = null
    }
    private fun client(budget: Int = 65_536) = PinnedTLSClient(arrayOf<KeyManager>(noIdentity), pin, "remozio-test/1", budget)

    @Test fun rejectsMalformedPinsAndProfileConfiguration() {
        for (badPin in listOf(byteArrayOf(), ByteArray(257), pin + byteArrayOf(0))) {
            assertThrows(Exception::class.java) { PinnedTLSClient(arrayOf(noIdentity), badPin, "test/1", 1000) }
        }
        for (protocol in listOf("", "has space", "x".repeat(256), "é")) {
            assertThrows(IllegalArgumentException::class.java) { PinnedTLSClient(arrayOf(noIdentity), pin, protocol, 1000) }
        }
        for (budget in listOf(0, -1, 1_048_577)) assertThrows(IllegalArgumentException::class.java) { client(budget) }
        assertThrows(IllegalArgumentException::class.java) { PinnedTLSClient(emptyArray(), pin, "test/1", 1000) }
    }

    @Test fun startProducesOnlyCiphertextAndCannotRepeat() {
        client().use { engine ->
            assertEquals(TLSClientState.NEW, engine.state())
            assertThrows(IllegalStateException::class.java) { engine.send(byteArrayOf(1)) }
            val batch = engine.start()
            assertEquals(TLSClientState.HANDSHAKING, batch.state)
            assertEquals(0, batch.consumedPlaintextBytes)
            assertFalse(batch.encrypted.isEmpty())
            assertTrue(batch.plaintext.isEmpty())
            assertEquals("TLSClientProgress(HANDSHAKING, redacted)", batch.toString())
            assertThrows(IllegalStateException::class.java) { engine.start() }
            assertEquals(TLSClientState.HANDSHAKING, engine.state())
        }
    }

    @Test fun oversizedInputAndHandshakeBudgetFailClosed() {
        client(1).use { engine ->
            assertThrows(SSLException::class.java) { engine.start() }
            assertEquals(TLSClientState.FAILED, engine.state())
        }
        client().use { engine ->
            engine.start()
            assertThrows(SSLException::class.java) { engine.receive(ByteArray(32_769)) }
            assertEquals(TLSClientState.FAILED, engine.state())
            assertThrows(IllegalStateException::class.java) { engine.receive(byteArrayOf()) }
        }
    }

    @Test fun eofFailsAndCloseIsIdempotent() {
        val engine = client()
        engine.start()
        assertThrows(SSLException::class.java) { engine.endOfInput() }
        assertEquals(TLSClientState.FAILED, engine.state())
        engine.close(); engine.close()
        assertEquals(TLSClientState.CLOSED, engine.state())
        assertThrows(IllegalStateException::class.java) { engine.start() }
    }
}
