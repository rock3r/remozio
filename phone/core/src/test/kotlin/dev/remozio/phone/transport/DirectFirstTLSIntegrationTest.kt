package dev.remozio.phone.transport

import dev.remozio.protocol.*
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.flowOf
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Test
import kotlin.test.*

class DirectFirstTLSIntegrationTest {
    private val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 })

    @Test fun authenticatesDirectOrFallsBackAfterPinAndScopeRejection(): Unit = runBlocking {
        val phone = HeldCertificate.Builder().commonName("synthetic-phone").ecdsa256().build()
        val mac = HeldCertificate.Builder().commonName("synthetic-mac").ecdsa256().build()
        val other = HeldCertificate.Builder().commonName("synthetic-other").ecdsa256().build()
        val phoneKeys = HandshakeCertificates.Builder().heldCertificate(phone).build()
        for (mode in 0..2) {
            Peer(if (mode == 1) other else mac, phone, wrongScope = mode == 2).use { direct ->
                Peer(mac, phone).use { relay ->
                    val owner = SupervisorJob()
                    var relayOpened = false
                    val connector = ApprovalChannelConnector(arrayOf(phoneKeys.keyManager), mac.certificate.publicKey.encoded,
                        scope, emptyList(), emptySet(), 1024)
                    var channel: NegotiatedTLSChannel? = null
                    try {
                        channel = withTimeout(10_000) {
                        connector.connect(CoroutineScope(owner), flowOf(ApprovalCarrierRoute { direct.open(it) }), ApprovalCarrierRoute {
                            relayOpened = true
                            direct.finished.await()
                            relay.open(it)
                        }, directTimeoutMillis = 5_000)
                        }
                        assertNotNull(channel.negotiated)
                        assertEquals(mode != 0, relayOpened)
                    } finally {
                        try { withTimeout(5_000) { channel?.closeAndJoin() } }
                        finally { owner.cancel(); withTimeout(5_000) { owner.join() } }
                    }
                    withTimeout(5_000) { if (mode == 0) direct.finished.await() else relay.finished.await() }
                }
            }
        }
    }

    private inner class Peer(certificate: HeldCertificate, phone: HeldCertificate, private val wrongScope: Boolean = false) : AutoCloseable {
        private val keys = HandshakeCertificates.Builder().heldCertificate(certificate).addTrustedCertificate(phone.certificate).build()
        private val listener = (keys.sslContext().serverSocketFactory.createServerSocket(0, 1,
            InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))) as SSLServerSocket).apply {
            needClientAuth = true
            enabledProtocols = arrayOf("TLSv1.3")
            sslParameters = sslParameters.apply { applicationProtocols = arrayOf("remozio/1") }
        }
        private val executor = Executors.newSingleThreadExecutor()
        @Volatile private var accepted: SSLSocket? = null
        val finished = CompletableDeferred<Unit>()
        init {
            executor.submit {
                try {
                    (listener.accept() as SSLSocket).use { socket ->
                        accepted = socket; socket.soTimeout = 6_000; socket.startHandshake()
                        val input = DataInputStream(socket.inputStream)
                        val output = DataOutputStream(socket.outputStream)
                        fun read(): ByteArray {
                            val count = input.readInt(); require(count in 1..65_536)
                            return ByteArray(count).also { input.readFully(it) }
                        }
                        fun write(bytes: ByteArray) { output.writeInt(bytes.size); output.write(bytes); output.flush() }
                        val peerScope = if (wrongScope) ChannelScope(ByteArray(16) { 9 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 }) else scope
                        val negotiation = ChannelNegotiation(ChannelOffer(ChannelRole.MAC, peerScope, ByteArray(32) { 7 }, setOf(1u), emptyList(), emptySet()), 1u)
                        try {
                            val offer = negotiation.offer()
                            val phoneOffer = read()
                            if (!wrongScope) negotiation.receiveOffer(phoneOffer)
                            write(offer)
                            if (!wrongScope) {
                                negotiation.receiveConfirmation(read())
                                write(negotiation.confirmation())
                            }
                            while (input.read() >= 0) { }
                        } finally { negotiation.close() }
                    }
                } catch (_: IOException) { }
                catch (failure: Throwable) { finished.completeExceptionally(failure) }
                finally { finished.complete(Unit) }
            }
        }
        suspend fun open(parent: CoroutineScope) = DirectTCPConnector().connect(parent, InetSocketAddress(listener.inetAddress, listener.localPort))
        override fun close() {
            listener.close(); accepted?.close(); executor.shutdownNow()
            check(executor.awaitTermination(7, TimeUnit.SECONDS))
        }
    }
}
