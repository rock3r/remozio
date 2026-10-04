package dev.remozio.phone.transport

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlinx.coroutines.*
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Test
import kotlin.test.*

class DirectTCPConnectorTest {
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val endpoint = InetSocketAddress(loopback, 12345)

    @Test fun preservesTheByteStreamWithBoundedReadChunks(): Unit = runBlocking {
        val payload = ByteArray(65_537) { (it * 31).toByte() }
        Peer { socket ->
            assertContentEquals(payload, socket.inputStream.readNBytes(payload.size))
            socket.outputStream.write(payload)
        }.use { peer ->
            val owner = SupervisorJob()
            val carrier = DirectTCPConnector().connect(CoroutineScope(owner), peer.endpoint, maximumMessageBytes = 127)
            try {
                payload.asList().chunked(127).forEach { carrier.send(it.toByteArray()) }
                val received = mutableListOf<Byte>()
                withTimeout(5_000) {
                    while (true) {
                        val chunk = carrier.receive() ?: break
                        assertTrue(chunk.size in 1..127)
                        received.addAll(chunk.toList())
                    }
                }
                assertContentEquals(payload, received.toByteArray())
                peer.finished.await()
            } finally { carrier.close(); withTimeout(5_000) { carrier.awaitClosed() }; owner.cancel() }
        }
    }

    @Test fun parentCancellationClosesAnIdleSocketAndRejectsFurtherIo(): Unit = runBlocking {
        Peer { assertEquals(-1, it.inputStream.read()) }.use { peer ->
            val owner = SupervisorJob()
            val carrier = DirectTCPConnector().connect(CoroutineScope(owner), peer.endpoint)
            owner.cancel()
            withTimeout(5_000) { carrier.awaitClosed(); owner.join(); peer.finished.await() }
            assertFailsWith<IOException> { carrier.receive() }
            assertFailsWith<IOException> { carrier.send(byteArrayOf(1)) }
        }
    }

    @Test fun cancellingAReceiveClosesTheConnection(): Unit = runBlocking {
        Peer { assertEquals(-1, it.inputStream.read()) }.use { peer ->
            val owner = SupervisorJob()
            val carrier = DirectTCPConnector().connect(CoroutineScope(owner), peer.endpoint)
            try {
                val read = launch(start = CoroutineStart.UNDISPATCHED) { carrier.receive() }
                read.cancelAndJoin()
                withTimeout(5_000) { carrier.awaitClosed(); peer.finished.await() }
            } finally { carrier.close(); owner.cancel() }
        }
    }

    @Test fun stalledConnectIsReleasedByDeadlineCallerAndParentCancellation(): Unit = runBlocking {
        for (mode in 0..2) {
            val socket = BlockingSocket(blockConnect = true)
            val owner = SupervisorJob()
            val attempt = async {
                runCatching { DirectTCPConnector { socket }.connect(CoroutineScope(owner), endpoint, timeoutMillis = if (mode == 0) 1_000 else 5_000) }
            }
            try {
                withTimeout(5_000) { socket.entered.await() }
                if (mode == 1) attempt.cancel()
                if (mode == 2) owner.cancel()
                withTimeout(5_000) { attempt.join() }
                if (mode == 0) assertIs<IOException>(attempt.await().exceptionOrNull())
                assertTrue(socket.wasClosed)
            } finally { attempt.cancel(); owner.cancel(); withTimeout(5_000) { owner.join() } }
        }
    }

    @Test fun parentCancellationBeforeSetupStartsStillReleasesTheSocket(): Unit = runBlocking {
        val owner = SupervisorJob()
        val socket = BlockingSocket(blockConnect = true)
        val connector = DirectTCPConnector { owner.cancel(); socket }
        withTimeout(5_000) {
            assertFailsWith<CancellationException> { connector.connect(CoroutineScope(owner), endpoint) }
            owner.join()
        }
        assertTrue(socket.wasClosed)
        assertFalse(socket.entered.isCompleted)
    }

    @Test fun cancellationReleasesABlockedNativeWrite(): Unit = runBlocking {
        val socket = BlockingSocket(blockConnect = false)
        val owner = SupervisorJob()
        val carrier = DirectTCPConnector { socket }.connect(CoroutineScope(owner), endpoint)
        try {
            val write = launch { carrier.send(ByteArray(32_768)) }
            withTimeout(5_000) { socket.entered.await() }
            write.cancelAndJoin()
            withTimeout(5_000) { carrier.awaitClosed() }
            assertTrue(socket.wasClosed)
        } finally { carrier.close(); owner.cancel() }
    }

    @Test fun rejectsUnresolvedWildcardMulticastAndInvalidLimitsBeforeOpeningASocket(): Unit = runBlocking {
        val owner = SupervisorJob()
        var creations = 0
        val connector = DirectTCPConnector { creations++; Socket() }
        try {
            for (address in listOf(InetSocketAddress.createUnresolved("unresolved.invalid", 12345),
                InetSocketAddress(12345), InetSocketAddress(InetAddress.getByAddress(byteArrayOf(224.toByte(), 0, 0, 1)), 12345))) {
                assertFailsWith<IllegalArgumentException> { connector.connect(CoroutineScope(owner), address) }
            }
            assertFailsWith<IllegalArgumentException> { connector.connect(CoroutineScope(owner), endpoint, maximumMessageBytes = 32769) }
            assertFailsWith<IllegalArgumentException> { connector.connect(CoroutineScope(owner), endpoint, queueCapacity = 65) }
            owner.cancel()
            assertFailsWith<CancellationException> { connector.connect(CoroutineScope(owner), endpoint) }
            assertEquals(0, creations)
        } finally { owner.cancel() }
    }

    @Test fun pinnedTlsAuthenticatesTheDirectPeerAndRejectsTheWrongPin(): Unit = runBlocking {
        val serverCert = HeldCertificate.Builder().commonName("synthetic-mac").ecdsa256().build()
        val phoneCert = HeldCertificate.Builder().commonName("synthetic-phone").ecdsa256().build()
        val serverKeys = HandshakeCertificates.Builder().heldCertificate(serverCert).addTrustedCertificate(phoneCert.certificate).build()
        val phoneKeys = HandshakeCertificates.Builder().heldCertificate(phoneCert).build()
        for (wrongPin in listOf(false, true)) {
            val listener = serverKeys.sslContext().serverSocketFactory.createServerSocket(0, 1, loopback) as SSLServerSocket
            listener.needClientAuth = true
            listener.enabledProtocols = arrayOf("TLSv1.3")
            listener.sslParameters = listener.sslParameters.apply { applicationProtocols = arrayOf("remozio/1") }
            Peer(listener) { socket ->
                try {
                    (socket as SSLSocket).startHandshake()
                    if (!wrongPin) {
                        assertEquals("remozio/1", socket.applicationProtocol)
                        assertContentEquals(byteArrayOf(10, 20, 30), socket.inputStream.readNBytes(3))
                        socket.outputStream.write(byteArrayOf(40, 50))
                    }
                } catch (failure: IOException) { if (!wrongPin) throw failure }
            }.use { peer ->
                val owner = SupervisorJob()
                val carrier = DirectTCPConnector().connect(CoroutineScope(owner), peer.endpoint)
                val pin = if (wrongPin) phoneCert.certificate.publicKey.encoded else serverCert.certificate.publicKey.encoded
                val engine = PinnedTLSClient(arrayOf(phoneKeys.keyManager), pin, "remozio/1", 1_048_576)
                val session = TLSRecordSession(CoroutineScope(owner), engine, carrier)
                try {
                    withTimeout(5_000) {
                        if (wrongPin) assertFailsWith<IOException> { session.awaitOpen() }
                        else {
                            session.awaitOpen()
                            session.send(byteArrayOf(10, 20, 30))
                            val received = mutableListOf<Byte>()
                            while (received.size < 2) received.addAll(assertNotNull(session.receive()).toList())
                            assertContentEquals(byteArrayOf(40, 50), received.toByteArray())
                        }
                        peer.finished.await()
                    }
                } finally { withTimeout(5_000) { session.closeAndJoin() }; owner.cancel() }
            }
        }
    }

    private class BlockingSocket(private val blockConnect: Boolean) : Socket() {
        val entered = CompletableDeferred<Unit>()
        private val released = CountDownLatch(1)
        @Volatile var wasClosed = false
        private fun block(): Nothing {
            entered.complete(Unit)
            check(released.await(7, TimeUnit.SECONDS))
            throw IOException("synthetic closed socket")
        }
        override fun connect(endpoint: SocketAddress?, timeout: Int) { if (blockConnect) block() }
        override fun getInputStream() = object : InputStream() {
            override fun read(): Int { check(released.await(7, TimeUnit.SECONDS)); throw IOException("synthetic closed socket") }
        }
        override fun getOutputStream() = object : OutputStream() { override fun write(value: Int) { block() } }
        override fun close() { wasClosed = true; released.countDown() }
    }

    private class Peer(val listener: ServerSocket = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")), action: (Socket) -> Unit) : AutoCloseable {
        val endpoint = InetSocketAddress(listener.inetAddress, listener.localPort)
        val finished = CompletableDeferred<Unit>()
        @Volatile private var accepted: Socket? = null
        private val executor = Executors.newSingleThreadExecutor()
        init {
            executor.submit {
                try {
                    listener.accept().use { socket -> accepted = socket; socket.soTimeout = 6_000; action(socket) }
                    finished.complete(Unit)
                } catch (failure: Throwable) { finished.completeExceptionally(failure) }
            }
        }
        override fun close() {
            listener.close(); accepted?.close(); executor.shutdownNow()
            check(executor.awaitTermination(7, TimeUnit.SECONDS))
        }
    }
}
