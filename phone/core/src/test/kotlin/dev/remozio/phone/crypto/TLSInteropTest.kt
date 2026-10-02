package dev.remozio.phone.crypto

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.int
import org.junit.Assert.*
import org.junit.Test

/** Disposable keys and loopback sockets only. This is not an Android Keystore or production relay test. */
class TLSInteropTest {
    @Test fun mutualTLS13PreservesPayloadThroughFragmentingOpaqueRelay(): Unit = Fixture().use { f ->
        for (payload in listOf(ByteArray(0), "synthetic-remozio-private-request-contents".repeat(1_500).toByteArray())) {
            Relay(f.port).use { relay ->
                f.connect(relay.port).use { socket ->
                    socket.startHandshake()
                    assertEquals("TLSv1.3", socket.session.protocol)
                    assertEquals("remozio-experiment/1", socket.applicationProtocol)
                    assertArrayEquals(payload, exchange(socket, payload))
                }
                if (payload.isNotEmpty()) {
                    val captured = relay.capture()
                    assertTrue(captured.size > payload.size)
                    assertFalse(String(captured, Charsets.ISO_8859_1).contains("synthetic-remozio-private-request-contents"))
                }
            }
        }
    }

    @Test fun wrongServerPinFailsBeforeApplicationData(): Unit = Fixture().use { f ->
        f.connect(f.port, serverPin = f.phone.certificate).use { socket ->
            assertThrows(IOException::class.java) { socket.startHandshake() }
        }
    }

    @Test fun wrongOrMissingClientIdentityCannotReceiveAnEcho(): Unit = Fixture().use { f ->
        for (identity in listOf(f.mac, null)) {
            f.connect(f.port, identity = identity).use { socket ->
                assertThrows(IOException::class.java) { socket.startHandshake(); exchange(socket, byteArrayOf(1, 2, 3)) }
            }
        }
    }

    @Test fun downgradeAndWrongApplicationProtocolFail(): Unit = Fixture().use { f ->
        f.connect(f.port).use { socket ->
            socket.enabledProtocols = arrayOf("TLSv1.2")
            assertThrows(IOException::class.java) { socket.startHandshake() }
        }
        f.connect(f.port).use { socket ->
            socket.sslParameters = socket.sslParameters.apply { applicationProtocols = arrayOf("unrelated/1") }
            assertThrows(IOException::class.java) { socket.startHandshake(); exchange(socket, byteArrayOf(1)) }
        }
    }

    @Test fun relayTamperingCannotProduceApplicationReply(): Unit = Fixture().use { f ->
        Relay(f.port).use { relay ->
            f.connect(relay.port).use { socket ->
                socket.startHandshake()
                relay.tamper.set(true)
                assertThrows(IOException::class.java) { exchange(socket, "synthetic-tamper-target".toByteArray()) }
                assertTrue(relay.changed.get())
            }
        }
    }

    @Test fun oversizedFrameIsRejectedWithoutAnEcho(): Unit = Fixture().use { f ->
        f.connect(f.port).use { socket ->
            socket.startHandshake()
            DataOutputStream(socket.outputStream).apply { writeInt(65_537); flush() }
            assertThrows(IOException::class.java) { DataInputStream(socket.inputStream).readInt() }
        }
    }

    private fun exchange(socket: SSLSocket, payload: ByteArray): ByteArray {
        DataOutputStream(socket.outputStream).apply { writeInt(payload.size); write(payload); flush() }
        val input = DataInputStream(socket.inputStream)
        val count = input.readInt()
        require(count in 0..65_536)
        return ByteArray(count).also { input.readFully(it) }
    }

    private class Identity(val path: Path) {
        val store = KeyStore.getInstance("PKCS12").apply {
            Files.newInputStream(path).use { load(it, PASSWORD.toCharArray()) }
        }
        val certificate = store.getCertificate("fixture") as X509Certificate
        val keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(store, PASSWORD.toCharArray())
        }.keyManagers
    }

    private class Fixture : AutoCloseable {
        private val directory = Files.createTempDirectory("remozio-tls-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val mac: Identity
        val phone: Identity
        private val process: Process
        val port: Int
        init {
            var child: Process? = null
            try {
                mac = generate("mac")
                phone = generate("phone")
                val peer = requireNotNull(System.getProperty("remozio.test.tlsPeer")) { "Build the native TLS peer first" }
                child = ProcessBuilder(peer, mac.path.toString()).redirectError(directory.resolve("peer.log").toFile()).start()
                process = child
                process.outputStream.bufferedWriter().use {
                    it.write("{\"peerCertificate\":\"" + Base64.getEncoder().encodeToString(phone.certificate.encoded) + "\"}\n")
                }
                val reader = Executors.newSingleThreadExecutor()
                try {
                    val line = reader.submit<String?> { process.inputStream.bufferedReader().readLine() }.get(10, TimeUnit.SECONDS)
                    port = Json.parseToJsonElement(requireNotNull(line) { "TLS peer did not start" }).jsonObject.getValue("port").jsonPrimitive.int
                    require(port in 1..65_535)
                } finally { reader.shutdownNow() }
            } catch (failure: Throwable) {
                child?.destroyForcibly()?.waitFor(3, TimeUnit.SECONDS)
                clean()
                throw failure
            }
        }
        private fun generate(name: String): Identity {
            val path = directory.resolve("$name.p12")
            val keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString()
            val command = ProcessBuilder(keytool, "-genkeypair", "-alias", "fixture", "-keyalg", "EC", "-groupname", "secp256r1",
                "-dname", "CN=synthetic-$name", "-validity", "1", "-storetype", "PKCS12", "-keystore", path.toString(),
                "-storepass", PASSWORD, "-keypass", PASSWORD, "-noprompt")
                .redirectErrorStream(true).redirectOutput(directory.resolve("$name-keytool.log").toFile()).start()
            if (!command.waitFor(15, TimeUnit.SECONDS)) { command.destroyForcibly(); error("Synthetic certificate generation timed out") }
            check(command.exitValue() == 0) { "Synthetic certificate generation failed" }
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
            return Identity(path)
        }
        fun connect(port: Int, identity: Identity? = phone, serverPin: X509Certificate = mac.certificate): SSLSocket {
            val context = SSLContext.getInstance("TLSv1.3")
            val trust = object : X509TrustManager {
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = verify(chain)
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = verify(chain)
                private fun verify(chain: Array<X509Certificate>) {
                    if (chain.isEmpty() || !chain[0].encoded.contentEquals(serverPin.encoded)) throw CertificateException("Wrong synthetic peer pin")
                    chain[0].checkValidity()
                }
            }
            context.init(identity?.keyManagers ?: emptyArray(), arrayOf<TrustManager>(trust), null)
            return (context.socketFactory.createSocket("127.0.0.1", port) as SSLSocket).apply {
                soTimeout = 4_000
                enabledProtocols = arrayOf("TLSv1.3")
                sslParameters = sslParameters.apply { applicationProtocols = arrayOf("remozio-experiment/1") }
            }
        }
        override fun close() {
            process.destroy()
            if (!process.waitFor(3, TimeUnit.SECONDS)) { process.destroyForcibly(); process.waitFor(3, TimeUnit.SECONDS) }
            clean()
        }
        private fun clean() { Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } } }
    }

    private class Relay(upstreamPort: Int) : AutoCloseable {
        private val listener = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port: Int = listener.localPort
        val tamper = AtomicBoolean(false)
        val changed = AtomicBoolean(false)
        private val recorded = ByteArrayOutputStream()
        private val workers = Executors.newFixedThreadPool(3)
        @Volatile private var incoming: Socket? = null
        @Volatile private var upstream: Socket? = null
        init {
            workers.submit {
                try {
                    val client = listener.accept().also { incoming = it }
                    val server = Socket("127.0.0.1", upstreamPort).also { upstream = it }
                    client.soTimeout = 5_000; server.soTimeout = 5_000
                    workers.submit { copy(client, server, true) }
                    workers.submit { copy(server, client, false) }
                } catch (_: IOException) { }
            }
        }
        private fun copy(from: Socket, to: Socket, alter: Boolean) {
            try {
                val buffer = ByteArray(4_096)
                while (true) {
                    val count = from.inputStream.read(buffer)
                    if (count < 0) break
                    if (alter && count > 0 && tamper.compareAndSet(true, false)) {
                        buffer[count - 1] = (buffer[count - 1].toInt() xor 1).toByte(); changed.set(true)
                    }
                    synchronized(recorded) {
                        check(recorded.size() + count <= 1_048_576)
                        recorded.write(buffer, 0, count)
                    }
                    var offset = 0
                    while (offset < count) {
                        val length = minOf(97, count - offset)
                        to.outputStream.write(buffer, offset, length); offset += length
                    }
                    to.outputStream.flush()
                }
            } catch (_: IOException) { }
            finally { runCatching { from.close() }; runCatching { to.close() } }
        }
        fun capture(): ByteArray = synchronized(recorded) { recorded.toByteArray() }
        override fun close() {
            listener.close(); incoming?.close(); upstream?.close()
            workers.shutdownNow(); check(workers.awaitTermination(6, TimeUnit.SECONDS)) { "Relay cleanup timed out" }
        }
    }

    private companion object { const val PASSWORD = "synthetic-only" }
}
