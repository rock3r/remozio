package dev.remozio.phone.crypto

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.ByteString
import okio.ByteString.Companion.toByteString

/** Test carrier only: TLS records cross a local WSS endpoint with an independent outer certificate. */
internal class WebSocketTLSRelay(upstreamPort: Int, trustOuter: Boolean = true) : AutoCloseable {
    private val server = MockWebServer()
    private val local = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
    val port: Int = local.localPort
    val outerAuthenticated = AtomicBoolean(false)
    val tamper = AtomicBoolean(false)
    val changed = AtomicBoolean(false)
    private val captured = ByteArrayOutputStream()
    private val workers = Executors.newFixedThreadPool(3)
    private val sockets = CopyOnWriteArrayList<Socket>()
    private val webSockets = CopyOnWriteArrayList<WebSocket>()
    private val serverWebSockets = CopyOnWriteArrayList<WebSocket>()
    private val client: OkHttpClient
    @Volatile private var upstream: Socket? = null

    init {
        val outer = HeldCertificate.Builder().commonName("synthetic-relay").addSubjectAlternativeName("localhost")
            .addSubjectAlternativeName("127.0.0.1").build()
        val serverKeys = HandshakeCertificates.Builder().heldCertificate(outer).build()
        val clientTrust = HandshakeCertificates.Builder().apply {
            addTrustedCertificate(if (trustOuter) outer.certificate else HeldCertificate.Builder().build().certificate)
        }.build()
        server.useHttps(serverKeys.sslSocketFactory())
        server.enqueue(MockResponse.Builder().webSocketUpgrade(object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                serverWebSockets += webSocket
                val socket = Socket("127.0.0.1", upstreamPort).apply { soTimeout = 5_000 }
                sockets += socket; upstream = socket
                workers.submit {
                    try {
                        val buffer = ByteArray(4_096)
                        while (true) {
                            val count = socket.inputStream.read(buffer)
                            if (count < 0) break
                            val bytes = buffer.copyOf(count)
                            record(bytes)
                            sendChunks(webSocket, bytes, 127)
                        }
                        webSocket.close(1000, "fixture complete")
                    } catch (_: IOException) { webSocket.close(1001, "fixture abort") }
                }
            }
            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                val data = bytes.toByteArray()
                if (data.isNotEmpty() && tamper.compareAndSet(true, false)) {
                    data[data.lastIndex] = (data.last().toInt() xor 1).toByte(); changed.set(true)
                }
                try {
                    record(data)
                    requireNotNull(upstream).outputStream.apply { write(data); flush() }
                } catch (_: IOException) { webSocket.close(1001, "fixture abort") }
            }
            override fun onMessage(webSocket: WebSocket, text: String) { webSocket.close(1003, "binary required") }
            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                webSocket.close(code, reason); runCatching { upstream?.close() }
            }
            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) { runCatching { upstream?.close() } }
        }).build())
        server.start(InetAddress.getByName("127.0.0.1"), 0)
        client = OkHttpClient.Builder().sslSocketFactory(clientTrust.sslSocketFactory(), clientTrust.trustManager)
            .connectTimeout(3, TimeUnit.SECONDS).readTimeout(5, TimeUnit.SECONDS).build()
        workers.submit {
            try {
                val socket = local.accept().apply { soTimeout = 5_000 }
                sockets += socket
                val ws = client.newWebSocket(Request.Builder().url(server.url("/tls")).build(), object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        outerAuthenticated.set(response.handshake != null)
                        workers.submit {
                            try {
                                val buffer = ByteArray(4_096)
                                while (true) {
                                    val count = socket.inputStream.read(buffer)
                                    if (count < 0) break
                                    sendChunks(webSocket, buffer.copyOf(count), 311)
                                }
                                webSocket.close(1000, "fixture complete")
                            } catch (_: IOException) { webSocket.cancel() }
                        }
                    }
                    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                        try { socket.outputStream.apply { write(bytes.toByteArray()); flush() } }
                        catch (_: IOException) { webSocket.cancel() }
                    }
                    override fun onMessage(webSocket: WebSocket, text: String) { webSocket.close(1003, "binary required") }
                    override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                        webSocket.close(code, reason); runCatching { socket.close() }
                    }
                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) { runCatching { socket.close() } }
                })
                webSockets += ws
            } catch (_: IOException) { }
        }
    }

    private fun sendChunks(webSocket: WebSocket, bytes: ByteArray, chunkSize: Int) {
        var offset = 0
        while (offset < bytes.size) {
            val length = minOf(chunkSize, bytes.size - offset)
            if (webSocket.queueSize() > 262_144 || !webSocket.send(bytes.toByteString(offset, length))) throw IOException("Carrier queue limit")
            offset += length
        }
    }
    private fun record(bytes: ByteArray) = synchronized(captured) {
        if (captured.size() + bytes.size > 1_048_576) throw IOException("Capture limit")
        captured.write(bytes)
    }
    fun capture(): ByteArray = synchronized(captured) { captured.toByteArray() }

    override fun close() {
        var failure: Throwable? = null
        fun attempt(block: () -> Unit) {
            try { block() } catch (problem: Throwable) {
                if (failure == null) failure = problem else failure.addSuppressed(problem)
            }
        }
        attempt { local.close() }
        webSockets.forEach { attempt { it.cancel() } }
        serverWebSockets.forEach { attempt { it.close(1001, "fixture shutdown") } }
        sockets.forEach { attempt { it.close() } }
        attempt { workers.shutdownNow() }
        attempt { check(workers.awaitTermination(6, TimeUnit.SECONDS)) { "Carrier cleanup timed out" } }
        attempt { server.close() }
        attempt { client.dispatcher.executorService.shutdownNow() }
        attempt { client.connectionPool.evictAll() }
        attempt { check(client.dispatcher.executorService.awaitTermination(6, TimeUnit.SECONDS)) { "WebSocket client cleanup timed out" } }
        failure?.let { throw it }
    }
}
