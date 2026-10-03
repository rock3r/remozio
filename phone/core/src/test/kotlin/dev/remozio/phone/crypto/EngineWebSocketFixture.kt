package dev.remozio.phone.crypto

import dev.remozio.phone.transport.PinnedTLSClient
import dev.remozio.phone.transport.TLSClientProgress
import dev.remozio.phone.transport.TLSClientState
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString

/** Bounded test driver. The trusted fixture bounds frames before OkHttp's complete-message callback. */
internal class EngineWebSocketFixture(relay: WebSocketTLSRelay, private val engine: PinnedTLSClient) : AutoCloseable {
    private sealed interface Event {
        class Data(val bytes: ByteArray) : Event
        data object End : Event
    }
    private val events = ArrayBlockingQueue<Event>(1_024)
    private val queuedBytes = AtomicInteger()
    private val ready = CountDownLatch(1)
    private val opened = AtomicBoolean(false)
    private val ended = AtomicBoolean(false)
    private val plaintext = ByteArrayOutputStream()
    private val socket = relay.open(object : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) { opened.set(true); ready.countDown() }
        override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
            if (ended.get()) return
            if (bytes.size > 32_768 || queuedBytes.addAndGet(bytes.size) > 262_144 || !events.offer(Event.Data(bytes.toByteArray()))) {
                end(); webSocket.cancel()
            }
        }
        override fun onMessage(webSocket: WebSocket, text: String) { end(); webSocket.cancel() }
        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) { end(); webSocket.close(code, reason) }
        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) { end() }
        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) { end() }
    })

    fun handshake() {
        if (!ready.await(5, TimeUnit.SECONDS) || !opened.get()) throw IOException("Fixture outer connection failed")
        deliver(engine.start())
        while (engine.state() == TLSClientState.HANDSHAKING) receive()
        check(engine.state() == TLSClientState.OPEN && plaintext.size() == 0)
    }

    fun exchange(payload: ByteArray): ByteArray {
        require(payload.size <= 65_536)
        val frame = ByteBuffer.allocate(payload.size + 4).putInt(payload.size).put(payload).array()
        var sent = 0
        while (sent < frame.size) {
            val batch = engine.send(frame.copyOfRange(sent, minOf(sent + 32_768, frame.size)))
            sent += batch.consumedPlaintextBytes
            deliver(batch)
            if (batch.consumedPlaintextBytes == 0) receive()
        }
        while (plaintext.size() < frame.size) receive()
        val reply = ByteBuffer.wrap(plaintext.toByteArray())
        val count = reply.int
        check(count == payload.size && reply.remaining() == count)
        return ByteArray(count).also { reply.get(it) }
    }

    private fun receive() {
        when (val event = events.poll(5, TimeUnit.SECONDS) ?: throw IOException("Fixture receive timed out")) {
            is Event.Data -> {
                queuedBytes.addAndGet(-event.bytes.size)
                deliver(engine.receive(event.bytes))
            }
            Event.End -> { engine.endOfInput(); throw IOException("Fixture peer closed") }
        }
    }
    private fun deliver(batch: TLSClientProgress) {
        for (value in batch.encrypted) {
            val bytes = value.copyBytes()
            var offset = 0
            while (offset < bytes.size) {
                val length = minOf(311, bytes.size - offset)
                if (socket.queueSize() + length > 262_144 || !socket.send(bytes.toByteString(offset, length))) {
                    throw IOException("Fixture output queue limit")
                }
                offset += length
            }
        }
        batch.plaintext.forEach {
            check(plaintext.size() + it.size <= 65_540)
            plaintext.write(it.copyBytes())
        }
    }
    private fun end() {
        if (ended.compareAndSet(false, true)) {
            if (!events.offer(Event.End)) { events.clear(); events.offer(Event.End) }
            ready.countDown()
        }
    }
    override fun close() { socket.cancel(); end() }
}
