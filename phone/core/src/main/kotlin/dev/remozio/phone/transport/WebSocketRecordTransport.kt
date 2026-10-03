package dev.remozio.phone.transport

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.websocket.DefaultWebSocketSession
import io.ktor.websocket.Frame
import io.ktor.websocket.RawWebSocket
import io.ktor.websocket.WebSocketChannelsConfig
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Binary record framing over an already authenticated and upgraded HTTPS connection.
 * The host owns endpoint authentication, upgrade validation, deadlines, and enrollment checks.
 * Closing or cancelling an operation aborts this incarnation; it proves no request outcome.
 */
@OptIn(InternalAPI::class)
class WebSocketRecordTransport(
    parent: CoroutineScope,
    private val input: ByteReadChannel,
    private val output: ByteWriteChannel,
    private val maximumMessageBytes: Int,
    queueCapacity: Int,
    private val closeUnderlying: () -> Unit,
) : AutoCloseable {
    private val queues = WebSocketChannelsConfig().apply {
        require(maximumMessageBytes in 1..32_768)
        require(queueCapacity in 1..64)
        incoming = bounded(queueCapacity)
        outgoing = bounded(queueCapacity)
    }
    private val owner = SupervisorJob(requireNotNull(parent.coroutineContext[Job]))
    private val closed = AtomicBoolean(false)
    private val released = AtomicBoolean(false)
    private val sendMutex = Mutex()
    private val receiveMutex = Mutex()
    // Set the limit at construction, before the raw reader can consume its first header.
    private val raw = RawWebSocket(input, output, maximumMessageBytes.toLong(), true, parent.coroutineContext + owner, queues)
    private val session = DefaultWebSocketSession(raw, channelsConfig = queues)

    init {
        owner.invokeOnCompletion { release() }
        session.closeReason.invokeOnCompletion { release() }
        requireNotNull(session.coroutineContext[Job]).invokeOnCompletion { owner.complete() }
        CoroutineScope(parent.coroutineContext + owner).launch(start = CoroutineStart.UNDISPATCHED) {
            try { requireNotNull(session.coroutineContext[Job]).join() } finally { release() }
        }
        session.start()
    }

    /** Acceptance into the bounded output queue is not delivery or execution acknowledgement. */
    suspend fun send(ciphertext: ByteArray) {
        require(ciphertext.size <= maximumMessageBytes) { "Split ciphertext into bounded messages" }
        try {
            sendMutex.withLock {
                if (closed.get() || !owner.isActive) throw IOException("WebSocket transport closed")
                session.send(Frame.Binary(true, ciphertext.copyOf()))
            }
        } catch (cancelled: CancellationException) { close(); throw cancelled }
        catch (_: Exception) { close(); throw IOException("WebSocket transport rejected") }
    }

    /** Drains messages that precede a peer close. Null is carrier EOF, not authenticated TLS closure. */
    suspend fun receive(): ByteArray? = try {
        receiveMutex.withLock {
            if (closed.get()) throw IOException("WebSocket transport closed")
            val result = select {
                session.incoming.onReceiveCatching { it }
                owner.onJoin { session.incoming.tryReceive() }
            }
            if (result.isFailure && !result.isClosed) throw IOException("WebSocket transport stopped")
            if (result.isClosed) {
                close()
                if (result.exceptionOrNull() != null) throw IOException("WebSocket input rejected")
                null
            } else {
                val frame = result.getOrThrow()
                if (frame !is Frame.Binary || frame.rsv1 || frame.rsv2 || frame.rsv3 || frame.data.size > maximumMessageBytes) {
                    throw IOException("WebSocket binary records required")
                }
                frame.data.copyOf()
            }
        }
    } catch (cancelled: CancellationException) { close(); throw cancelled }
    catch (_: Exception) { close(); throw IOException("WebSocket transport rejected") }

    /** Abort immediately. The underlying close callback must be nonblocking and release the host connection. */
    override fun close() {
        if (closed.compareAndSet(false, true)) {
            owner.cancel()
            release()
        }
    }

    suspend fun closeAndJoin() { close(); owner.join() }

    private fun release() {
        if (released.compareAndSet(false, true)) {
            val cause = IOException("WebSocket transport released")
            runCatching { input.cancel(cause) }
            runCatching { output.cancel(cause) }
            runCatching { closeUnderlying() }
        }
    }
}
