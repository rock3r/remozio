package dev.remozio.phone.transport

import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout

internal interface SessionTLSEngine : AutoCloseable {
    fun start(): TLSClientProgress
    fun receive(bytes: ByteArray): TLSClientProgress
    fun send(bytes: ByteArray): TLSClientProgress
    fun endOfInput(): TLSClientProgress
}

private class NativeSessionEngine(private val engine: PinnedTLSClient) : SessionTLSEngine {
    override fun start() = engine.start()
    override fun receive(bytes: ByteArray) = engine.receive(bytes)
    override fun send(bytes: ByteArray) = engine.send(bytes)
    override fun endOfInput() = engine.endOfInput()
    override fun close() = engine.close()
}

/**
 * One TLS incarnation over an owned carrier. Enrollment changes must close this session synchronously.
 * Returned plaintext still needs protocol verification and a current-enrollment check before it grants authority.
 */
class TLSRecordSession internal constructor(
    parent: CoroutineScope,
    private val engine: SessionTLSEngine,
    private val carrier: EncryptedRecordTransport,
    private val handshakeTimeoutMillis: Long,
    dispatcher: CoroutineDispatcher,
) : AutoCloseable {
    constructor(
        parent: CoroutineScope,
        engine: PinnedTLSClient,
        carrier: EncryptedRecordTransport,
        handshakeTimeoutMillis: Long = 15_000,
        dispatcher: CoroutineDispatcher = Dispatchers.IO,
    ) : this(parent, NativeSessionEngine(engine), carrier, handshakeTimeoutMillis, dispatcher)

    private class Write(val bytes: ByteArray, val done: CompletableDeferred<Unit> = CompletableDeferred(), var offset: Int = 0)
    private val parentJob = requireNotNull(parent.coroutineContext[Job])
    private val aborted = AtomicBoolean(false)
    private val carrierClosed = AtomicBoolean(false)
    private val engineClosed = AtomicBoolean(false)
    private val opened = CompletableDeferred<Unit>()
    private val plaintext = Channel<ByteArray>(1)
    private val input = Channel<ByteArray>(1)
    private val writes = Channel<Write>(1, onUndeliveredElement = { it.done.completeExceptionally(rejected()) })
    private val pendingPlaintext = ArrayDeque<ByteArray>()
    private var pendingPlaintextBytes = 0
    private val sendMutex = Mutex()
    private val receiveMutex = Mutex()
    private val worker: Job

    init {
        require(handshakeTimeoutMillis in 1..60_000)
        require(carrier.maximumMessageBytes in 1..32_768)
        worker = parent.launch(dispatcher, start = CoroutineStart.LAZY) { runSession() }
        worker.invokeOnCompletion {
            // Also runs if the parent was cancelled before the lazy worker could enter its body.
            opened.completeExceptionally(rejected())
            writes.cancel()
            input.cancel()
            if (it != null) abortBuffers()
            releaseCarrier()
            releaseEngine()
        }
        worker.start()
    }

    suspend fun awaitOpen(): Unit = operation {
        opened.await()
        checkActive()
    }

    /** Accepts one plaintext chunk. Completion is local carrier acceptance, never a remote outcome. */
    suspend fun send(bytes: ByteArray): Unit = operation {
        require(bytes.size in 1..32_768)
        sendMutex.withLock {
            awaitOpen()
            checkActive()
            val write = Write(bytes.copyOf())
            writes.send(write)
            write.done.await()
            checkActive()
        }
    }

    /** Authenticated TLS closure permits draining prior plaintext. Abrupt carrier EOF rejects the session. */
    suspend fun receive(): ByteArray? = operation {
        receiveMutex.withLock {
            awaitOpen()
            checkActive()
            val result = plaintext.receiveCatching()
            checkActive()
            if (result.exceptionOrNull() != null) throw rejected()
            result.getOrNull()
        }
    }

    /** Abort I/O immediately. A provider key operation may finish later; its output is discarded. */
    override fun close() {
        abortBuffers()
        releaseCarrier()
        worker.cancel()
    }

    suspend fun closeAndJoin() { close(); worker.join(); carrier.awaitClosed() }

    private suspend fun runSession() = coroutineScope {
        var activeWrite: Write? = null
        val reader = launch {
            try {
                while (true) {
                    val bytes = carrier.receive() ?: break
                    if (bytes.size !in 1..carrier.maximumMessageBytes) throw rejected()
                    input.send(bytes.copyOf())
                }
                input.close()
            } catch (_: Exception) { input.close(rejected()) }
        }
        try {
            var state = withTimeout(handshakeTimeoutMillis) {
                var current = deliver(engine.start())
                while (current == TLSClientState.HANDSHAKING) current = readInput()
                if (current != TLSClientState.OPEN && current != TLSClientState.PEER_CLOSED) throw rejected()
                current
            }
            var awaitingPeer = false
            while (state != TLSClientState.PEER_CLOSED || pendingPlaintext.isNotEmpty()) {
                val write = activeWrite
                if (write != null && !awaitingPeer) {
                    checkActive()
                    val batch = engine.send(write.bytes.copyOfRange(write.offset, write.bytes.size))
                    require(batch.consumedPlaintextBytes in 0..(write.bytes.size - write.offset))
                    write.offset += batch.consumedPlaintextBytes
                    state = deliver(batch)
                    if (state != TLSClientState.OPEN) throw rejected()
                    if (write.offset == write.bytes.size) {
                        checkActive()
                        write.done.complete(Unit)
                        activeWrite = null
                    } else {
                        awaitingPeer = batch.consumedPlaintextBytes == 0
                        if (!awaitingPeer) continue
                    }
                }
                select<Unit> {
                    if (pendingPlaintext.isNotEmpty()) {
                        plaintext.onSend(pendingPlaintext.first()) {
                            pendingPlaintextBytes -= pendingPlaintext.removeFirst().size
                        }
                    } else if (state != TLSClientState.PEER_CLOSED) {
                        input.onReceiveCatching { next ->
                            state = consume(next.getOrNull(), next.exceptionOrNull() != null)
                            awaitingPeer = false
                        }
                    }
                    if (activeWrite == null && state == TLSClientState.OPEN) {
                        writes.onReceive { activeWrite = it }
                    }
                }
            }
            checkActive()
            plaintext.close()
        } catch (_: Exception) {
            abortBuffers()
        } finally {
            activeWrite?.done?.completeExceptionally(rejected())
            writes.cancel()
            pendingPlaintext.clear()
            pendingPlaintextBytes = 0
            reader.cancel()
            releaseCarrier()
            releaseEngine()
            withContext(NonCancellable) { carrier.awaitClosed() }
        }
    }

    private suspend fun readInput(): TLSClientState {
        val next = input.receiveCatching()
        return consume(next.getOrNull(), next.exceptionOrNull() != null)
    }

    private suspend fun consume(bytes: ByteArray?, failed: Boolean): TLSClientState {
        checkActive()
        if (failed) throw rejected()
        return deliver(if (bytes == null) engine.endOfInput() else engine.receive(bytes))
    }

    private suspend fun deliver(batch: TLSClientProgress): TLSClientState {
        checkActive()
        if (batch.state != TLSClientState.HANDSHAKING && batch.state != TLSClientState.OPEN && batch.state != TLSClientState.PEER_CLOSED) throw rejected()
        for (encrypted in batch.encrypted) {
            val bytes = encrypted.copyBytes()
            var offset = 0
            while (offset < bytes.size) {
                checkActive()
                val end = minOf(offset + carrier.maximumMessageBytes, bytes.size)
                carrier.send(bytes.copyOfRange(offset, end))
                checkActive()
                offset = end
            }
        }
        if (batch.state == TLSClientState.OPEN || batch.state == TLSClientState.PEER_CLOSED) opened.complete(Unit)
        for (value in batch.plaintext) {
            checkActive()
            if (!opened.isCompleted || batch.state == TLSClientState.HANDSHAKING) throw rejected()
            if (value.size > 65_536 - pendingPlaintextBytes) throw rejected()
            pendingPlaintext.addLast(value.copyBytes())
            pendingPlaintextBytes += value.size
        }
        return batch.state
    }

    private suspend fun checkActive() {
        kotlin.coroutines.coroutineContext.ensureActive()
        if (aborted.get() || parentJob.isCancelled) throw rejected()
    }

    private fun abortBuffers() {
        aborted.set(true)
        opened.completeExceptionally(rejected())
        plaintext.cancel()
        input.cancel()
        writes.cancel()
    }

    private fun releaseEngine() {
        if (engineClosed.compareAndSet(false, true)) engine.close()
    }

    private fun releaseCarrier() {
        if (carrierClosed.compareAndSet(false, true)) runCatching { carrier.close() }
    }

    private suspend fun <T> operation(block: suspend () -> T): T = try {
        kotlin.coroutines.coroutineContext.ensureActive()
        block()
    } catch (cancelled: CancellationException) { close(); throw cancelled }
    catch (_: Exception) { close(); throw rejected() }

    private companion object { fun rejected() = IOException("TLS session closed") }
}
