package dev.remozio.phone.transport

import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** A resolved route is only a hint. Authenticate it with PinnedTLSClient before sending application data. */
class DirectTCPConnector(private val sockets: () -> Socket = ::Socket) {
    suspend fun connect(parent: CoroutineScope, endpoint: InetSocketAddress, timeoutMillis: Long = 5_000,
                        maximumMessageBytes: Int = 32_768, queueCapacity: Int = 1): EncryptedRecordTransport {
        require(!endpoint.isUnresolved && endpoint.port in 1..65_535)
        require(!endpoint.address.isAnyLocalAddress && !endpoint.address.isMulticastAddress)
        require(timeoutMillis in 1..60_000 && maximumMessageBytes in 1..32_768 && queueCapacity in 1..64)
        val parentJob = requireNotNull(parent.coroutineContext[Job])
        parentJob.ensureActive()
        val lifetime = DirectSocketLifetime(parentJob, sockets())
        try {
            val connected = withTimeoutOrNull(timeoutMillis) {
                suspendCancellableCoroutine { continuation ->
                    val setup = lifetime.scope.launch {
                        try {
                            lifetime.socket.connect(endpoint, timeoutMillis.toInt())
                            ensureActive()
                            continuation.resume(Unit) { _, _, _ -> lifetime.close() }
                        } catch (_: Exception) {
                            continuation.resumeWith(Result.failure(IOException("Direct connection rejected")))
                        }
                    }
                    setup.invokeOnCompletion { if (it != null) continuation.cancel() }
                    continuation.invokeOnCancellation { lifetime.close(); setup.cancel() }
                }
                true
            } ?: false
            if (!connected) throw IOException("Direct connection timed out")
            parentJob.ensureActive()
            currentCoroutineContext().ensureActive()
            return DirectSocketCarrier(lifetime, maximumMessageBytes, queueCapacity)
        } catch (failure: Throwable) {
            lifetime.close()
            throw failure
        }
    }
}

private class DirectSocketLifetime(parent: Job, val socket: Socket) : AutoCloseable {
    val owner = SupervisorJob(parent)
    val scope = CoroutineScope(owner + Dispatchers.IO)
    private val closed = AtomicBoolean(false)
    init {
        // Cancellation closes the socket immediately, including while native connect/read/write is blocked.
        CoroutineScope(owner + Dispatchers.Unconfined).launch(start = CoroutineStart.UNDISPATCHED) {
            try { awaitCancellation() } finally { release() }
        }
    }
    private fun release() { if (closed.compareAndSet(false, true)) runCatching { socket.close() } }
    override fun close() { release(); owner.cancel() }
}

private class DirectSocketCarrier(
    private val lifetime: DirectSocketLifetime,
    override val maximumMessageBytes: Int,
    queueCapacity: Int,
) : EncryptedRecordTransport {
    private class Write(val bytes: ByteArray) { val completed = CompletableDeferred<Unit>() }
    private val closed = AtomicBoolean(false)
    private val sendMutex = Mutex()
    private val inbound = Channel<ByteArray>(queueCapacity)
    private val outbound = Channel<Write>(queueCapacity, onUndeliveredElement = { it.completed.completeExceptionally(closedError()) })
    private val reader = lifetime.scope.launch {
        try {
            val buffer = ByteArray(maximumMessageBytes)
            while (true) {
                val count = lifetime.socket.inputStream.read(buffer)
                if (count < 0) { inbound.close(); break }
                if (count == 0) throw IOException("Direct read made no progress")
                inbound.send(buffer.copyOf(count))
            }
        } catch (_: Exception) { close() }
    }
    private val writer = lifetime.scope.launch {
        try {
            for (write in outbound) {
                try {
                    lifetime.socket.outputStream.write(write.bytes)
                    lifetime.socket.outputStream.flush()
                    write.completed.complete(Unit)
                } catch (failure: Exception) {
                    write.completed.completeExceptionally(closedError())
                    throw failure
                }
            }
        } catch (_: Exception) { close() }
    }
    init { lifetime.owner.invokeOnCompletion { close() } }

    override suspend fun send(ciphertext: ByteArray) {
        require(ciphertext.size in 1..maximumMessageBytes)
        try {
            sendMutex.withLock {
                if (closed.get()) throw closedError()
                val write = Write(ciphertext.copyOf())
                outbound.send(write)
                write.completed.await()
            }
        } catch (failure: CancellationException) { close(); throw failure }
        catch (_: Exception) { close(); throw closedError() }
    }
    override suspend fun receive(): ByteArray? = try {
        if (closed.get()) throw closedError()
        val result = inbound.receiveCatching()
        if (result.exceptionOrNull() != null) throw closedError()
        result.getOrNull()
    } catch (failure: CancellationException) { close(); throw failure }
    catch (_: Exception) { close(); throw closedError() }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            inbound.cancel(); outbound.cancel()
            lifetime.close()
        }
    }
    override suspend fun awaitClosed() { reader.join(); writer.join(); lifetime.owner.join() }
    private companion object { fun closedError() = IOException("Direct connection closed") }
}
