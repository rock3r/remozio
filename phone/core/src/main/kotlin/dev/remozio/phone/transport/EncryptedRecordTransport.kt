package dev.remozio.phone.transport

/** Ordered ciphertext only. close must abort I/O without blocking the caller. */
interface EncryptedRecordTransport : AutoCloseable {
    val maximumMessageBytes: Int
    suspend fun send(ciphertext: ByteArray)
    suspend fun receive(): ByteArray?
    /** Called after close. Implementations with independent jobs wait for their termination here. */
    suspend fun awaitClosed() {}
    override fun close()
}
