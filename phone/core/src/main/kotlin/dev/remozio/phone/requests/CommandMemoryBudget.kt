package dev.remozio.phone.requests

/** Shared across all Mac connections. Bounds retained capture bytes and parsed collection elements. */
class CommandMemoryBudget(private val maximumBytes: Long, private val maximumItems: Long) {
    private val parsing = Any()
    private var bytes = 0L
    private var items = 0L
    init { require(maximumBytes > 0 && maximumItems > 0) }

    // Parsing has a separate monitor: releasing a session never waits for the parsing monitor.
    internal fun <T> parse(operation: () -> T): T = synchronized(parsing) { operation() }

    @Synchronized internal fun retain(captureBytes: Long, captureItems: Long): Reservation {
        require(captureBytes >= 0 && captureItems >= 0)
        if (captureBytes > maximumBytes - bytes - METADATA_BYTES || captureItems > maximumItems - items - METADATA_ITEMS)
            throw InboxException(InboxRejection.CAPACITY)
        bytes += captureBytes + METADATA_BYTES
        items += captureItems + METADATA_ITEMS
        return Reservation(captureBytes, captureItems)
    }

    inner class Reservation internal constructor(private var captureBytes: Long, private var captureItems: Long) : AutoCloseable {
        private var closed = false
        internal fun releaseCapture() = synchronized(this@CommandMemoryBudget) {
            if (!closed) {
                bytes -= captureBytes; items -= captureItems
                captureBytes = 0; captureItems = 0
            }
        }
        override fun close() = synchronized(this@CommandMemoryBudget) {
            if (!closed) {
                releaseCapture(); closed = true
                bytes -= METADATA_BYTES; items -= METADATA_ITEMS
            }
        }
    }
    private companion object { const val METADATA_BYTES = 1024L; const val METADATA_ITEMS = 64L }
}
