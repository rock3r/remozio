package dev.remozio.phone.requests

import dev.remozio.phone.transport.NegotiatedTLSChannel
import dev.remozio.protocol.*
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ensureActive

class RequestCapacityException : IOException("Request memory capacity reached")

internal interface RequestMessageChannel : AutoCloseable {
    val scope: ChannelScope
    val supportsCommands: Boolean
    val maximumPayloadBytes: Int
    suspend fun receive(): ByteArray?
}
private class NegotiatedRequestChannel(private val channel: NegotiatedTLSChannel) : RequestMessageChannel {
    override val scope get() = channel.negotiated.peer.scope
    override val maximumPayloadBytes get() = channel.maximumPayloadBytes
    override val supportsCommands: Boolean get() {
        fun List<ChannelRequestCapability>.supports() = any { it.kind == 0uL && it.wireVersion == 1uL && it.schemaVersion == 1uL }
        return channel.negotiated.peer.role == ChannelRole.MAC && channel.localRequests.supports() &&
            channel.localRequests.all { it.kind == 0uL && it.wireVersion == 1uL && it.schemaVersion == 1uL && it.features.isEmpty() } &&
            channel.localAuditVersions.isEmpty() && channel.negotiated.peer.requests.supports()
    }
    override suspend fun receive() = channel.receive()
    override fun close() = channel.close()
}

/** Delivers authenticated captures and statuses. It grants no freshness, reachability, or action authority. */
class CommandRequestReceiver private constructor(
    private val enrollment: CommandRequestEnrollment,
    private val channel: RequestMessageChannel,
    private val maximumBodyBytes: Int,
    private val clock: () -> ElapsedInstant,
) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    private val started = AtomicBoolean(false)

    /** Run once in the host's connection scope. EOF leaves retained request owners intact. */
    suspend fun run() {
        check(started.compareAndSet(false, true))
        try {
            while (!closed.get()) {
                kotlin.coroutines.coroutineContext.ensureActive()
                val bytes = channel.receive() ?: return
                kotlin.coroutines.coroutineContext.ensureActive()
                if (closed.get()) return
                val message = ApprovalMessage.decode(bytes, maximumBodyBytes)
                require(message.type != ApprovalMessageType.DECISION)
                enrollment.deliver(this, message, clock())
            }
        } catch (cancelled: CancellationException) {
            kotlin.coroutines.coroutineContext.ensureActive()
            if (!closed.get()) throw cancelled
        } catch (failure: InboxException) {
            if (!closed.get()) {
                if (failure.reason == InboxRejection.CAPACITY) throw RequestCapacityException()
                throw IOException("Request delivery stopped")
            }
        } catch (_: Exception) { if (!closed.get()) throw IOException("Request delivery stopped") }
        finally { close() }
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            try { channel.close() } finally { enrollment.detach(this) }
        }
    }

    companion object {
        /** The phone ID and epoch come from trusted enrollment. Ownership transfers even if binding fails. */
        fun bind(enrollment: CommandRequestEnrollment, channel: NegotiatedTLSChannel,
                 phoneID: ByteArray, enrollmentEpoch: ByteArray, clock: () -> ElapsedInstant): CommandRequestReceiver =
            bind(enrollment, NegotiatedRequestChannel(channel), phoneID, enrollmentEpoch, clock)

        internal fun bind(enrollment: CommandRequestEnrollment, channel: RequestMessageChannel,
                          phoneID: ByteArray, enrollmentEpoch: ByteArray, clock: () -> ElapsedInstant): CommandRequestReceiver {
            try {
                val expected = ChannelScope(enrollment.macID.copyBytes(), enrollment.accountID.copyBytes(), phoneID, enrollmentEpoch)
                require(channel.scope == expected && channel.supportsCommands)
                val maximum = maxOf(enrollment.limits.body.maxBytes, enrollment.limits.status.maxBytes)
                require(maximum in 1..(16_777_216 - ApprovalMessage.OVERHEAD_BYTES))
                require(channel.maximumPayloadBytes >= maximum + ApprovalMessage.OVERHEAD_BYTES)
                val receiver = CommandRequestReceiver(enrollment, channel, maximum, clock)
                enrollment.attach(receiver)
                return receiver
            } catch (failure: Exception) { channel.close(); throw failure }
        }
    }
}
