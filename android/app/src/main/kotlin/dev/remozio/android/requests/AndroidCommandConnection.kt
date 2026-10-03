package dev.remozio.android.requests

import android.content.Context
import androidx.annotation.WorkerThread
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.android.transport.AndroidTransportIdentities
import dev.remozio.android.transport.AndroidTransportIdentity
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.requests.CommandMemoryBudget
import dev.remozio.phone.requests.CommandRequestReceiver
import dev.remozio.phone.requests.RequestLimits
import dev.remozio.phone.transport.*
import dev.remozio.protocol.ApprovalMessage
import dev.remozio.protocol.ChannelRequestCapability
import dev.remozio.protocol.ChannelScope
import java.util.concurrent.atomic.AtomicBoolean

/** Uses the saved relay route. LAN discovery and setup must never replace the enrolled inner TLS pin. */
@WorkerThread
internal fun androidCommandConnection(context: Context, record: StoredPhoneEnrollment, limits: RequestLimits, memoryBudget: CommandMemoryBudget? = null): CommandConnection {
    require(record.phase == EnrollmentPhase.ACTIVE)
    val retired = AndroidRetiredCommandRequests.open(context, record.enrollment)
    try {
        return CommandConnection(record, limits, open = { scope, enrollment ->
            val e = record.enrollment
            val credential = checkNotNull(e.relayCredential)
            var identity: AndroidTransportIdentity? = null
            var carrier: EncryptedRecordTransport? = null
            var engine: PinnedTLSClient? = null
            var session: TLSRecordSession? = null
            var channel: NegotiatedTLSChannel? = null
            try {
                identity = AndroidTransportIdentities.load(e.transportKey.alias, e.transportKey.publicKey.copyBytes())
                carrier = RelayConnector().connect(scope, credential)
                engine = PinnedTLSClient(arrayOf(identity.keyManager), e.transportPublicKey.copyBytes(), "remozio/1", 1_048_576)
                session = TLSRecordSession(scope, engine, carrier)
                channel = NegotiatedTLSChannel.connect(session,
                    ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes()),
                    listOf(ChannelRequestCapability(0u, 1u, 1u, emptySet())), emptySet(),
                    maxOf(limits.body.maxBytes, limits.status.maxBytes) + ApprovalMessage.OVERHEAD_BYTES)
                val receiver = CommandRequestReceiver.bind(enrollment, channel, e.phoneID.copyBytes(), e.epoch.copyBytes(), RequestElapsedClock::now)
                NativeCommandWire(receiver, channel, identity)
            } catch (failure: Throwable) {
                channel?.close()
                session?.close()
                engine?.close()
                carrier?.close()
                identity?.close()
                throw failure
            }
        }, clock = RequestElapsedClock::now, retired = retired, memoryBudget = memoryBudget)
    } catch (failure: Throwable) { retired.close(); throw failure }
}

private class NativeCommandWire(
    private val receiver: CommandRequestReceiver,
    private val channel: NegotiatedTLSChannel,
    private val identity: AndroidTransportIdentity,
) : CommandConnectionWire {
    private val closed = AtomicBoolean(false)
    override suspend fun receive() = receiver.run()
    override suspend fun send(bytes: ByteArray) = channel.send(bytes)
    override fun close() {
        if (closed.compareAndSet(false, true)) {
            try { receiver.close() } finally { identity.close() }
        }
    }
}
