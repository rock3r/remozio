package dev.remozio.android.requests

import android.content.Context
import androidx.annotation.WorkerThread
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.android.transport.AndroidTransportIdentities
import dev.remozio.android.transport.LocalNetworkSettings
import dev.remozio.android.transport.androidDirectRoutes
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

/** Direct-first routing uses the same enrolled TLS pin and protocol scope on every path. */
@WorkerThread
internal fun androidCommandConnection(context: Context, record: StoredPhoneEnrollment, limits: RequestLimits, memoryBudget: CommandMemoryBudget? = null): CommandConnection {
    require(record.phase == EnrollmentPhase.ACTIVE)
    val retired = AndroidRetiredCommandRequests.open(context, record.enrollment)
    try {
        return CommandConnection(record, limits, open = { scope, enrollment ->
            val e = record.enrollment
            var identity: AndroidTransportIdentity? = null
            var channel: NegotiatedTLSChannel? = null
            try {
                identity = AndroidTransportIdentities.load(e.transportKey.alias, e.transportKey.publicKey.copyBytes())
                val connector = ApprovalChannelConnector(arrayOf(identity.keyManager), e.transportPublicKey.copyBytes(),
                    ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes()),
                    listOf(ChannelRequestCapability(0u, 1u, 1u, emptySet()), ChannelRequestCapability(0u, 1u, 2u, emptySet())), emptySet(),
                    maxOf(limits.body.maxBytes, limits.status.maxBytes) + ApprovalMessage.OVERHEAD_BYTES,
                    trustedMinimum = record.pairing?.minimumEnvelopeVersion ?: 1u)
                val relay = e.relayCredential?.let { credential -> ApprovalCarrierRoute { parent -> RelayConnector().connect(parent, credential) } }
                channel = connector.connect(scope, androidDirectRoutes(context, e.macID.copyBytes()), relay,
                    directTimeoutMillis = LocalNetworkSettings(context).timeoutSeconds() * 1000L)
                val receiver = CommandRequestReceiver.bind(enrollment, channel, e.phoneID.copyBytes(), e.epoch.copyBytes(), clock = RequestElapsedClock::now)
                NativeCommandWire(receiver, identity)
            } catch (failure: Throwable) {
                channel?.close()
                identity?.close()
                throw failure
            }
        }, clock = RequestElapsedClock::now, retired = retired, memoryBudget = memoryBudget)
    } catch (failure: Throwable) { retired.close(); throw failure }
}

private class NativeCommandWire(
    private val receiver: CommandRequestReceiver,
    private val identity: AndroidTransportIdentity,
) : CommandConnectionWire {
    private val closed = AtomicBoolean(false)
    override suspend fun receive() = receiver.run()
    override suspend fun send(bytes: ByteArray) = receiver.sendDecision(bytes)
    override fun close() {
        if (closed.compareAndSet(false, true)) {
            try { receiver.close() } finally { identity.close() }
        }
    }
}
