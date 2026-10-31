package dev.remozio.phone.transport

import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.*
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.PrivateKey
import java.security.Signature

/** Runs the real routing parser and verifier. This source set never enters application artifacts. */
suspend fun verifiedSyntheticRouting(
    record: StoredPhoneEnrollment, rootKey: PrivateKey, response: RoutingStatusResponse, elapsedNanos: () -> Long,
    query: PhoneRoutingFrame = PhoneRoutingFrame.Status(response.queryNonce.copyBytes()),
    challenge: PhoneRoutingChallenge? = null,
): PhoneRoutingResult.Verified {
    val e = record.enrollment
    val scope = ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes())
    val bytes = response.encode()
    val signature = Signature.getInstance("SHA256withECDSAinP1363Format").run {
        initSign(rootKey); update(RoutingStatusSigningInput.make(1u, bytes, CborLimits(3200, 2, 16))); sign()
    }
    val result = PhoneRoutingFrame.Response(response.queryNonce.copyBytes(), bytes, signature).encode()
    val peer = SyntheticRoutingPeer(scope, query, result)
    val carrier = NegotiatedTLSChannel.connect(peer, scope, emptyList(), emptySet(), PhoneRoutingFrame.MAXIMUM_BYTES,
        purpose = EnrolledChannelPurpose.ROUTING)
    val channel = PhoneRoutingChannel.bind(record, carrier, elapsedNanos, 5000) { response.queryNonce.copyBytes() }
    return try {
        when (query) {
            is PhoneRoutingFrame.Status -> channel.status()
            is PhoneRoutingFrame.Challenge -> channel.challenge(query.expectedRevision)
            is PhoneRoutingFrame.Apply -> channel.apply(checkNotNull(challenge), query.signature.copyBytes())
            else -> error("Invalid synthetic routing query")
        } as PhoneRoutingResult.Verified
    } finally { channel.closeAndJoin() }
}

private class SyntheticRoutingPeer(scope: ChannelScope, private val query: PhoneRoutingFrame,
                                    private val result: ByteArray) : ApprovalByteStream {
    private val owner = ChannelNegotiation(ChannelOffer(ChannelRole.MAC, scope, ByteArray(32) { 12 }, setOf(1u), emptyList(), emptySet()), 1u)
    private val offer = owner.offer()
    private val output = ByteArrayOutputStream()
    private val input = ArrayDeque<ByteArray>()
    private var phase = 0
    override suspend fun awaitOpen() = Unit
    override suspend fun send(bytes: ByteArray) {
        output.write(bytes); val all = output.toByteArray()
        if (all.size < 4) return
        val count = ByteBuffer.wrap(all).int
        if (all.size < count + 4) return
        check(all.size == count + 4); output.reset()
        val body = all.copyOfRange(4, all.size)
        when (phase++) {
            0 -> { owner.receiveOffer(body); input.add(frame(offer)) }
            1 -> { owner.receiveConfirmation(body); input.add(frame(owner.confirmation())) }
            else -> {
                val envelope = SessionEnvelope.decode(body, PhoneRoutingFrame.MAXIMUM_BYTES)
                check(envelope.sessionID == owner.confirmed().sessionID && envelope.sequence == 0uL)
                check(envelope.payload.copyBytes().contentEquals(query.encode()))
                input.add(frame(SessionEnvelope(envelope.sessionID.copyBytes(), 0u, result).encode(PhoneRoutingFrame.MAXIMUM_BYTES)))
            }
        }
    }
    override suspend fun receive(): ByteArray = input.removeFirst()
    override fun close() = owner.close()
    override suspend fun awaitClosed() = Unit
    private fun frame(bytes: ByteArray) = ByteBuffer.allocate(bytes.size + 4).putInt(bytes.size).put(bytes).array()
}
