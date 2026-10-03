package dev.remozio.phone.transport

import dev.remozio.protocol.*
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.test.runTest
import org.junit.Test
import kotlin.test.*

class NegotiatedTLSChannelTest {
    private val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 })
    private fun frame(bytes: ByteArray) = ByteBuffer.allocate(bytes.size + 4).putInt(bytes.size).put(bytes).array()
    private inner class Peer(val fragment: Int = 32_768, val initial: ByteArray? = null,
                             val replay: Boolean = false, val wrongSession: Boolean = false) : ApprovalByteStream {
        val owner = ChannelNegotiation(ChannelOffer(ChannelRole.MAC, scope, ByteArray(32) { 9 }, setOf(1u), emptyList(), emptySet()), 1u)
        val offer = owner.offer()
        val output = ByteArrayOutputStream()
        val input = ArrayDeque<ByteArray>()
        var phase = 0
        var closes = 0
        val waiting = CompletableDeferred<Unit>()
        override suspend fun awaitOpen() { }
        override suspend fun send(bytes: ByteArray) {
            output.write(bytes)
            val all = output.toByteArray()
            if (all.size < 4) return
            val count = ByteBuffer.wrap(all).int
            if (all.size < count + 4) return
            check(all.size == count + 4); output.reset()
            val body = all.copyOfRange(4, all.size)
            val reply = when (phase++) {
                0 -> { owner.receiveOffer(body); initial ?: frame(offer) }
                1 -> {
                    owner.receiveConfirmation(body)
                    val confirmation = frame(owner.confirmation())
                    val id = if (wrongSession) ByteArray(32) else owner.confirmed().sessionID.copyBytes()
                    val envelope = frame(SessionEnvelope(id, 0u, byteArrayOf(7, 8)).encode(64))
                    confirmation + envelope + if (replay) envelope else ByteArray(0)
                }
                else -> {
                    val envelope = SessionEnvelope.decode(body, 64)
                    check(envelope.sessionID == owner.confirmed().sessionID)
                    frame(SessionEnvelope(envelope.sessionID.copyBytes(), envelope.sequence + 1u, envelope.payload.copyBytes()).encode(64))
                }
            }
            var offset = 0
            while (offset < reply.size) {
                val end = minOf(offset + fragment, reply.size); input.add(reply.copyOfRange(offset, end)); offset = end
            }
        }
        override suspend fun receive(): ByteArray {
            if (input.isNotEmpty()) return input.removeFirst()
            waiting.complete(Unit); awaitCancellation()
        }
        override fun close() { closes++; owner.close() }
        override suspend fun awaitClosed() { }
    }
    private suspend fun connect(peer: ApprovalByteStream, timeout: Long = 1000) = NegotiatedTLSChannel.connect(
        peer, scope, emptyList(), emptySet(), 64, timeoutMillis = timeout)

    @Test fun coalescedConfirmationAndApplicationBytesSurviveNegotiation() = runTest {
        val peer = Peer(); val channel = connect(peer)
        assertEquals(1uL, channel.negotiated.envelopeVersion)
        assertContentEquals(byteArrayOf(7, 8), channel.receive())
        channel.send(byteArrayOf(1, 2, 3)); assertContentEquals(byteArrayOf(1, 2, 3), channel.receive())
        channel.closeAndJoin(); channel.close(); assertEquals(1, peer.closes)
        assertFails { channel.send(byteArrayOf(1)) }
    }
    @Test fun singleByteFragmentationPreservesFrames() = runTest {
        val peer = Peer(fragment = 1); val channel = connect(peer)
        assertContentEquals(byteArrayOf(7, 8), channel.receive()); channel.closeAndJoin()
    }
    @Test fun wrongSessionAndRepeatedSequencesCloseTheChannel() = runTest {
        val wrong = Peer(wrongSession = true); val channel = connect(wrong)
        assertFails { channel.receive() }; assertEquals(1, wrong.closes)
        val repeated = Peer(replay = true); val second = connect(repeated)
        assertContentEquals(byteArrayOf(7, 8), second.receive())
        assertFails { second.receive() }; assertEquals(1, repeated.closes)
    }
    @Test fun oversizedAndZeroHeadersFailBeforeReadingABody() = runTest {
        for (size in listOf(0, 65_537, -1)) {
            val peer = Peer(initial = ByteBuffer.allocate(4).putInt(size).array())
            assertFails { connect(peer) }; assertFalse(peer.waiting.isCompleted); assertEquals(1, peer.closes)
        }
    }
    @Test fun wholeHandshakeDeadlineClosesStalledInput() = runTest {
        val peer = Peer(initial = byteArrayOf(0, 0))
        assertFails { connect(peer, timeout = 10) }; assertTrue(peer.waiting.isCompleted); assertEquals(1, peer.closes)
    }
    @Test fun cancellationClosesAnEstablishedRead() = runTest {
        val peer = Peer(); val channel = connect(peer); channel.receive()
        val reader = async { channel.receive() }; peer.waiting.await(); reader.cancel(); reader.join()
        assertEquals(1, peer.closes); assertFails { channel.send(byteArrayOf(1)) }
    }
    @Test fun overlappingReadsAreRejectedWithoutAnUnboundedQueue() = runTest {
        val peer = Peer(); val channel = connect(peer); channel.receive()
        val reader = async { runCatching { channel.receive() } }; peer.waiting.await()
        assertFails { channel.receive() }; reader.cancel(); reader.join(); assertEquals(1, peer.closes)
    }
    @Test fun invalidConfigurationStillClosesTheTransferredStream() = runTest {
        val peer = Peer()
        assertFails { NegotiatedTLSChannel.connect(peer, scope, emptyList(), emptySet(), 0) }
        assertEquals(1, peer.closes)
    }
}
