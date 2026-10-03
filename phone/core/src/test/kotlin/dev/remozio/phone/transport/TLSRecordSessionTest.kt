package dev.remozio.phone.transport

import dev.remozio.protocol.CborValue
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.writeFully
import java.io.IOException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Test
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class TLSRecordSessionTest {
    private class Engine : SessionTLSEngine {
        var closed = false
        var pauseNextWrite = false
        var reads = 0
        var firstWriteAtRead: Int? = null
        val writes = mutableListOf<ByteArray>()
        override fun start() = batch(TLSClientState.HANDSHAKING, encrypted = byteArrayOf(10, 11, 12, 13, 14))
        override fun receive(bytes: ByteArray): TLSClientProgress {
            reads++
            return when (bytes[0].toInt()) {
            1 -> batch(TLSClientState.OPEN)
            2 -> batch(TLSClientState.OPEN, plain = byteArrayOf(42))
            3 -> batch(TLSClientState.PEER_CLOSED, plain = byteArrayOf(43))
            4 -> TLSClientProgress(TLSClientState.OPEN, 0, emptyList(), List(4) { CborValue.Bytes(byteArrayOf(it.toByte())) })
            else -> throw IOException("synthetic failure")
            }
        }
        override fun send(bytes: ByteArray): TLSClientProgress {
            if (pauseNextWrite) { pauseNextWrite = false; return batch(TLSClientState.OPEN) }
            if (firstWriteAtRead == null) firstWriteAtRead = reads
            val count = minOf(2, bytes.size)
            writes += bytes.copyOfRange(0, count)
            return TLSClientProgress(TLSClientState.OPEN, count, listOf(CborValue.Bytes(bytes.copyOfRange(0, count))), emptyList())
        }
        override fun endOfInput(): TLSClientProgress = throw IOException("abrupt EOF")
        override fun close() { closed = true }
        private fun batch(state: TLSClientState, encrypted: ByteArray? = null, plain: ByteArray? = null) =
            TLSClientProgress(state, 0, encrypted?.let { listOf(CborValue.Bytes(it)) } ?: emptyList(),
                plain?.let { listOf(CborValue.Bytes(it)) } ?: emptyList())
    }
    private class Carrier : EncryptedRecordTransport {
        override val maximumMessageBytes = 3
        val inbound = Channel<ByteArray>(8)
        val sent = mutableListOf<ByteArray>()
        var closes = 0
        var sendGate: CompletableDeferred<Unit>? = null
        var closeGate: CompletableDeferred<Unit>? = null
        override suspend fun send(ciphertext: ByteArray) {
            sendGate?.await()
            check(closes == 0)
            sent += ciphertext.copyOf()
        }
        override suspend fun receive() = inbound.receiveCatching().getOrNull()
        override fun close() { closes++; inbound.cancel() }
        override suspend fun awaitClosed() { closeGate?.await() }
    }
    private class Fixture(val carrier: Carrier, val engine: Engine, val session: TLSRecordSession)
    private fun TestScope.fixture(timeout: Long = 1_000): Fixture {
        val carrier = Carrier()
        val engine = Engine()
        return Fixture(carrier, engine, TLSRecordSession(backgroundScope, engine, carrier, timeout, StandardTestDispatcher(testScheduler)))
    }
    private suspend fun TestScope.open(f: Fixture) {
        f.carrier.inbound.send(byteArrayOf(1))
        runCurrent()
        f.session.awaitOpen()
    }

    @Test fun splitsCiphertextAndRetainsPartiallyConsumedWrites(): Unit = runTest {
        val f = fixture(); open(f)
        assertEquals(listOf(3, 2), f.carrier.sent.map { it.size })
        val write = async { f.session.send(byteArrayOf(1, 2, 3, 4, 5)) }
        runCurrent(); write.await()
        assertEquals(listOf(2, 2, 1), f.engine.writes.map { it.size })
        assertContentEquals(byteArrayOf(1, 2, 3, 4, 5), f.engine.writes.flatMap { it.toList() }.toByteArray())
        f.session.closeAndJoin()
        assertTrue(f.engine.closed); assertEquals(1, f.carrier.closes)
    }

    @Test fun applicationBackpressureDoesNotBlockAnIndependentWrite(): Unit = runTest {
        val f = fixture(); open(f)
        f.carrier.inbound.send(byteArrayOf(4)); runCurrent()
        val write = async { f.session.send(byteArrayOf(9)) }
        runCurrent(); write.await()
        repeat(4) { assertContentEquals(byteArrayOf(it.toByte()), f.session.receive()) }
        f.session.closeAndJoin()
    }

    @Test fun resumesAWriteAfterTlsNeedsMorePeerInput(): Unit = runTest {
        val f = fixture(); open(f)
        f.engine.pauseNextWrite = true
        val write = async { f.session.send(byteArrayOf(7)) }
        runCurrent(); assertFalse(write.isCompleted)
        f.carrier.inbound.send(byteArrayOf(1)); runCurrent(); write.await()
        assertContentEquals(byteArrayOf(7), f.engine.writes.single())
        f.session.closeAndJoin()
    }

    @Test fun aHandshakeDeadlineReleasesBothOwners(): Unit = runTest {
        val f = fixture(timeout = 20)
        runCurrent(); advanceTimeBy(21); runCurrent()
        assertFailsWith<IOException> { f.session.awaitOpen() }
        assertTrue(f.engine.closed); assertEquals(1, f.carrier.closes)
    }

    @Test fun closeDiscardsBufferedPlaintextAndRejectsNewOperations(): Unit = runTest {
        val f = fixture(); open(f)
        f.carrier.inbound.send(byteArrayOf(2)); runCurrent()
        f.session.closeAndJoin(); f.session.close()
        assertFailsWith<IOException> { f.session.receive() }
        assertFailsWith<IOException> { f.session.send(byteArrayOf(9)) }
        assertEquals(1, f.carrier.closes)
    }

    @Test fun authenticatedCloseDrainsPlaintextThenReturnsEof(): Unit = runTest {
        val f = fixture(); open(f)
        f.carrier.inbound.send(byteArrayOf(2)); f.carrier.inbound.send(byteArrayOf(3)); runCurrent()
        assertContentEquals(byteArrayOf(42), f.session.receive())
        assertContentEquals(byteArrayOf(43), f.session.receive())
        assertNull(f.session.receive()); runCurrent()
        assertTrue(f.engine.closed); assertEquals(1, f.carrier.closes)
        f.session.closeAndJoin()
    }

    @Test fun abruptEofDoesNotInventAnAuthenticatedClose(): Unit = runTest {
        val f = fixture(); open(f)
        f.carrier.inbound.close(); runCurrent()
        assertFailsWith<IOException> { f.session.receive() }
        assertTrue(f.engine.closed); assertEquals(1, f.carrier.closes)
    }

    @Test fun cancellingAReaderAbortsABlockedWriter(): Unit = runTest {
        val f = fixture(); open(f)
        f.carrier.sendGate = CompletableDeferred()
        val writer = async { runCatching { f.session.send(byteArrayOf(9)) } }
        val reader = launch { f.session.receive() }
        runCurrent(); reader.cancelAndJoin(); runCurrent()
        assertTrue(writer.await().isFailure)
        assertEquals(2, f.carrier.sent.size)
        assertTrue(f.engine.closed); assertEquals(1, f.carrier.closes)
    }

    @Test fun closeBeforeTheWorkerStartsStillReleasesTheEngine(): Unit = runTest {
        val f = fixture()
        f.session.closeAndJoin()
        assertTrue(f.engine.closed); assertEquals(1, f.carrier.closes)
        assertTrue(f.carrier.sent.isEmpty())
    }

    @Test fun handshakeDeadlineDoesNotIncludeApplicationConsumption(): Unit = runTest {
        val f = fixture(timeout = 20)
        f.carrier.inbound.send(byteArrayOf(4)); runCurrent()
        f.session.awaitOpen()
        advanceTimeBy(100); runCurrent()
        val write = async { f.session.send(byteArrayOf(9)) }
        runCurrent(); write.await()
        repeat(4) { assertContentEquals(byteArrayOf(it.toByte()), f.session.receive()) }
        f.session.closeAndJoin()
    }

    @Test fun closeAndJoinWaitsForCarrierJobs(): Unit = runTest {
        val f = fixture(); open(f)
        val gate = CompletableDeferred<Unit>()
        f.carrier.closeGate = gate
        val closing = async { f.session.closeAndJoin() }
        runCurrent(); assertFalse(closing.isCompleted)
        assertEquals(1, f.carrier.closes)
        gate.complete(Unit); runCurrent(); closing.await()
        assertTrue(f.engine.closed)
    }

    @Test fun ownsTheWebSocketFramerAndItsCleanupJobs(): Unit = runTest {
        val input = ByteChannel(autoFlush = true)
        val output = ByteChannel(autoFlush = true)
        var releases = 0
        val carrier = WebSocketRecordTransport(backgroundScope, input, output, 3, 1) { releases++ }
        val engine = Engine()
        val session = TLSRecordSession(backgroundScope, engine, carrier, 1_000, StandardTestDispatcher(testScheduler))
        input.writeFully(byteArrayOf(0x82.toByte(), 1, 1))
        runCurrent(); session.awaitOpen()
        input.writeFully(byteArrayOf(0x82.toByte(), 1, 2))
        runCurrent()
        assertContentEquals(byteArrayOf(42), session.receive())
        session.send(byteArrayOf(7))
        session.closeAndJoin()
        assertTrue(engine.closed); assertEquals(1, releases)
    }

    @Test fun finalPlaintextSurvivesPeerCloseDuringAStalledWrite(): Unit = runTest {
        val f = fixture(); open(f)
        f.engine.pauseNextWrite = true
        val writing = async { runCatching { f.session.send(byteArrayOf(9)) } }
        runCurrent(); assertFalse(writing.isCompleted)
        f.carrier.inbound.send(byteArrayOf(3)); runCurrent()
        assertTrue(writing.await().exceptionOrNull() is IOException)
        assertTrue(f.engine.writes.isEmpty())
        assertFailsWith<IOException> { f.session.send(byteArrayOf(10)) }
        assertContentEquals(byteArrayOf(43), f.session.receive())
        assertNull(f.session.receive())
        f.session.closeAndJoin()
    }

    @Test fun aReadyWriteGetsATurnUnderContinuousInput(): Unit = runTest {
        val f = fixture(); open(f)
        val readingBefore = f.engine.reads
        val producer = launch(start = CoroutineStart.UNDISPATCHED) {
            repeat(500) { f.carrier.inbound.send(byteArrayOf(1)) }
        }
        val writing = async(start = CoroutineStart.UNDISPATCHED) { f.session.send(byteArrayOf(9)) }
        runCurrent(); writing.await()
        assertTrue(assertNotNull(f.engine.firstWriteAtRead) <= readingBefore + 1)
        producer.cancelAndJoin()
        f.session.closeAndJoin()
    }

    @Test fun oversizedInputFailsWithoutPlaintext(): Unit = runTest {
        val f = fixture(); open(f)
        f.carrier.inbound.send(ByteArray(4)); runCurrent()
        assertFailsWith<IOException> { f.session.receive() }
        assertTrue(f.engine.closed)
    }
}
