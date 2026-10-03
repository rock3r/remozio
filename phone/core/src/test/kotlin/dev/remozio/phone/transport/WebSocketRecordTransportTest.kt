package dev.remozio.phone.transport

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readFully
import io.ktor.utils.io.writeFully
import java.io.IOException
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlin.coroutines.CoroutineContext
import kotlin.test.assertFailsWith
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class WebSocketRecordTransportTest {
    @Test fun rejectsAnOversizedFirstHeaderWithoutReadingItsBody(): Unit = runTest {
        val input = ByteChannel(autoFlush = true)
        input.writeFully(byteArrayOf(0x82.toByte(), 126, 1, 0))
        Fixture(this, input = input, limit = 32).use { f ->
            assertFailsWith<IOException> { f.transport.receive() }
            f.transport.closeAndJoin()
            assertEquals(1, f.releases.get())
        }
    }

    @Test fun rejectsAnOversizedFragmentedMessage(): Unit = runTest {
        Fixture(this, limit = 32).use { f ->
            f.input.writeFully(frame(0x02, ByteArray(20)))
            f.input.writeFully(frame(0x80, ByteArray(20)))
            assertFailsWith<IOException> { f.transport.receive() }
        }
    }

    @Test fun reassemblesFragmentsAndDrainsMessagesBeforePeerClose(): Unit = runTest {
        Fixture(this).use { f ->
            f.input.writeFully(frame(0x02, byteArrayOf(1, 2)))
            f.input.writeFully(frame(0x80, byteArrayOf(3, 4)))
            f.input.writeFully(frame(0x82, byteArrayOf(5)))
            f.input.writeFully(frame(0x88, byteArrayOf(3, 0xe8.toByte())))
            runCurrent()
            assertArrayEquals(byteArrayOf(1, 2, 3, 4), f.transport.receive())
            assertArrayEquals(byteArrayOf(5), f.transport.receive())
            assertNull(f.transport.receive())
            f.transport.closeAndJoin()
            assertEquals(1, f.releases.get())
        }
    }

    @Test fun masksOutputAndCopiesAcceptedCallerBytes(): Unit = runTest {
        Fixture(this).use { f ->
            val bytes = byteArrayOf(7, 8, 9)
            f.transport.send(bytes)
            bytes.fill(0)
            val (opcode, payload) = clientFrame(f.output)
            assertEquals(0x82, opcode)
            assertArrayEquals(byteArrayOf(7, 8, 9), payload)
        }
    }

    @Test fun rejectsTextAndUnsupportedReservedBits(): Unit = runTest {
        for (opcode in listOf(0x81, 0xc2)) {
            Fixture(this).use { f ->
                f.input.writeFully(frame(opcode, byteArrayOf(1)))
                assertFailsWith<IOException> { f.transport.receive() }
                assertFailsWith<IOException> { f.transport.send(byteArrayOf(1)) }
            }
        }
    }

    @Test fun respondsToPingWithoutExposingControlFrames(): Unit = runTest {
        Fixture(this).use { f ->
            f.input.writeFully(frame(0x89, byteArrayOf(2, 3)))
            f.input.writeFully(frame(0x82, byteArrayOf(4)))
            assertArrayEquals(byteArrayOf(4), f.transport.receive())
            val (opcode, payload) = clientFrame(f.output)
            assertEquals(0x8a, opcode)
            assertArrayEquals(byteArrayOf(2, 3), payload)
        }
    }

    @Test fun appliesBackpressureAndCancellationReleasesTheTransport(): Unit = runTest {
        Fixture(this, queue = 1).use { f ->
            var accepted = 0
            val writer = launch {
                repeat(1_000_000) { f.transport.send(ByteArray(32)); accepted++ }
            }
            runCurrent()
            assertTrue(accepted > 0)
            assertFalse(writer.isCompleted)
            writer.cancelAndJoin()
            f.transport.closeAndJoin()
            assertEquals(1, f.releases.get())
        }
    }

    @Test fun cancelledReadAndParentCancellationCloseOnlyOnce(): Unit = runTest {
        Fixture(this).use { f ->
            val reader = launch { f.transport.receive() }
            runCurrent()
            reader.cancelAndJoin()
            f.transport.closeAndJoin()
            assertEquals(1, f.releases.get())
        }
        val parent = SupervisorJob(coroutineContext[Job])
        Fixture(CoroutineScope(coroutineContext + parent)).use { f ->
            parent.cancelAndJoin()
            f.transport.closeAndJoin()
            assertEquals(1, f.releases.get())
        }
    }

    @Test fun oversizedSendCanBeSplitWithoutClosingTheChannel(): Unit = runTest {
        Fixture(this, limit = 4).use { f ->
            assertFailsWith<IllegalArgumentException> { f.transport.send(ByteArray(5)) }
            f.transport.send(byteArrayOf(1, 2))
            assertArrayEquals(byteArrayOf(1, 2), clientFrame(f.output).second)
        }
    }

    @Test fun alreadyCancelledParentCannotLeaveAReceiverWaiting(): Unit = runTest {
        val parent = SupervisorJob()
        parent.cancel()
        Fixture(CoroutineScope(coroutineContext + parent)).use { f ->
            assertFailsWith<IOException> { f.transport.receive() }
            f.transport.closeAndJoin()
            assertEquals(1, f.releases.get())
        }
    }

    @Test fun closeAndJoinWaitsForDetachedLibraryJobs(): Unit = runTest {
        val gate = DefaultSessionGate(StandardTestDispatcher(testScheduler))
        val f = Fixture(CoroutineScope(coroutineContext + gate))
        try {
            assertTrue(gate.hasHeldTask())
            val closer = async { f.transport.closeAndJoin() }
            runCurrent()
            assertFalse(closer.isCompleted)
            gate.release()
            closer.await()
            assertEquals(1, f.releases.get())
        } finally { gate.release(); f.transport.closeAndJoin() }
    }

    /** Hold the pinned library's default-session coordinator while raw transport jobs can stop. */
    private class DefaultSessionGate(private val delegate: CoroutineDispatcher) : CoroutineDispatcher() {
        private val held = mutableListOf<Pair<CoroutineContext, Runnable>>()
        private var holding = true
        override fun dispatch(context: CoroutineContext, block: Runnable) {
            if (holding && context[CoroutineName]?.name == "ws-default") held += context to block
            else delegate.dispatch(context, block)
        }
        fun hasHeldTask(): Boolean = held.isNotEmpty()
        fun release() {
            holding = false
            val tasks = held.toList()
            held.clear()
            tasks.forEach { (context, block) -> delegate.dispatch(context, block) }
        }
    }

    private class Fixture(parent: CoroutineScope, val input: ByteChannel = ByteChannel(autoFlush = true), limit: Int = 64, queue: Int = 2) : AutoCloseable {
        val output = ByteChannel(autoFlush = true)
        val releases = AtomicInteger()
        val transport = WebSocketRecordTransport(parent, input, output, limit, queue) { releases.incrementAndGet() }
        override fun close() = transport.close()
    }
    private fun frame(first: Int, payload: ByteArray): ByteArray {
        require(payload.size <= 125)
        return byteArrayOf(first.toByte(), payload.size.toByte()) + payload
    }
    private suspend fun clientFrame(output: ByteChannel): Pair<Int, ByteArray> {
        val first = output.readByte().toInt() and 0xff
        val second = output.readByte().toInt() and 0xff
        assertTrue(second and 0x80 != 0)
        val count = second and 0x7f
        require(count <= 125)
        val mask = ByteArray(4).also { output.readFully(it) }
        val bytes = ByteArray(count).also { output.readFully(it) }
        bytes.indices.forEach { bytes[it] = (bytes[it].toInt() xor mask[it % 4].toInt()).toByte() }
        return first to bytes
    }
}
