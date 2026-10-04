package dev.remozio.phone.transport

import java.io.IOException
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.test.*
import org.junit.Test
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class ApprovalChannelConnectorTest {
    @Test fun selectsTheFirstAuthenticatedDirectRouteWithoutOpeningRelay(): Unit = runTest {
        val opened = mutableListOf<Int>()
        val released = mutableListOf<Int>()
        val result = directFirst(flowOf(1, 2, 3), 99, 1000,
            { opened += it; if (it == 1) throw IOException(); it }, { released += it })
        assertEquals(2, result)
        assertEquals(listOf(1, 2), opened)
        assertTrue(released.isEmpty())
    }

    @Test fun aSingleBudgetIncludesDiscoveryAndAuthentication(): Unit = runTest {
        val opened = mutableListOf<Int>()
        var cleaned = false
        val result = directFirst(flow { delay(600); emit(1) }, 99, 1000, {
            opened += it
            if (it == 1) try { delay(500) } finally { cleaned = true }
            if (it == 99) assertTrue(cleaned)
            it
        }, { })
        assertEquals(99, result)
        assertEquals(listOf(1, 99), opened)
        assertEquals(1000L, currentTime)
    }

    @Test fun deniedDiscoveryAndFailedAuthenticationFallBack(): Unit = runTest {
        for (direct in listOf(flow<Int> { throw SecurityException() }, flowOf(1))) {
            assertEquals(99, directFirst(direct, 99, 1000,
                { if (it == 1) throw IOException(); it }, { }))
        }
        assertFailsWith<IOException> { directFirst(emptyFlow<Int>(), null, 1000, { it }, { }) }
    }

    @Test fun cancellationDoesNotAttemptRelay(): Unit = runTest {
        val opened = mutableListOf<Int>()
        val attempt = launch { directFirst(flowOf(1), 99, 1000, { opened += it; awaitCancellation() }, { _: Nothing -> }) }
        runCurrent(); attempt.cancelAndJoin()
        assertEquals(listOf(1), opened)
    }

    @Test fun directCandidateCountIsBounded(): Unit = runTest {
        val opened = mutableListOf<Int>()
        val result = directFirst((1..100).asFlow(), 99, 1000, {
            opened += it; if (it != 99) throw IOException(); it
        }, { })
        assertEquals(99, result)
        assertEquals((1..8).toList() + 99, opened)
    }

    @Test fun cancelledHandoffReleasesTheSuccessfulDirectChannel(): Unit = runTest {
        val released = mutableListOf<Int>()
        val job = launch {
            directFirst<Int, Int>(flowOf(1), 99, 1000, {
                currentCoroutineContext().cancel()
                it
            }, { released += it })
        }
        job.join()
        assertEquals(listOf(1), released)
    }
}
