package dev.remozio.phone.push

import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.PushData
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.withContext
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class PhoneWakeSchedulerTest {
    private fun bytes(value: Int, size: Int = 16) = ByteArray(size) { value.toByte() }
    private fun router() = PushWakeRouter(8, 16, 16, 60_000uL, 100uL)
    private fun add(r: PushWakeRouter, n: Int = 1) = r.add(bytes(n), bytes(2), bytes(3), bytes(n, 32))
    private fun TestScope.wake(r: PushWakeRouter, e: WakeEnrollment, id: Int = 1) = r.receive(
        PushData.Wake(bytes(id, 32), e.notificationTag.copyBytes()).encode(),
        { ElapsedInstant(1, testScheduler.currentTime.toULong()) }) { _, _ -> WakeNotificationResult.POSTED }
    private fun TestScope.scheduler(r: PushWakeRouter, slots: Int = 2, fetch: suspend (WakeFetch) -> Unit) =
        PhoneWakeScheduler(this, r, slots, 100, 1_000, { testScheduler.currentTime }, fetch)

    @Test fun startsExistingDemandAndDoesNotPollWhenIdle() = runTest {
        val r = router(); val e = add(r); wake(r, e)
        var count = 0
        val s = scheduler(r) { count++ }
        try {
            runCurrent(); assertEquals(1, count)
            advanceTimeBy(10_000); runCurrent(); assertEquals(1, count)
            assertNull(r.beginFetch(e))
        } finally { s.closeAndJoin() }
    }

    @Test fun wakeDuringFetchRunsAgainButDuplicateDoesNot() = runTest {
        val r = router(); val e = add(r); val release = CompletableDeferred<Unit>(); var count = 0
        val s = scheduler(r) { count++; if (count == 1) release.await() }
        try {
            wake(r, e); s.signal(); runCurrent(); assertEquals(1, count)
            wake(r, e); s.signal(); runCurrent(); assertEquals(1, count)
            wake(r, e, 2); s.signal(); release.complete(Unit); runCurrent()
            assertEquals(2, count); assertNull(r.beginFetch(e))
        } finally { s.closeAndJoin() }
    }

    @Test fun failedMacBackoffDoesNotBlockAnotherMacWithOneSlot() = runTest {
        val r = router(); val a = add(r); val b = add(r, 2); val starts = mutableListOf<WakeEnrollment>()
        val s = scheduler(r, 1) { starts += it.enrollment; if (it.enrollment === a) error("offline") }
        try {
            wake(r, a); wake(r, b); s.signal(); runCurrent()
            assertEquals(listOf(a, b), starts)
            advanceTimeBy(99); runCurrent(); assertEquals(2, starts.size)
            advanceTimeBy(1); runCurrent(); assertEquals(listOf(a, b, a), starts)
        } finally { s.closeAndJoin() }
    }

    @Test fun timeoutReleasesSlotAndRetainsDemandForRetry() = runTest {
        val r = router(); val a = add(r); val b = add(r, 2); val starts = mutableListOf<WakeEnrollment>()
        val s = scheduler(r, 1) { starts += it.enrollment; if (it.enrollment === a) awaitCancellation() }
        try {
            wake(r, a); wake(r, b); s.signal(); runCurrent(); assertEquals(listOf(a), starts)
            advanceTimeBy(1_000); runCurrent(); assertEquals(listOf(a, b), starts)
            advanceTimeBy(100); runCurrent(); assertEquals(listOf(a, b, a), starts)
        } finally { s.closeAndJoin() }
    }

    @Test fun independentCancellationFromFetchBacksOffInsteadOfSpinning() = runTest {
        val r = router(); val e = add(r); var count = 0
        val s = scheduler(r) { count++; throw kotlinx.coroutines.CancellationException("adapter cancelled") }
        try {
            wake(r, e); s.signal(); runCurrent(); assertEquals(1, count)
            advanceTimeBy(99); runCurrent(); assertEquals(1, count)
            advanceTimeBy(1); runCurrent(); assertEquals(2, count)
        } finally { s.closeAndJoin() }
    }

    @Test fun removalCancelsFlightAndCannotClearReplacementDemand() = runTest {
        val r = router(); val old = add(r); val starts = mutableListOf<WakeEnrollment>(); var cancelled = false
        val s = scheduler(r, 1) { starts += it.enrollment; if (it.enrollment === old) try { awaitCancellation() } finally { cancelled = true } }
        try {
            wake(r, old); s.signal(); runCurrent()
            assertTrue(r.remove(old)); val next = r.add(bytes(1), bytes(2), bytes(4), bytes(9, 32))
            wake(r, next); s.signal(); runCurrent()
            assertTrue(cancelled); assertEquals(listOf(old, next), starts); assertNull(r.beginFetch(next))
        } finally { s.closeAndJoin() }
    }

    @Test fun cancelledWorkerKeepsItsSlotUntilCleanupCompletes() = runTest {
        val r = router(); val a = add(r); val b = add(r, 2); val cleanup = CompletableDeferred<Unit>()
        val starts = mutableListOf<WakeEnrollment>()
        val s = scheduler(r, 1) { starts += it.enrollment; if (it.enrollment === a) try { awaitCancellation() }
            finally { withContext(NonCancellable) { cleanup.await() } } }
        try {
            wake(r, a); wake(r, b); s.signal(); runCurrent()
            r.remove(a); s.signal(); runCurrent(); assertEquals(listOf(a), starts)
            cleanup.complete(Unit); runCurrent(); assertEquals(listOf(a, b), starts)
        } finally { cleanup.complete(Unit); s.closeAndJoin() }
    }

    @Test fun signalsCoalesceWithoutLosingDemandOrExceedingCapacity() = runTest {
        val r = router(); val enrollments = (1..6).map { add(r, it) }
        val release = CompletableDeferred<Unit>(); var active = 0; var peak = 0; val starts = mutableListOf<WakeEnrollment>()
        val s = scheduler(r, 2) { starts += it.enrollment; active++; peak = maxOf(peak, active)
            try { release.await() } finally { active-- } }
        try {
            enrollments.forEach { wake(r, it); repeat(100) { s.signal() } }
            runCurrent(); assertEquals(2, starts.size)
            release.complete(Unit); runCurrent()
            assertEquals(enrollments.toSet(), starts.toSet()); assertEquals(6, starts.size); assertEquals(2, peak)
        } finally { s.closeAndJoin() }
    }

    @Test fun closeInvalidatesReservationsAndJoinsCleanup() = runTest {
        val r = router(); val e = add(r); var reservation: WakeFetch? = null; var cleaned = false
        val s = scheduler(r) { reservation = it; try { awaitCancellation() } finally { cleaned = true } }
        wake(r, e); s.signal(); runCurrent(); s.closeAndJoin()
        assertTrue(cleaned); assertFalse(r.isCurrent(requireNotNull(reservation)))
        assertEquals(WakeReception.CLOSED, wake(r, e).reception)
        s.signal(); advanceTimeBy(10_000); runCurrent()
    }

    @Test fun regressingSchedulerClockClosesOwnerWithoutRestartingIt() = runTest {
        val r = router(); val e = add(r); var now = 10L
        val s = PhoneWakeScheduler(this, r, 1, 100, 1_000, { now }) { awaitCancellation() }
        wake(r, e); s.signal(); runCurrent(); now = 9; s.signal(); runCurrent()
        assertEquals(WakeReception.CLOSED, wake(r, e).reception)
        s.closeAndJoin()
    }
}
