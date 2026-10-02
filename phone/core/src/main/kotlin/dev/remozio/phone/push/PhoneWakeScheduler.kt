package dev.remozio.phone.push

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Drains complete-set fetch demand without holding the router lock during network work.
 * The fetch adapter must authenticate retained enrollment pins and recheck its reservation around awaits.
 * This owner cancels work and closes its router when its parent scope ends. It never signs a decision.
 */
class PhoneWakeScheduler(
    parent: CoroutineScope,
    private val router: PushWakeRouter,
    private val maximumConcurrentFetches: Int,
    private val retryIntervalMillis: Long,
    private val fetchTimeoutMillis: Long,
    private val elapsedMillis: () -> Long,
    private val fetch: suspend (WakeFetch) -> Unit,
) : AutoCloseable {
    private class Flight(val reservation: WakeFetch) {
        lateinit var job: Job
        @Volatile var successful = false
    }
    private val changed = Channel<Unit>(Channel.CONFLATED)
    private val owner: Job

    init {
        require(maximumConcurrentFetches in 1..64)
        require(retryIntervalMillis in 1..60_000 && fetchTimeoutMillis in 1..300_000)
        owner = parent.launch { run() }
        owner.invokeOnCompletion { router.close(); changed.close() }
    }

    /** Call after receiving a wake or removing an enrollment. Signals coalesce; demand stays in the router. */
    fun signal() { changed.trySend(Unit) }

    override fun close() { router.close(); owner.cancel() }

    /** Await cooperative fetch cleanup before releasing the host's transport or key resources. */
    suspend fun closeAndJoin() { close(); owner.cancelAndJoin() }

    private suspend fun run(): Unit = coroutineScope {
        val flights = linkedMapOf<WakeEnrollment, Flight>()
        val retryAt = mutableMapOf<WakeEnrollment, Long>()
        var lastStarted: WakeEnrollment? = null
        var previousTime = -1L
        try {
            while (isActive) {
                val now = elapsedMillis()
                if (now < 0 || now < previousTime) return@coroutineScope
                previousTime = now
                retryAt.keys.removeAll { !router.contains(it) }
                val completed = flights.filterValues { it.job.isCompleted }
                for ((enrollment, flight) in completed) {
                    flights.remove(enrollment)
                    if (router.finishFetch(flight.reservation, flight.successful)) {
                        if (flight.successful) retryAt.remove(enrollment)
                        else retryAt[enrollment] = if (now > Long.MAX_VALUE - retryIntervalMillis) Long.MAX_VALUE else now + retryIntervalMillis
                    }
                }
                for (flight in flights.values) {
                    if (!router.isCurrent(flight.reservation)) flight.job.cancel()
                }
                val pending = router.pendingFetches()
                val pivot = pending.indexOf(lastStarted).let { if (it < 0) 0 else (it + 1) % pending.size }
                val ordered = pending.drop(pivot) + pending.take(pivot)
                for (enrollment in ordered) {
                    if (flights.size >= maximumConcurrentFetches) break
                    if (enrollment in flights || (retryAt[enrollment] ?: 0) > now) continue
                    val reservation = router.beginFetch(enrollment) ?: continue
                    val flight = Flight(reservation)
                    flight.job = launch(start = CoroutineStart.LAZY) {
                        flight.successful = try {
                            withTimeoutOrNull(fetchTimeoutMillis) {
                                if (router.isCurrent(reservation)) { fetch(reservation); true } else false
                            } == true
                        } catch (_: CancellationException) {
                            currentCoroutineContext().ensureActive()
                            false
                        } catch (_: Exception) { false }
                    }
                    flights[enrollment] = flight
                    lastStarted = enrollment
                    flight.job.invokeOnCompletion { signal() }
                    flight.job.start()
                }
                // Only backoff needs a timer. Idle owners and occupied slots wait for a signal or completion.
                val wait = if (flights.size < maximumConcurrentFetches) router.pendingFetches()
                    .filter { it !in flights }.mapNotNull { retryAt[it] }.filter { it > now }
                    .minOrNull()?.minus(now) else null
                if (wait == null) changed.receive() else withTimeoutOrNull(wait) { changed.receive() }
            }
        } finally {
            router.close()
            flights.values.forEach { it.job.cancel() }
        }
    }
}
