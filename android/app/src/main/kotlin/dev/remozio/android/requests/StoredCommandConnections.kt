package dev.remozio.android.requests

import dev.remozio.phone.enrollment.EncryptedEnrollmentStore
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.CborValue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Application-owned connections survive screen recreation and ordinary network failures. */
internal class StoredCommandConnections(
    private val open: () -> EncryptedEnrollmentStore?,
    private val create: (StoredPhoneEnrollment) -> CommandConnection,
    private val enrollmentAccess: Mutex,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    private val owners = mutableMapOf<CborValue.Bytes, CommandConnection>()

    /** Revalidates the complete archive before returning an existing owner or opening its request index. */
    suspend fun acquire(recordID: CborValue.Bytes): CommandConnection = withContext(dispatcher) {
        enrollmentAccess.withLock {
            val rows = try {
                open()?.use { it.snapshot().entries } ?: emptyList()
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) {
                invalidateLocked()
                throw CommandRegistryUnavailable()
            }
            val active = rows.filter { it.phase == EnrollmentPhase.ACTIVE }.associateBy { it.enrollment.recordID }
            val stale = owners.filter { (id, owner) -> active[id]?.sameConnectionAs(owner.record) != true }
            // Invalidate every changed incarnation before constructing any replacement.
            stale.keys.forEach { owners.remove(it) }
            closeAll(stale.values)
            val record = active[recordID] ?: throw CommandEnrollmentUnavailable()
            owners[recordID] ?: try {
                create(record).also { owners[recordID] = it }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { throw CommandRegistryUnavailable() }
        }
    }

    /** Setup must call this before committing enrollment changes, under the same enrollment mutex. */
    internal fun invalidateLocked() {
        val previous = owners.values.toList()
        owners.clear()
        closeAll(previous)
    }

    /** The application enrollment host holds the shared mutex while retiring these records. */
    internal fun invalidateRecordsLocked(recordIDs: Set<CborValue.Bytes>) {
        val previous = recordIDs.mapNotNull { owners.remove(it) }
        closeAll(previous)
    }

    suspend fun invalidate() = withContext(dispatcher) {
        enrollmentAccess.withLock { invalidateLocked() }
    }

    private fun closeAll(connections: Collection<CommandConnection>) {
        var failed = false
        connections.forEach { try { it.close() } catch (_: Exception) { failed = true } }
        if (failed) throw CommandRegistryUnavailable()
    }
}

internal class CommandEnrollmentUnavailable : IllegalStateException("Enrollment is not active")
internal class CommandRegistryUnavailable : IllegalStateException("Command storage unavailable")
