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
    private val closeConnection: (CommandConnection) -> Unit = { it.close() },
) {
    private val failedClosures = mutableSetOf<CborValue.Bytes>()
    private val owners = mutableMapOf<CborValue.Bytes, CommandConnection>()

    /** Revalidates the complete archive before returning an existing owner or opening its request index. */
    suspend fun acquire(recordID: CborValue.Bytes): CommandConnection = withContext(dispatcher) {
        enrollmentAccess.withLock {
            if (recordID in failedClosures) throw CommandRegistryUnavailable()
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
            invalidateRecordsLocked(stale.keys)
            val record = active[recordID] ?: throw CommandEnrollmentUnavailable()
            owners[recordID] ?: try {
                create(record).also { owners[recordID] = it }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { throw CommandRegistryUnavailable() }
        }
    }

    /** Setup must call this before committing enrollment changes, under the same enrollment mutex. */
    internal fun invalidateLocked() {
        invalidateRecordsLocked(owners.keys.toSet() + failedClosures)
    }

    /** The application enrollment host holds the shared mutex while retiring these records. */
    internal fun invalidateRecordsLocked(recordIDs: Set<CborValue.Bytes>) {
        recordIDs.forEach { id ->
            val owner = owners.remove(id)
            if (owner != null) {
                try { closeConnection(owner) } catch (_: Exception) { failedClosures.add(id) }
            }
        }
        if (recordIDs.any { it in failedClosures }) throw CommandRegistryUnavailable()
    }

    suspend fun invalidate() = withContext(dispatcher) {
        enrollmentAccess.withLock { invalidateLocked() }
    }


}

internal class CommandEnrollmentUnavailable : IllegalStateException("Enrollment is not active")
internal class CommandRegistryUnavailable : IllegalStateException("Command storage unavailable")
