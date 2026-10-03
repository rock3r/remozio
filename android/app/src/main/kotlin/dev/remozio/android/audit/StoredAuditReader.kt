package dev.remozio.android.audit

import dev.remozio.phone.audit.*
import dev.remozio.phone.enrollment.EncryptedEnrollmentStore
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.*
import java.util.Collections
import javax.crypto.AEADBadTagException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

internal class AuditMacOption(val macID: CborValue.Bytes, val label: String) {
    override fun toString() = "AuditMacOption(redacted)"
}

internal sealed interface CachedAuditContent {
    data object Missing : CachedAuditContent
    data object Unavailable : CachedAuditContent
    class Loaded(val snapshot: AuditEvidenceSnapshot, val history: AuditHistoryGroup) : CachedAuditContent {
        override fun toString() = "CachedAuditContent.Loaded(redacted)"
    }
}

internal class CachedAuditScope(val scope: AuditHistoryScope, val label: String, val content: CachedAuditContent) {
    override fun toString() = "CachedAuditScope(redacted)"
}

internal sealed interface StoredAuditState {
    data object Loading : StoredAuditState
    data object Unavailable : StoredAuditState
    class Ready(macs: List<AuditMacOption>, scopes: List<CachedAuditScope>) : StoredAuditState {
        val macs: List<AuditMacOption> = Collections.unmodifiableList(macs.toList())
        val scopes: List<CachedAuditScope> = Collections.unmodifiableList(scopes.toList())
        override fun toString() = "StoredAuditState.Ready(redacted)"
    }
}

/** Read budgets bound retained proof bytes; reaching one never deletes or rewrites retained evidence. */
internal class AuditReadBudget(val perArchiveBytes: Int = 16_777_216, val totalBytes: Int = 33_554_432) {
    init { require(perArchiveBytes in 1..16_777_216 && totalBytes in perArchiveBytes..67_108_864) }
}

/** No callbacks may create a key, reset an archive, connect to a peer, or grant current authority. */
internal class StoredAuditReader(
    private val openEnrollments: () -> EncryptedEnrollmentStore?,
    private val openCache: (AuditCacheBinding, Int) -> EncryptedAuditCache?,
    private val budget: AuditReadBudget = AuditReadBudget(),
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    private val mutex = Mutex()

    suspend fun read(macID: CborValue.Bytes? = null, category: AuditCategory? = null,
                     outcome: AuditOutcome? = null): StoredAuditState = mutex.withLock {
        try {
            withContext(dispatcher) {
                val rows = openEnrollments()?.use { it.snapshot().entries } ?: emptyList()
                // Prepared setups are not an established source of history. Removed rows keep cache bindings.
                val retained = rows.filter { it.phase != EnrollmentPhase.PREPARED }
                val groups = retained.groupBy { AuditHistoryScope(it.enrollment.macID, it.enrollment.accountID) }
                    .toList().sortedWith(compareBy({ hex(it.first.macID) }, { hex(it.first.accountID) }))
                val options = retained.groupBy { it.enrollment.macID }.toList().sortedBy { hex(it.first) }
                    .map { (id, entries) -> AuditMacOption(id, label(entries)) }
                var remaining = budget.totalBytes
                val scopes = groups.filter { macID == null || it.first.macID == macID }.map { (scope, entries) ->
                    currentCoroutineContext().ensureActive()
                    val content = if (remaining <= 0) CachedAuditContent.Unavailable else {
                        val limit = minOf(remaining, budget.perArchiveBytes)
                        readScope(entries, limit, category, outcome).also {
                            if (it is CachedAuditContent.Loaded) remaining -= it.snapshot.storedBytes.toInt()
                        }
                    }
                    CachedAuditScope(scope, label(entries), content)
                }
                StoredAuditState.Ready(options, scopes)
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            StoredAuditState.Unavailable
        }
    }

    private suspend fun readScope(entries: List<StoredPhoneEnrollment>, maximumBytes: Int,
                                  category: AuditCategory?, outcome: AuditOutcome?): CachedAuditContent {
        val bindings = entries.asReversed().sortedBy { it.phase != EnrollmentPhase.ACTIVE }
            .map { it.enrollment }.distinctBy { it.authorityPublicKey }
        try {
            for (entry in bindings) {
                currentCoroutineContext().ensureActive()
                val binding = AuditCacheBinding(entry.macID.copyBytes(), entry.accountID.copyBytes(), entry.authorityPublicKey.copyBytes())
                try {
                    val snapshot = openCache(binding, maximumBytes)?.use { it.snapshot() } ?: return CachedAuditContent.Missing
                    check(snapshot.scope == AuditHistoryScope(entry.macID, entry.accountID))
                    check(snapshot.storedBytes <= maximumBytes)
                    val history = AuditHistory.list(listOf(snapshot), AuditHistoryFilter(
                        categories = category?.let { setOf(it) }, outcomes = outcome?.let { setOf(it) },
                    )).single()
                    return CachedAuditContent.Loaded(snapshot, history)
                } catch (_: AEADBadTagException) {
                    // A retained archive can belong to a former authority key for this same Mac/account.
                }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            return CachedAuditContent.Unavailable
        }
        return CachedAuditContent.Unavailable
    }

    private fun label(entries: List<StoredPhoneEnrollment>) =
        (entries.lastOrNull { it.phase == EnrollmentPhase.ACTIVE } ?: entries.last()).enrollment.label
    private fun hex(bytes: CborValue.Bytes) = bytes.copyBytes().joinToString("") { "%02x".format(it) }
}
