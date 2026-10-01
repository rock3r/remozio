package dev.remozio.phone.audit

import dev.remozio.protocol.*
import java.util.Collections

/** Stable identities, independent of editable device and account labels. */
data class AuditHistoryScope(val macID: CborValue.Bytes, val accountID: CborValue.Bytes) {
    init { require(macID.size == 16 && accountID.size == 16) }
}

/** Null selects all values; an empty set selects none. Filters never change gap or conflict evidence. */
class AuditHistoryFilter(
    macIDs: Set<CborValue.Bytes>? = null,
    categories: Set<AuditCategory>? = null,
    outcomes: Set<AuditOutcome>? = null,
) {
    val macIDs = macIDs?.let { immutableSet(it) }
    val categories = categories?.let { immutableSet(it) }
    val outcomes = outcomes?.let { immutableSet(it) }
    init { require(this.macIDs?.all { it.size == 16 } != false) }
    internal fun includes(event: AuditEventMetadata) =
        (categories == null || event.category in categories) && (outcomes == null || event.outcome in outcomes)
}

/** Records follow sequence order, never wall time. Gaps cover the whole epoch, including filtered records. */
class AuditHistoryEpoch internal constructor(
    val epoch: CborValue.Bytes,
    val generation: ULong,
    val descriptor: AuditEpochDescriptor?,
    val highestObservedHead: ULong,
    val highestRetainedAfter: ULong,
    val retainedRecordCount: Int,
    records: List<AuditEventMetadata>,
    gaps: List<AuditHistoryGap>,
) {
    val records = immutableList(records)
    val gaps = immutableList(gaps)
}

/** One unambiguous predecessor chain. Separate chains have no established relative chronology. */
class AuditHistoryChain internal constructor(epochs: List<AuditHistoryEpoch>) {
    val epochs = immutableList(epochs)
}

/** A retained signed report. Arrival order does not establish the current epoch or a current sync result. */
class AuditHistoryReport internal constructor(val status: AuditHistoryStatus, conflicts: Set<AuditEvidenceConflict>) {
    val conflicts = immutableSet(conflicts)
}

/**
 * A read-only view of retained evidence, not a current-epoch or last-sync assertion.
 * Conflicting proofs stay quarantined; the first accepted records are not a resolution of the conflict.
 */
class AuditHistoryGroup internal constructor(
    val scope: AuditHistoryScope,
    chains: List<AuditHistoryChain>,
    conflicts: Set<AuditEvidenceConflict>,
    val conflictingProofCount: Int,
    reports: List<AuditHistoryReport>,
) {
    val chains = immutableList(chains)
    val reports = immutableList(reports)
    val conflicts = immutableSet(conflicts)
}

object AuditHistory {
    /** Mac/account groups and independent chains use stable identity order, not a global event chronology. */
    fun list(snapshots: List<AuditEvidenceSnapshot>, filter: AuditHistoryFilter = AuditHistoryFilter()): List<AuditHistoryGroup> {
        require(snapshots.map { it.scope }.toSet().size == snapshots.size) { "Duplicate audit history scope" }
        return immutableList(snapshots.filter { filter.macIDs == null || it.scope.macID in filter.macIDs }
            .sortedWith(compareBy({ identity(it.scope.macID) }, { identity(it.scope.accountID) }))
            .map { project(it, newestFirst = true, filter::includes) })
    }

    /** A request detail ignores list filters and retains all its events, with explicit epoch boundaries. */
    fun timeline(snapshot: AuditEvidenceSnapshot, requestID: ByteArray): AuditHistoryGroup {
        require(requestID.size == 16)
        val request = CborValue.Bytes(requestID)
        return project(snapshot, newestFirst = false) { it.requestID?.let(CborValue::Bytes) == request }
    }

    private fun project(snapshot: AuditEvidenceSnapshot, newestFirst: Boolean,
                        include: (AuditEventMetadata) -> Boolean): AuditHistoryGroup {
        val epochs = snapshot.epochs.associateBy { it.epoch }
        val previous = epochs.mapValues { (_, epoch) -> epoch.descriptor?.previousEpoch?.let(CborValue::Bytes) }
        val children = previous.values.filterNotNull().groupingBy { it }.eachCount()
        // A fork has no sibling order. Keep its branches and shared predecessor in separate chains.
        val linearPrevious = previous.mapNotNull { (epoch, prior) ->
            if (prior != null && prior in epochs && children[prior] == 1) epoch to prior else null
        }.toMap()
        val tips = (epochs.keys - linearPrevious.values.toSet()).sortedBy(::identity)
        val visited = HashSet<CborValue.Bytes>()
        val chains = tips.map { tip ->
            val chain = ArrayList<AuditEpochEvidence>()
            var cursor: CborValue.Bytes? = tip
            while (cursor != null) {
                check(visited.add(cursor)) { "Invalid audit epoch graph" }
                chain.add(epochs.getValue(cursor))
                cursor = linearPrevious[cursor]
            }
            val ordered = if (newestFirst) chain else chain.asReversed()
            AuditHistoryChain(ordered.map { epoch ->
                val records = epoch.records.filter(include).sortedBy { it.sequence }
                AuditHistoryEpoch(epoch.epoch, epoch.generation, epoch.descriptor, epoch.highestObservedHead,
                    epoch.highestRetainedAfter, epoch.records.size,
                    if (newestFirst) records.asReversed() else records, epoch.gaps)
            })
        }
        check(visited.size == epochs.size) { "Invalid audit epoch graph" }
        val conflicted = snapshot.proofs.filter { it.conflicts.isNotEmpty() }
        return AuditHistoryGroup(snapshot.scope, chains, conflicted.flatMap { it.conflicts }.toSet(), conflicted.size,
            snapshot.proofs.mapNotNull { proof -> proof.historyStatus?.let { AuditHistoryReport(it, proof.conflicts) } })
    }

    private fun identity(bytes: CborValue.Bytes) = bytes.copyBytes().joinToString("") { "%02x".format(it) }
}

private fun <T> immutableList(values: Collection<T>): List<T> = Collections.unmodifiableList(ArrayList(values))
private fun <T> immutableSet(values: Collection<T>): Set<T> = Collections.unmodifiableSet(LinkedHashSet(values))
