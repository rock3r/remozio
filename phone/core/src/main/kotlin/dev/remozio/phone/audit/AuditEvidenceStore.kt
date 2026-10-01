package dev.remozio.phone.audit

import dev.remozio.protocol.*
import java.security.MessageDigest
import java.util.Collections

enum class AuditEvidenceKind { PAGE, HISTORY_STATUS }
enum class AuditEvidenceAcceptance { ADDED, DUPLICATE, CONFLICT }
enum class AuditEvidenceConflict { GENERATION, DESCRIPTOR, RECORD, EVENT_ID, PRIOR_DIGEST, EPOCH_CYCLE }
enum class AuditEvidenceRejection { INVALID_SIGNATURE, WRONG_AUTHORITY, CAPACITY }
class AuditEvidenceException(val reason: AuditEvidenceRejection) : IllegalArgumentException(reason.name)

/** Resource limits halt ingestion at capacity. They never permit eviction or history pruning. */
class AuditEvidenceLimits(val maximumProofs: Int, val maximumBytes: Long, val maximumRecords: Int, val maximumEpochs: Int) {
    init { require(maximumProofs > 0 && maximumBytes > 0 && maximumRecords > 0 && maximumEpochs > 0) }
}

class StoredAuditProof internal constructor(
    val kind: AuditEvidenceKind,
    val canonicalBody: CborValue.Bytes,
    val signature: CborValue.Bytes,
    conflicts: Set<AuditEvidenceConflict>,
) {
    val conflicts: Set<AuditEvidenceConflict> = Collections.unmodifiableSet(LinkedHashSet(conflicts))
}

/** Missing sequences in (after, through]. A retention gap is reported, not permission to remove cached records. */
data class AuditHistoryGap(val after: ULong, val through: ULong, val belowRetentionBoundary: Boolean)
class AuditEpochEvidence internal constructor(
    val epoch: CborValue.Bytes,
    val generation: ULong,
    val descriptor: AuditEpochDescriptor?,
    val highestObservedHead: ULong,
    val highestRetainedAfter: ULong,
    records: List<AuditEventMetadata>,
    gaps: List<AuditHistoryGap>,
) {
    val records: List<AuditEventMetadata> = Collections.unmodifiableList(ArrayList(records))
    val gaps: List<AuditHistoryGap> = Collections.unmodifiableList(ArrayList(gaps))
}
class AuditEvidenceSnapshot internal constructor(epochs: List<AuditEpochEvidence>, proofs: List<StoredAuditProof>, val storedBytes: Long) {
    val epochs: List<AuditEpochEvidence> = Collections.unmodifiableList(ArrayList(epochs))
    val proofs: List<StoredAuditProof> = Collections.unmodifiableList(ArrayList(proofs))
}

/**
 * Bounded evidence for one trusted Mac/account/key. It keeps conflicting proofs without replacing accepted records.
 * This in-memory store grants no freshness, current-epoch selection, trust migration or action authority.
 */
class AuditEvidenceStore(
    expectedMacID: ByteArray,
    expectedAccountID: ByteArray,
    trustedAuthorityPublicKey: ByteArray,
    private val protocolLimits: AuditPageLimits,
    private val capacity: AuditEvidenceLimits,
) {
    init {
        require(expectedMacID.size == 16 && expectedAccountID.size == 16)
        require(trustedAuthorityPublicKey.size == 65 && trustedAuthorityPublicKey[0] == 4.toByte())
    }
    private val mac = CborValue.Bytes(expectedMacID)
    private val account = CborValue.Bytes(expectedAccountID)
    private val key = trustedAuthorityPublicKey.copyOf()
    private data class ProofID(val kind: AuditEvidenceKind, val digest: CborValue.Bytes)
    private class Record(val metadata: AuditEventMetadata, val canonical: CborValue.Bytes)
    private class Epoch(
        val generation: ULong,
        var descriptor: AuditEpochDescriptor?,
        var descriptorBytes: CborValue.Bytes?,
        var head: ULong,
        var retainedAfter: ULong,
        val records: MutableMap<ULong, Record> = LinkedHashMap(),
        val eventIDs: MutableMap<CborValue.Bytes, ULong> = LinkedHashMap(),
    ) {
        fun copy() = Epoch(generation, descriptor, descriptorBytes, head, retainedAfter, LinkedHashMap(records), LinkedHashMap(eventIDs))
    }
    private var epochs = LinkedHashMap<CborValue.Bytes, Epoch>()
    private val proofs = LinkedHashMap<ProofID, StoredAuditProof>()
    private var storedBytes = 0L

    fun append(receipt: ReceivedAuditPage) = importEvidence(AuditEvidenceKind.PAGE, receipt.canonicalBody, receipt.signature)
    fun append(receipt: ReceivedAuditHistory) = importEvidence(AuditEvidenceKind.HISTORY_STATUS, receipt.canonicalBody, receipt.signature)

    /** Also supports verified offline restoration. Import never advances a last-sync time or grants freshness. */
    @Synchronized
    fun importEvidence(kind: AuditEvidenceKind, canonicalBody: ByteArray, signature: ByteArray): AuditEvidenceAcceptance {
        val bodyLimits = if (kind == AuditEvidenceKind.PAGE) protocolLimits.batch else protocolLimits.history
        if (canonicalBody.size > bodyLimits.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
        if (signature.size != 64) reject(AuditEvidenceRejection.INVALID_SIGNATURE)
        val body = canonicalBody.copyOf(); val signed = signature.copyOf()
        val verified = when (kind) {
            AuditEvidenceKind.PAGE -> AuditBatchSignature.verify(signed, key, 1u, body, bodyLimits, protocolLimits.signing)
            AuditEvidenceKind.HISTORY_STATUS -> AuditHistoryStatusSignature.verify(signed, key, 1u, body, bodyLimits, protocolLimits.signing)
        }
        if (!verified) reject(AuditEvidenceRejection.INVALID_SIGNATURE)
        val proofID = ProofID(kind, digest(body))
        if (proofs.containsKey(proofID)) return AuditEvidenceAcceptance.DUPLICATE
        val candidate = LinkedHashMap(epochs.mapValues { it.value.copy() })
        val conflicts = LinkedHashSet<AuditEvidenceConflict>()
        fun scoped(macID: ByteArray, accountID: ByteArray) {
            if (CborValue.Bytes(macID) != mac || CborValue.Bytes(accountID) != account) reject(AuditEvidenceRejection.WRONG_AUTHORITY)
        }
        fun epoch(id: ByteArray, generation: ULong, head: ULong, retained: ULong, descriptor: AuditEpochDescriptor? = null): Epoch {
            val identity = CborValue.Bytes(id)
            val entry = candidate.getOrPut(identity) { Epoch(generation, null, null, head, retained) }
            if (entry.generation != generation) conflicts.add(AuditEvidenceConflict.GENERATION)
            if (descriptor != null) {
                val encoded = CborValue.Bytes(descriptor.encode(protocolLimits.descriptor))
                if (entry.descriptorBytes != null && entry.descriptorBytes != encoded) conflicts.add(AuditEvidenceConflict.DESCRIPTOR)
                else { entry.descriptor = descriptor; entry.descriptorBytes = encoded }
            }
            entry.head = maxOf(entry.head, head)
            entry.retainedAfter = maxOf(entry.retainedAfter, retained)
            return entry
        }
        when (kind) {
            AuditEvidenceKind.PAGE -> {
                val batch = AuditBatch.decode(body, bodyLimits, protocolLimits.record, protocolLimits.maximumRecords)
                scoped(batch.macID, batch.accountID)
                val entry = epoch(batch.journalEpoch, batch.epochCreationGeneration, batch.head, batch.retainedAfter)
                for (record in batch.records) {
                    val bytes = CborValue.Bytes(record.encode(protocolLimits.record))
                    val old = entry.records[record.sequence]
                    if (old != null && old.canonical != bytes) conflicts.add(AuditEvidenceConflict.RECORD)
                    val eventID = CborValue.Bytes(record.eventID)
                    val oldSequence = entry.eventIDs[eventID]
                    if (oldSequence != null && oldSequence != record.sequence) conflicts.add(AuditEvidenceConflict.EVENT_ID)
                    entry.records.putIfAbsent(record.sequence, Record(record, bytes))
                    entry.eventIDs.putIfAbsent(eventID, record.sequence)
                }
            }
            AuditEvidenceKind.HISTORY_STATUS -> {
                val status = AuditHistoryStatus.decode(body, bodyLimits, protocolLimits.descriptor)
                scoped(status.macID, status.accountID)
                epoch(status.current.epoch, status.current.generation, status.currentHead, status.currentRetainedAfter, status.current)
                status.queried?.let {
                    epoch(it.epoch, it.generation, checkNotNull(status.queriedHead), checkNotNull(status.queriedRetainedAfter), it)
                }
            }
        }
        checkLinks(candidate, conflicts)
        val proofBytes = body.size.toLong() + signed.size
        if (proofs.size >= capacity.maximumProofs || proofBytes > capacity.maximumBytes - storedBytes ||
            (conflicts.isEmpty() && (candidate.size > capacity.maximumEpochs ||
                candidate.values.sumOf { it.records.size.toLong() } > capacity.maximumRecords))) reject(AuditEvidenceRejection.CAPACITY)
        proofs[proofID] = StoredAuditProof(kind, CborValue.Bytes(body), CborValue.Bytes(signed), conflicts)
        storedBytes += proofBytes
        if (conflicts.isNotEmpty()) return AuditEvidenceAcceptance.CONFLICT
        epochs = candidate
        return AuditEvidenceAcceptance.ADDED
    }

    private fun checkLinks(candidate: Map<CborValue.Bytes, Epoch>, conflicts: MutableSet<AuditEvidenceConflict>) {
        for ((identity, entry) in candidate) {
            entry.descriptor?.let { descriptor ->
                val previous = descriptor.previousEpoch?.let(CborValue::Bytes)
                val sequence = descriptor.previousSequence
                if (previous != null && sequence != null && sequence > 0uL) {
                    candidate[previous]?.records?.get(sequence)?.let { record ->
                        if (digest(record.canonical.copyBytes()) != CborValue.Bytes(checkNotNull(descriptor.previousEventDigest))) {
                            conflicts.add(AuditEvidenceConflict.PRIOR_DIGEST)
                        }
                    }
                }
            }
            val visited = HashSet<CborValue.Bytes>()
            var cursor: CborValue.Bytes? = identity
            while (cursor != null && visited.add(cursor)) {
                cursor = candidate[cursor]?.descriptor?.previousEpoch?.let(CborValue::Bytes)
            }
            if (cursor != null) conflicts.add(AuditEvidenceConflict.EPOCH_CYCLE)
        }
    }

    @Synchronized
    fun snapshot(): AuditEvidenceSnapshot = AuditEvidenceSnapshot(epochs.map { (id, entry) ->
        val ordered = entry.records.toSortedMap()
        val gaps = ArrayList<AuditHistoryGap>()
        fun gap(after: ULong, through: ULong) {
            if (after >= through) return
            val boundary = minOf(through, entry.retainedAfter)
            if (after < boundary) gaps.add(AuditHistoryGap(after, boundary, true))
            if (through > maxOf(after, boundary)) gaps.add(AuditHistoryGap(maxOf(after, boundary), through, false))
        }
        var previous = 0uL
        for (sequence in ordered.keys) {
            if (sequence - previous > 1uL) gap(previous, sequence - 1uL)
            previous = sequence
        }
        gap(previous, entry.head)
        AuditEpochEvidence(id, entry.generation, entry.descriptor, entry.head, entry.retainedAfter,
            ordered.values.map { it.metadata }, gaps)
    }, proofs.values.toList(), storedBytes)

    private fun digest(bytes: ByteArray) = CborValue.Bytes(MessageDigest.getInstance("SHA-256").digest(bytes))
    private fun reject(reason: AuditEvidenceRejection): Nothing = throw AuditEvidenceException(reason)
}
