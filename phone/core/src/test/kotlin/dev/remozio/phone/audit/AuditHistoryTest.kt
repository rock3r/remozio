package dev.remozio.phone.audit

import dev.remozio.protocol.*
import kotlin.test.*

class AuditHistoryTest {
    private val limits = CborLimits(16384, 8, 256)
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun bytes(n: Int) = CborValue.Bytes(id(n))
    private fun scope(mac: Int = 1, account: Int = 2) = AuditHistoryScope(bytes(mac), bytes(account))
    private fun event(seq: ULong, epoch: Int = 3, scope: AuditHistoryScope = scope(), request: Int? = 8,
                      time: ULong? = null, category: AuditCategory = AuditCategory.COMMAND,
                      outcome: AuditOutcome = AuditOutcome.PENDING) = AuditEventMetadata(
        id(seq.toInt()), scope.macID.copyBytes(), scope.accountID.copyBytes(), id(epoch), seq,
        request?.let(::id), time, null, AuditEventKind.REQUEST_CREATED, category, null, null,
        AuditAuthentication.UNKNOWN, outcome, AuditReason.UNKNOWN, null, null)
    private fun descriptor(epoch: Int, previous: Int? = null) = AuditEpochDescriptor.decode(
        DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Unsigned(1u), 1uL to bytes(1), 2uL to bytes(2), 3uL to bytes(epoch),
            4uL to CborValue.Unsigned(7u), 5uL to CborValue.Unsigned(AuditEpochCause.RESTART.tag),
            6uL to (previous?.let(::bytes) ?: CborValue.Null),
            7uL to (previous?.let { CborValue.Unsigned(0u) } ?: CborValue.Null), 8uL to CborValue.Null,
        )), limits), limits)
    private fun epoch(id: Int, records: List<AuditEventMetadata> = emptyList(), previous: Int? = null,
                      gaps: List<AuditHistoryGap> = emptyList(), header: Boolean = true) =
        AuditEpochEvidence(bytes(id), 7u, if (header) descriptor(id, previous) else null,
            records.maxOfOrNull { it.sequence } ?: 0u, 0u, records, gaps)
    private fun snapshot(epochs: List<AuditEpochEvidence>, scope: AuditHistoryScope = scope(),
                         proofs: List<StoredAuditProof> = emptyList()) = AuditEvidenceSnapshot(scope, epochs, proofs, 0)
    private fun records(group: AuditHistoryGroup) = group.chains.flatMap { it.epochs }.flatMap { it.records }

    @Test fun keepsMacsAndAccountsSeparateEvenWhenRequestIDsAndClocksMatch() {
        val otherMac = scope(9); val otherAccount = scope(1, 6)
        val first = snapshot(listOf(epoch(3, listOf(event(1u, time = 999u)))))
        val second = snapshot(listOf(epoch(3, listOf(event(1u, scope = otherMac, time = 999u)))), otherMac)
        val third = snapshot(listOf(epoch(3, listOf(event(1u, scope = otherAccount, time = 999u)))), otherAccount)
        val groups = AuditHistory.list(listOf(second, third, first))
        assertEquals(listOf(scope(), otherAccount, otherMac), groups.map { it.scope })
        assertEquals(1, records(AuditHistory.timeline(first, id(8))).size)
        assertEquals(listOf(scope(), otherAccount), AuditHistory.list(listOf(second, third, first),
            AuditHistoryFilter(macIDs = setOf(bytes(1)))).map { it.scope })
        assertFailsWith<IllegalArgumentException> { AuditHistory.list(listOf(first, first)) }
    }

    @Test fun ordersSequencesInsteadOfTimestampsAndKeepsUnknownOutcomes() {
        val source = snapshot(listOf(epoch(3, listOf(event(ULong.MAX_VALUE, time = 1u, outcome = AuditOutcome.UNRESOLVED),
            event(1u, time = ULong.MAX_VALUE), event(2u, time = null, outcome = AuditOutcome.UNKNOWN)))))
        val feed = records(AuditHistory.list(listOf(source)).single())
        assertEquals(listOf(ULong.MAX_VALUE, 2uL, 1uL), feed.map { it.sequence })
        assertEquals(listOf(AuditOutcome.UNRESOLVED, AuditOutcome.UNKNOWN, AuditOutcome.PENDING), feed.map { it.outcome })
        assertNull(feed[1].eventTimeMs)
        assertEquals(listOf(1uL, 2uL, ULong.MAX_VALUE), records(AuditHistory.timeline(source, id(8))).map { it.sequence })
    }

    @Test fun ordersOnlyUnambiguousChainsAndPreservesMissingEpochBoundaries() {
        val old = epoch(3, listOf(event(1u)))
        val newer = epoch(4, listOf(event(1u, epoch = 4)), previous = 3)
        val newest = epoch(5, listOf(event(1u, epoch = 5)), previous = 4)
        val missing = epoch(6, previous = 90)
        val unknown = epoch(7, header = false)
        for (input in listOf(listOf(old, newer, newest, missing, unknown), listOf(unknown, newest, old, missing, newer))) {
            val source = snapshot(input)
            val group = AuditHistory.list(listOf(source)).single()
            assertEquals(listOf(listOf(bytes(5), bytes(4), bytes(3)), listOf(bytes(6)), listOf(bytes(7))),
                group.chains.map { chain -> chain.epochs.map { it.epoch } })
            assertContentEquals(id(90), group.chains[1].epochs.single().descriptor?.previousEpoch)
            assertNull(group.chains[2].epochs.single().descriptor)
            assertEquals(listOf(bytes(3), bytes(4), bytes(5)), AuditHistory.timeline(source, id(8)).chains.first().epochs.map { it.epoch })
        }
        val forked = snapshot(listOf(old, newer, epoch(8, previous = 3)))
        assertEquals(listOf(listOf(bytes(3)), listOf(bytes(4)), listOf(bytes(8))),
            AuditHistory.list(listOf(forked)).single().chains.map { chain -> chain.epochs.map { it.epoch } })
    }

    @Test fun filtersRecordsWithoutHidingGapsConflictsOrRequestEvents() {
        val gap = AuditHistoryGap(2u, 4u, true)
        val conflict = StoredAuditProof(AuditEvidenceKind.PAGE, CborValue.Bytes(byteArrayOf()),
            CborValue.Bytes(ByteArray(64)), setOf(AuditEvidenceConflict.RECORD))
        val source = snapshot(listOf(epoch(3, listOf(event(1u), event(2u, outcome = AuditOutcome.UNRESOLVED),
            event(5u, request = 9, category = AuditCategory.LITTLE_SNITCH)), gaps = listOf(gap))), proofs = listOf(conflict))
        val filtered = AuditHistory.list(listOf(source), AuditHistoryFilter(categories = setOf(AuditCategory.COMMAND),
            outcomes = setOf(AuditOutcome.UNRESOLVED))).single()
        assertEquals(listOf(2uL), records(filtered).map { it.sequence })
        assertEquals(3, filtered.chains.single().epochs.single().retainedRecordCount)
        assertEquals(listOf(gap), filtered.chains.single().epochs.single().gaps)
        assertEquals(setOf(AuditEvidenceConflict.RECORD), filtered.conflicts)
        assertEquals(1, filtered.conflictingProofCount)
        assertEquals(listOf(1uL, 2uL), records(AuditHistory.timeline(source, id(8))).map { it.sequence })
        val empty = AuditHistory.list(listOf(source), AuditHistoryFilter(categories = emptySet())).single()
        assertTrue(records(empty).isEmpty())
        assertEquals(listOf(gap), empty.chains.single().epochs.single().gaps)
        assertEquals(filtered.conflicts, empty.conflicts)
    }

    @Test fun retainsReconciliationReportsEvenWhenEveryRecordIsFiltered() {
        val status = AuditHistoryStatus.decode(DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Unsigned(1u), 1uL to bytes(1), 2uL to bytes(2), 3uL to CborValue.Bytes(ByteArray(32)),
            4uL to bytes(9), 5uL to CborValue.Unsigned(10u), 6uL to CborValue.Unsigned(AuditHistoryDisposition.UNAVAILABLE.tag),
            7uL to CborValue.Bytes(descriptor(3).encode(limits)), 8uL to CborValue.Unsigned(0u), 9uL to CborValue.Unsigned(0u),
            10uL to CborValue.Null, 11uL to CborValue.Null, 12uL to CborValue.Null,
        )), limits), limits, limits)
        val proof = StoredAuditProof(AuditEvidenceKind.HISTORY_STATUS, CborValue.Bytes(status.encode(limits)),
            CborValue.Bytes(ByteArray(64)), setOf(AuditEvidenceConflict.DESCRIPTOR), status)
        val source = snapshot(listOf(epoch(3)), proofs = listOf(proof))
        val report = AuditHistory.list(listOf(source), AuditHistoryFilter(outcomes = emptySet())).single().reports.single()
        assertEquals(AuditHistoryDisposition.UNAVAILABLE, report.status.disposition)
        assertContentEquals(id(9), report.status.requestedEpoch)
        assertEquals(setOf(AuditEvidenceConflict.DESCRIPTOR), report.conflicts)
    }

    @Test fun ownsFilterSetsAndReturnsImmutableViews() {
        val categories = mutableSetOf(AuditCategory.COMMAND)
        val filter = AuditHistoryFilter(categories = categories); categories.clear()
        val source = snapshot(listOf(epoch(3, listOf(event(1u)))))
        val groups = AuditHistory.list(listOf(source), filter)
        assertEquals(1, records(groups.single()).size)
        assertFailsWith<UnsupportedOperationException> { (groups as MutableList<*>).clear() }
        assertFailsWith<UnsupportedOperationException> { (groups.single().chains as MutableList<*>).clear() }
        assertFailsWith<UnsupportedOperationException> { (groups.single().chains.single().epochs.single().records as MutableList<*>).clear() }
        assertFailsWith<UnsupportedOperationException> { (filter.categories as MutableSet<*>).clear() }
        groups.single().scope.macID.copyBytes().fill(0)
        assertEquals(scope(), groups.single().scope)
    }
}
