package dev.remozio.phone.audit

import dev.remozio.protocol.*
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlin.test.*

class AuditEvidenceStoreTest {
    private val bound = CborLimits(16384, 8, 256)
    private val protocol = AuditPageLimits(bound, bound, bound, 8, bound, bound)
    private val capacity = AuditEvidenceLimits(30, 100000, 20, 10)
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private inner class Fixture {
        private val keys = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val key: ByteArray get() = (keys.public as ECPublicKey).w.let { point ->
            fun scalar(value: java.math.BigInteger) = value.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
            byteArrayOf(4) + scalar(point.affineX) + scalar(point.affineY)
        }
        val store = store()
        fun store(cap: AuditEvidenceLimits = capacity, mac: ByteArray = id(1)) = AuditEvidenceStore(mac, id(2), key, protocol, cap)
        fun sign(body: ByteArray, kind: AuditEvidenceKind): ByteArray = P256SignatureEncoding.fromDer(
            Signature.getInstance("SHA256withECDSA").run {
                initSign(keys.private)
                update(if (kind == AuditEvidenceKind.PAGE) AuditBatchSigningInput.make(1u, body, bound, bound)
                    else AuditHistoryStatusSigningInput.make(1u, body, bound, bound))
                sign()
            })
        fun add(body: ByteArray, kind: AuditEvidenceKind = AuditEvidenceKind.PAGE, target: AuditEvidenceStore = store) =
            target.importEvidence(kind, body, sign(body, kind))
    }
    private fun event(seq: ULong, epoch: Int = 3, eventID: ByteArray = ByteBuffer.allocate(16).putLong(0).putLong(seq.toLong()).array(),
                      reason: AuditReason = AuditReason.NONE) = AuditEventMetadata(eventID, id(1), id(2), id(epoch), seq,
        null, null, null, AuditEventKind.REQUEST_CREATED, AuditCategory.COMMAND, null, null,
        AuditAuthentication.SYSTEM, AuditOutcome.PENDING, reason, null, null)
    private fun page(after: ULong, head: ULong, records: List<AuditEventMetadata>, retained: ULong = 0u, epoch: Int = 3, generation: ULong = 7u): ByteArray =
        DeterministicCbor.encode(CborValue.Fields(mapOf(
            0uL to CborValue.Unsigned(1u), 1uL to CborValue.Bytes(id(1)), 2uL to CborValue.Bytes(id(2)),
            3uL to CborValue.Bytes(id(epoch)), 4uL to CborValue.Unsigned(generation), 5uL to CborValue.Unsigned(after),
            6uL to CborValue.Unsigned(retained), 7uL to CborValue.Unsigned(head), 8uL to CborValue.Bytes(ByteArray(32)),
            9uL to CborValue.ArrayValue(records.map { CborValue.Bytes(it.encode(bound)) }),
        )), bound)
    private fun header(epoch: Int = 3, cause: AuditEpochCause = AuditEpochCause.RESTART, previous: Int? = null,
                       sequence: ULong? = null, digest: ByteArray? = null) = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to CborValue.Bytes(id(1)), 2uL to CborValue.Bytes(id(2)),
        3uL to CborValue.Bytes(id(epoch)), 4uL to CborValue.Unsigned(7u), 5uL to CborValue.Unsigned(cause.tag),
        6uL to (previous?.let { CborValue.Bytes(id(it)) } ?: CborValue.Null),
        7uL to (sequence?.let(CborValue::Unsigned) ?: CborValue.Null), 8uL to (digest?.let(CborValue::Bytes) ?: CborValue.Null),
    )), bound)
    private fun history(descriptor: ByteArray) = DeterministicCbor.encode(CborValue.Fields(mapOf(
        0uL to CborValue.Unsigned(1u), 1uL to CborValue.Bytes(id(1)), 2uL to CborValue.Bytes(id(2)),
        3uL to CborValue.Bytes(ByteArray(32)), 4uL to CborValue.Null, 5uL to CborValue.Null,
        6uL to CborValue.Unsigned(0u), 7uL to CborValue.Bytes(descriptor), 8uL to CborValue.Unsigned(0u),
        9uL to CborValue.Unsigned(0u), 10uL to CborValue.Null, 11uL to CborValue.Null, 12uL to CborValue.Null,
    )), bound)
    private fun rejected(reason: AuditEvidenceRejection, block: () -> Unit) =
        assertEquals(reason, assertFailsWith<AuditEvidenceException>(block = block).reason)

    @Test fun mergesOutOfOrderPagesWithoutRegressingHeadsOrHidingGaps() {
        val f = Fixture(); val late = page(2u, 4u, listOf(event(3u), event(4u)))
        assertEquals(AuditEvidenceAcceptance.ADDED, f.add(late))
        assertEquals(listOf(AuditHistoryGap(0u, 2u, false)), f.store.snapshot().epochs.single().gaps)
        val older = page(0u, 2u, listOf(event(1u), event(2u)))
        assertEquals(AuditEvidenceAcceptance.ADDED, f.add(older))
        val snapshot = f.store.snapshot().epochs.single()
        assertEquals(4uL, snapshot.highestObservedHead)
        assertEquals(listOf(1uL, 2uL, 3uL, 4uL), snapshot.records.map { it.sequence })
        assertTrue(snapshot.gaps.isEmpty())
        assertEquals(AuditEvidenceAcceptance.DUPLICATE, f.add(older))
        assertEquals(2, f.store.snapshot().proofs.size)
        assertTrue(f.store.snapshot().proofs.all { it.conflicts.isEmpty() })
        val retention = page(4u, 4u, emptyList(), retained = 4u)
        f.add(retention)
        assertEquals(4, f.store.snapshot().epochs.single().records.size)
        assertTrue(f.store.snapshot().epochs.single().gaps.isEmpty())
    }

    @Test fun conflictingRecordsIDsGenerationsAndDescriptorsKeepOldDataAndNewProofs() {
        val f = Fixture(); val original = event(1u)
        f.add(page(0u, 1u, listOf(original)))
        val attempts = listOf(
            page(0u, 1u, listOf(event(1u, reason = AuditReason.UNKNOWN))) to AuditEvidenceConflict.RECORD,
            page(1u, 2u, listOf(event(2u, eventID = original.eventID))) to AuditEvidenceConflict.EVENT_ID,
            page(1u, 1u, emptyList(), generation = 8u) to AuditEvidenceConflict.GENERATION,
        )
        for ((body, conflict) in attempts) {
            assertEquals(AuditEvidenceAcceptance.CONFLICT, f.add(body))
            assertTrue(conflict in f.store.snapshot().proofs.last().conflicts)
            val epoch = f.store.snapshot().epochs.single()
            assertEquals(1uL, epoch.highestObservedHead)
            assertEquals(1, epoch.records.size)
            assertEquals(AuditReason.NONE, epoch.records.single().reason)
        }
        f.add(history(header()), AuditEvidenceKind.HISTORY_STATUS)
        assertEquals(AuditEvidenceAcceptance.CONFLICT, f.add(history(header(cause = AuditEpochCause.RESTORATION)), AuditEvidenceKind.HISTORY_STATUS))
        assertEquals(AuditEpochCause.RESTART, f.store.snapshot().epochs.single().descriptor?.cause)
        assertTrue(AuditEvidenceConflict.DESCRIPTOR in f.store.snapshot().proofs.last().conflicts)
    }

    @Test fun verifiesPriorDigestsInEitherArrivalOrderAndRejectsCycles() {
        val record = event(1u)
        val right = MessageDigest.getInstance("SHA-256").digest(record.encode(bound))
        for (recordFirst in listOf(true, false)) {
            val f = Fixture(); val p = page(0u, 1u, listOf(record))
            val h = history(header(epoch = 4, previous = 3, sequence = 1u, digest = ByteArray(32)))
            if (recordFirst) { f.add(p); assertEquals(AuditEvidenceAcceptance.CONFLICT, f.add(h, AuditEvidenceKind.HISTORY_STATUS)) }
            else { f.add(h, AuditEvidenceKind.HISTORY_STATUS); assertEquals(AuditEvidenceAcceptance.CONFLICT, f.add(p)) }
            assertTrue(AuditEvidenceConflict.PRIOR_DIGEST in f.store.snapshot().proofs.last().conflicts)
        }
        val valid = Fixture(); valid.add(page(0u, 1u, listOf(record)))
        assertEquals(AuditEvidenceAcceptance.ADDED, valid.add(history(header(epoch = 4, previous = 3, sequence = 1u, digest = right)), AuditEvidenceKind.HISTORY_STATUS))
        val cycle = Fixture()
        cycle.add(history(header(previous = 4, sequence = 0u)), AuditEvidenceKind.HISTORY_STATUS)
        assertEquals(AuditEvidenceAcceptance.CONFLICT, cycle.add(history(header(epoch = 4, previous = 3, sequence = 0u)), AuditEvidenceKind.HISTORY_STATUS))
        assertTrue(AuditEvidenceConflict.EPOCH_CYCLE in cycle.store.snapshot().proofs.last().conflicts)
        assertEquals(1, cycle.store.snapshot().epochs.size)
    }

    @Test fun capacityFailuresAreAtomicAndNeverEvict() {
        val f = Fixture(); val first = page(0u, 1u, listOf(event(1u))); val second = page(1u, 2u, listOf(event(2u)))
        for (cap in listOf(AuditEvidenceLimits(1, 10000, 20, 10), AuditEvidenceLimits(20, first.size.toLong() + 64, 20, 10),
            AuditEvidenceLimits(20, 10000, 1, 10))) {
            val store = f.store(cap); f.add(first, target = store); val before = store.snapshot()
            rejected(AuditEvidenceRejection.CAPACITY) { f.add(second, target = store) }
            assertEquals(before.storedBytes, store.snapshot().storedBytes)
            assertEquals(1, store.snapshot().proofs.size)
            assertEquals(1, store.snapshot().epochs.single().records.size)
            assertEquals(AuditEvidenceAcceptance.DUPLICATE, f.add(first, target = store))
        }
        val store = f.store(AuditEvidenceLimits(20, 10000, 20, 1)); f.add(first, target = store)
        rejected(AuditEvidenceRejection.CAPACITY) { f.add(page(0u, 1u, listOf(event(1u, epoch = 4)), epoch = 4), target = store) }
        assertEquals(1, store.snapshot().epochs.size)
    }

    @Test fun revalidatesRestoredEvidenceAndOwnsInputsAndSnapshots() {
        val f = Fixture(); val body = page(0u, 1u, listOf(event(1u))); val sig = f.sign(body, AuditEvidenceKind.PAGE)
        f.store.importEvidence(AuditEvidenceKind.PAGE, body, sig)
        body.fill(0); sig.fill(0)
        val proof = f.store.snapshot().proofs.single()
        proof.canonicalBody.copyBytes().fill(0); proof.signature.copyBytes().fill(0)
        val restored = f.store()
        assertEquals(AuditEvidenceAcceptance.ADDED, restored.importEvidence(proof.kind, proof.canonicalBody.copyBytes(), proof.signature.copyBytes()))
        assertEquals(1, restored.snapshot().epochs.single().records.size)
        rejected(AuditEvidenceRejection.INVALID_SIGNATURE) { restored.importEvidence(proof.kind, proof.canonicalBody.copyBytes(), ByteArray(64)) }
        rejected(AuditEvidenceRejection.WRONG_AUTHORITY) { f.store(mac = id(9)).importEvidence(proof.kind, proof.canonicalBody.copyBytes(), proof.signature.copyBytes()) }
        rejected(AuditEvidenceRejection.INVALID_SIGNATURE) { Fixture().store.importEvidence(proof.kind, proof.canonicalBody.copyBytes(), proof.signature.copyBytes()) }
        assertFailsWith<UnsupportedOperationException> { (restored.snapshot().proofs as MutableList<*>).clear() }
        assertFailsWith<UnsupportedOperationException> { (restored.snapshot().epochs.single().records as MutableList<*>).clear() }
    }

    @Test fun maximumSequenceAndRetentionGapsDoNotOverflow() {
        val f = Fixture()
        f.add(page(ULong.MAX_VALUE - 1u, ULong.MAX_VALUE, listOf(event(ULong.MAX_VALUE)), retained = 5u))
        assertEquals(listOf(AuditHistoryGap(0u, 5u, true), AuditHistoryGap(5u, ULong.MAX_VALUE - 1u, false)),
            f.store.snapshot().epochs.single().gaps)
        val pruned = Fixture(); pruned.add(page(0u, ULong.MAX_VALUE, emptyList(), retained = ULong.MAX_VALUE))
        assertEquals(listOf(AuditHistoryGap(0u, ULong.MAX_VALUE, true)), pruned.store.snapshot().epochs.single().gaps)
    }
}
