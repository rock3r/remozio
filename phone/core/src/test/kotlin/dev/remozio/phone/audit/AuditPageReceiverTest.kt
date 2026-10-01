package dev.remozio.phone.audit

import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.*
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.*

class AuditPageReceiverTest {
    private val bound = CborLimits(8192, 8, 256)
    private val limits = AuditPageLimits(bound, bound, bound, 4)
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private inner class Fixture {
        val keys = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val key: ByteArray get() = (keys.public as ECPublicKey).w.let { point ->
            fun scalar(value: java.math.BigInteger) = value.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
            byteArrayOf(4) + scalar(point.affineX) + scalar(point.affineY)
        }
        var now = ElapsedInstant(1, 100u)
        val receiver = AuditPageReceiver(id(1), id(2), key, limits, 2, 100u) { now }
        fun begin(after: ULong = 0u) = receiver.begin(id(3), 7u, after)
        fun body(query: AuditPageQuery, change: Map<ULong, CborValue> = emptyMap()): ByteArray =
            DeterministicCbor.encode(CborValue.Fields(mapOf(
                0uL to CborValue.Unsigned(1u), 1uL to CborValue.Bytes(id(1)), 2uL to CborValue.Bytes(id(2)),
                3uL to CborValue.Bytes(query.journalEpoch), 4uL to CborValue.Unsigned(query.epochCreationGeneration),
                5uL to CborValue.Unsigned(query.requestedAfter), 6uL to CborValue.Unsigned(0u),
                7uL to CborValue.Unsigned(query.requestedAfter), 8uL to CborValue.Bytes(query.queryNonce),
                9uL to CborValue.ArrayValue(emptyList()),
            ) + change), bound)
        fun sign(body: ByteArray, approval: Boolean = false): ByteArray = P256SignatureEncoding.fromDer(
            Signature.getInstance("SHA256withECDSA").run {
                initSign(keys.private)
                update(if (approval) SigningInput.make(1u, ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST,
                    body, bound, bound) else AuditBatchSigningInput.make(1u, body, bound, bound))
                sign()
            })
        fun receive(query: AuditPageQuery): ReceivedAuditPage { val body = body(query); return receiver.receive(query, body, sign(body)) }
    }
    private fun rejected(reason: AuditPageRejection, block: () -> Unit) =
        assertEquals(reason, assertFailsWith<AuditPageException>(block = block).reason)

    @Test fun acceptsOnceAndOwnsEvidenceAndQueryBytes() {
        val f = Fixture(); val epoch = id(3)
        val q = f.receiver.begin(epoch, 7u, 0u)
        epoch.fill(0); q.journalEpoch.fill(0); q.queryNonce.fill(0)
        val body = f.body(q); val original = body.copyOf(); val signature = f.sign(body); val originalSignature = signature.copyOf()
        f.now = ElapsedInstant(1, 150u)
        val receipt = f.receiver.receive(q, body, signature)
        assertEquals(f.now, receipt.receivedAt)
        assertContentEquals(id(3), receipt.batch.journalEpoch)
        body.fill(0); signature.fill(0); receipt.canonicalBody.fill(0); receipt.signature.fill(0)
        assertContentEquals(original, receipt.canonicalBody)
        assertContentEquals(originalSignature, receipt.signature)
        rejected(AuditPageRejection.INACTIVE_QUERY) { f.receive(q) }
        val next = f.begin()
        assertFalse(next.queryNonce.contentEquals(q.queryNonce))
        rejected(AuditPageRejection.WRONG_QUERY) { f.receiver.receive(next, original, originalSignature) }
        f.receive(next)
    }

    @Test fun everyQueryBindingAndSignatureDomainAreCheckedWithoutConsumingValidRetry() {
        val f = Fixture(); val q = f.begin(); val body = f.body(q)
        rejected(AuditPageRejection.INVALID_SIGNATURE) { f.receiver.receive(q, body, Fixture().sign(body)) }
        rejected(AuditPageRejection.INVALID_SIGNATURE) { f.receiver.receive(q, body, f.sign(body, approval = true)) }
        rejected(AuditPageRejection.INVALID_SIGNATURE) { f.receiver.receive(q, body, ByteArray(63)) }
        for ((field, value) in listOf(
            1uL to CborValue.Bytes(id(9)), 2uL to CborValue.Bytes(id(9)), 3uL to CborValue.Bytes(id(9)),
            4uL to CborValue.Unsigned(8u), 8uL to CborValue.Bytes(ByteArray(32)),
        )) {
            val changed = f.body(q, mapOf(field to value))
            rejected(AuditPageRejection.WRONG_QUERY) { f.receiver.receive(q, changed, f.sign(changed)) }
        }
        val wrongCursor = f.body(q, mapOf(5uL to CborValue.Unsigned(1u), 7uL to CborValue.Unsigned(1u)))
        rejected(AuditPageRejection.WRONG_QUERY) { f.receiver.receive(q, wrongCursor, f.sign(wrongCursor)) }
        f.receive(q)
    }

    @Test fun deadlineClockRestartRegressionAndValidationDelayInvalidateQueries() {
        for (now in listOf(ElapsedInstant(1, 200u), ElapsedInstant(2, 150u), ElapsedInstant(1, 99u))) {
            val f = Fixture(); val q = f.begin(); f.now = now
            rejected(AuditPageRejection.EXPIRED_QUERY) { f.receive(q) }
            f.now = ElapsedInstant(1, 150u)
            rejected(AuditPageRejection.INACTIVE_QUERY) { f.receive(q) }
        }
        val f = Fixture(); val q = f.begin(); f.now = ElapsedInstant(1, 180u)
        rejected(AuditPageRejection.INVALID_SIGNATURE) { f.receiver.receive(q, f.body(q), ByteArray(64)) }
        f.now = ElapsedInstant(1, 170u)
        rejected(AuditPageRejection.EXPIRED_QUERY) { f.receive(q) }
        var ticks = 0
        val receiver = AuditPageReceiver(id(1), id(2), f.key, limits, 1, 100u) {
            ElapsedInstant(1, if (++ticks <= 2) 100u else 200u)
        }
        val delayed = receiver.begin(id(3), 7u, 0u); val bytes = f.body(delayed)
        rejected(AuditPageRejection.EXPIRED_QUERY) { receiver.receive(delayed, bytes, f.sign(bytes)) }
    }

    @Test fun cancellationRevocationAndCapacityStayScoped() {
        val f = Fixture(); val q = f.begin(); val other = f.begin()
        rejected(AuditPageRejection.CAPACITY) { f.begin() }
        q.close(); q.close()
        rejected(AuditPageRejection.INACTIVE_QUERY) { f.receive(q) }
        val replacement = f.begin()
        f.receive(other)
        val second = Fixture(); val unrelated = second.begin()
        rejected(AuditPageRejection.INACTIVE_QUERY) { second.receiver.receive(replacement, f.body(replacement), f.sign(f.body(replacement))) }
        f.receiver.close()
        rejected(AuditPageRejection.CLOSED) { f.receive(replacement) }
        rejected(AuditPageRejection.CLOSED) { f.begin() }
        second.receive(unrelated)
        val expired = Fixture(); val a = expired.begin(); expired.begin(); expired.now = ElapsedInstant(1, 200u)
        expired.begin()
        rejected(AuditPageRejection.INACTIVE_QUERY) { expired.receive(a) }
    }

    @Test fun concurrentReceiptsHaveExactlyOneWinner() {
        val f = Fixture(); val q = f.begin(); val body = f.body(q); val signature = f.sign(body)
        val start = CountDownLatch(1); val pool = Executors.newFixedThreadPool(2)
        try {
            val results = (1..2).map { pool.submit<Boolean> {
                check(start.await(5, TimeUnit.SECONDS))
                try { f.receiver.receive(q, body, signature); true }
                catch (error: AuditPageException) { assertEquals(AuditPageRejection.INACTIVE_QUERY, error.reason); false }
            } }
            start.countDown()
            assertEquals(1, results.count { it.get(5, TimeUnit.SECONDS) })
        } finally { pool.shutdownNow() }
    }

    @Test fun boundsAndMalformedPayloadCannotConsumeLiveQuery() {
        val f = Fixture(); val q = f.begin()
        assertFailsWith<CborException> { f.receiver.receive(q, ByteArray(bound.maxBytes + 1), ByteArray(64)) }
        val malformed = f.body(q, mapOf(10uL to CborValue.Unsigned(0u)))
        assertFailsWith<AuditBatchException> { f.receiver.receive(q, malformed, f.sign(malformed)) }
        f.receive(q)
        assertFailsWith<IllegalArgumentException> { AuditPageLimits(bound, bound, bound, 0) }
        assertFailsWith<IllegalArgumentException> { AuditPageReceiver(id(1), id(2), f.key, limits, 0, 1u) { f.now } }
        assertFailsWith<IllegalArgumentException> { AuditPageReceiver(id(1), id(2), f.key, limits, 1, 0u) { f.now } }
        assertFailsWith<IllegalArgumentException> { f.receiver.begin(ByteArray(15), 7u, 0u) }
    }
}
