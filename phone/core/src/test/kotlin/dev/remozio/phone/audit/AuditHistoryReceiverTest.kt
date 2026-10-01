package dev.remozio.phone.audit

import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.*
import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlin.test.*
import kotlinx.serialization.json.*

class AuditHistoryReceiverTest {
    private val bound = CborLimits(16384, 8, 256)
    private val limits = AuditPageLimits(bound, bound, bound, 4, bound, bound)
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun template(name: String): ByteArray {
        val rows = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.test.auditHistoryVectors"))).readText())
            .jsonObject.getValue("valid").jsonArray
        return hex(rows.single { it.jsonObject.getValue("name").jsonPrimitive.content == name }.jsonObject.getValue("hex").jsonPrimitive.content)
    }
    private inner class Fixture {
        private val keys = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val key: ByteArray get() = (keys.public as ECPublicKey).w.let { point ->
            fun scalar(value: java.math.BigInteger) = value.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
            byteArrayOf(4) + scalar(point.affineX) + scalar(point.affineY)
        }
        var now = ElapsedInstant(1, 100u)
        val receiver = AuditPageReceiver(id(1), id(2), key, limits, 2, 100u) { now }
        fun body(query: AuditHistoryQuery, name: String): ByteArray {
            val fields = (DeterministicCbor.decode(template(name), bound) as CborValue.Fields).values
            return DeterministicCbor.encode(CborValue.Fields(fields + (3uL to CborValue.Bytes(query.queryNonce))), bound)
        }
        fun sign(body: ByteArray, batch: Boolean = false): ByteArray = P256SignatureEncoding.fromDer(
            Signature.getInstance("SHA256withECDSA").run {
                initSign(keys.private)
                update(if (batch) AuditBatchSigningInput.make(1u, body, bound, bound)
                    else AuditHistoryStatusSigningInput.make(1u, body, bound, bound))
                sign()
            })
        fun receive(query: AuditHistoryQuery, name: String): ReceivedAuditHistory {
            val body = body(query, name)
            return receiver.receiveHistory(query, body, sign(body))
        }
    }
    private fun rejected(reason: AuditPageRejection, block: () -> Unit) =
        assertEquals(reason, assertFailsWith<AuditPageException>(block = block).reason)

    @Test fun discoveryAndEachOldCursorStateReturnBoundEvidence() {
        for (name in listOf("discovery", "old-available", "old-unavailable", "old-cursor-ahead", "current-cursor-ahead")) {
            val f = Fixture(); val expected = AuditHistoryStatus.decode(template(name), bound, bound)
            val epoch = expected.requestedEpoch
            val q = f.receiver.beginHistory(epoch, expected.requestedAfter)
            epoch?.fill(0); q.requestedEpoch?.fill(0); q.queryNonce.fill(0)
            val body = f.body(q, name); val signature = f.sign(body)
            val receipt = f.receiver.receiveHistory(q, body, signature)
            assertEquals(expected.disposition, receipt.status.disposition)
            assertContentEquals(expected.current.epoch, receipt.status.current.epoch)
            assertContentEquals(expected.requestedEpoch, receipt.status.requestedEpoch)
            val original = body.copyOf(); val originalSignature = signature.copyOf()
            body.fill(0); signature.fill(0); receipt.canonicalBody.fill(0); receipt.signature.fill(0)
            assertContentEquals(original, receipt.canonicalBody)
            assertContentEquals(originalSignature, receipt.signature)
            rejected(AuditPageRejection.INACTIVE_QUERY) { f.receive(q, name) }
            // The caller can explicitly request the current epoch; no old cursor is silently repurposed.
            val page = f.receiver.begin(receipt.status.current.epoch, receipt.status.current.generation, receipt.status.currentRetainedAfter)
            assertContentEquals(id(3), page.journalEpoch)
        }
    }

    @Test fun oldResponsesWrongBindingsAndBatchSignaturesCannotAnswerDiscovery() {
        val f = Fixture(); val q = f.receiver.beginHistory(null, null); val body = f.body(q, "discovery")
        rejected(AuditPageRejection.INVALID_SIGNATURE) { f.receiver.receiveHistory(q, body, f.sign(body, batch = true)) }
        rejected(AuditPageRejection.INVALID_SIGNATURE) { f.receiver.receiveHistory(q, body, Fixture().sign(body)) }
        val another = f.receiver.beginHistory(null, null)
        rejected(AuditPageRejection.WRONG_QUERY) { f.receiver.receiveHistory(another, body, f.sign(body)) }
        val retained = f.body(q, "old-available")
        rejected(AuditPageRejection.WRONG_QUERY) { f.receiver.receiveHistory(q, retained, f.sign(retained)) }
        f.receive(q, "discovery")
        f.receive(another, "discovery")
        val wrongCursor = f.receiver.beginHistory(id(4), 99u)
        rejected(AuditPageRejection.WRONG_QUERY) { f.receive(wrongCursor, "old-cursor-ahead") }
        wrongCursor.close()
        val wrongEpoch = f.receiver.beginHistory(id(8), 7u)
        rejected(AuditPageRejection.WRONG_QUERY) { f.receive(wrongEpoch, "old-cursor-ahead") }
    }

    @Test fun bothQueryKindsShareCapacityCancellationClosureAndDeadline() {
        val f = Fixture(); val history = f.receiver.beginHistory(null, null)
        f.receiver.begin(id(3), 7u, 0u)
        rejected(AuditPageRejection.CAPACITY) { f.receiver.beginHistory(null, null) }
        history.close()
        rejected(AuditPageRejection.INACTIVE_QUERY) { f.receive(history, "discovery") }
        val expired = f.receiver.beginHistory(null, null); f.now = ElapsedInstant(1, 200u)
        rejected(AuditPageRejection.EXPIRED_QUERY) { f.receive(expired, "discovery") }
        val pending = f.receiver.beginHistory(null, null); f.receiver.close()
        rejected(AuditPageRejection.CLOSED) { f.receive(pending, "discovery") }
        rejected(AuditPageRejection.CLOSED) { f.receiver.beginHistory(null, null) }
    }

    @Test fun malformedInputAndBoundsDoNotConsumeDiscovery() {
        val f = Fixture(); val q = f.receiver.beginHistory(null, null)
        assertFailsWith<CborException> { f.receiver.receiveHistory(q, ByteArray(bound.maxBytes + 1), ByteArray(64)) }
        rejected(AuditPageRejection.INVALID_SIGNATURE) { f.receiver.receiveHistory(q, f.body(q, "discovery"), ByteArray(63)) }
        f.receive(q, "discovery")
        assertFailsWith<IllegalArgumentException> { f.receiver.beginHistory(id(3), null) }
        assertFailsWith<IllegalArgumentException> { f.receiver.beginHistory(null, 1u) }
        assertFailsWith<IllegalArgumentException> { f.receiver.beginHistory(ByteArray(15), 1u) }
    }
}
