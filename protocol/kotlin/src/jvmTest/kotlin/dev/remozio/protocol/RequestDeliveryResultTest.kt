package dev.remozio.protocol

import org.junit.Test
import kotlin.test.*

class RequestDeliveryResultTest {
    @Test fun canonicalDeliveryResultVectors() {
        val rows = CommandCarrierVectors.rows("requestDeliveryResult", "valid")
        assertEquals(2, rows.size)
        for ((row, reason) in rows.zip(RequestDeliveryResult.Reason.entries)) {
            val id = ByteArray(16) { 0xaa.toByte() }
            val digest = ByteArray(32) { 0xbb.toByte() }
            val result = RequestDeliveryResult(id, digest, reason)
            id[0] = 0
            digest[0] = 0
            val bytes = row.bytes()
            assertContentEquals(bytes, result.encode(), row.name)
            val decoded = RequestDeliveryResult.decode(bytes)
            assertEquals(result.requestID, decoded.requestID)
            assertEquals(result.requestDigest, decoded.requestDigest)
            assertEquals(reason, decoded.reason)
        }
    }

    @Test fun rejectsUnknownFieldsReasonsAndInvalidLengths() {
        val rows = CommandCarrierVectors.rows("requestDeliveryResult", "invalid")
        assertEquals(8, rows.size)
        for (row in rows) {
            assertFails(row.name) { RequestDeliveryResult.decode(row.bytes()) }
        }
    }
}
