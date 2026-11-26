package dev.remozio.protocol

import org.junit.Test
import kotlin.test.*

class RequestStatusQueryTest {
    @Test fun sharedCanonicalQueryAndDefensiveCopy() {
        val id = ByteArray(16) { 0xaa.toByte() }
        val query = RequestStatusQuery(id)
        id[0] = 0
        val row = CommandCarrierVectors.rows("requestStatusQuery", "valid").single()
        val bytes = row.bytes()
        assertContentEquals(bytes, query.encode(), row.name)
        assertEquals(query.requestID, RequestStatusQuery.decode(bytes).requestID)
        assertTrue(bytes.size <= RequestStatusQuery.MAXIMUM_BYTES)
        assertEquals("RequestStatusQuery(redacted)", query.toString())
    }
    @Test fun versionShapeAndBoundsAreStrict() {
        val rows = CommandCarrierVectors.rows("requestStatusQuery", "invalid")
        assertEquals(11, rows.size)
        for (row in rows) {
            val bytes = row.bytes()
            assertFails(row.name) { RequestStatusQuery.decode(bytes) }
        }
        assertFails { RequestStatusQuery(ByteArray(15)) }
    }
}
