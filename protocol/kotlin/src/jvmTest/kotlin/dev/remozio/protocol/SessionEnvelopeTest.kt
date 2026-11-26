package dev.remozio.protocol

import org.junit.Test
import kotlin.test.*

class SessionEnvelopeTest {
    @Test fun sharedCanonicalBytesAndUnsignedSequenceRoundTrip() {
        val value = SessionEnvelope(ByteArray(32) { 0xaa.toByte() }, ULong.MAX_VALUE, byteArrayOf(1, 2, 3))
        val row = CommandCarrierVectors.rows("sessionEnvelope", "valid").single()
        val encoded = row.bytes()
        assertContentEquals(encoded, value.encode(3), row.name)
        val decoded = SessionEnvelope.decode(encoded, 3)
        assertEquals(ULong.MAX_VALUE, decoded.sequence); assertEquals(value.sessionID, decoded.sessionID)
        assertEquals(value.payload, decoded.payload)
    }
    @Test fun incompatibleAndOversizedEnvelopesFail() {
        val original = SessionEnvelope(ByteArray(32), 0u, byteArrayOf(1)).encode(1)
        val rows = CommandCarrierVectors.rows("sessionEnvelope", "invalid")
        assertEquals(6, rows.size)
        for (row in rows) {
            val bytes = row.bytes()
            assertFails(row.name) { SessionEnvelope.decode(bytes, 1) }
        }
        assertFails { SessionEnvelope(ByteArray(32), 0u, byteArrayOf(1, 2)).encode(1) }
        assertFails { SessionEnvelope.decode(original, Int.MAX_VALUE) }
    }
}
