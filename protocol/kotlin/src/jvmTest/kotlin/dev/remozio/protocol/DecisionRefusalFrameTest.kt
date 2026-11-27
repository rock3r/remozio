package dev.remozio.protocol

import org.junit.Test
import kotlin.test.*

class DecisionRefusalFrameTest {
    @Test fun canonicalDecisionRefusalVectors() {
        val valid = CommandCarrierVectors.rows("decisionRefusalFrame", "valid")
        val signing = CommandCarrierVectors.rows("decisionRefusalFrame", "signingInputs")
        assertEquals(2, valid.size)
        assertEquals(2, signing.size)
        fun repeated(byte: Int, count: Int = 16) = ByteArray(count) { byte.toByte() }
        val scope = ChannelScope(repeated(1), repeated(2), repeated(3), repeated(4))
        val sequences = listOf(23uL, ULong.MAX_VALUE)
        for ((index, row) in valid.withIndex()) {
            val reason = DecisionRefusalFrame.Reason.entries[index]
            val payload = DecisionRefusalFrame.Payload(scope, repeated(5, 32), sequences[index], repeated(6),
                repeated(7, 32), repeated(8, 32), reason)
            val bytes = row.bytes()
            assertContentEquals(bytes, DecisionRefusalFrame(payload, repeated(0xcc, 64)).encode(), row.name)
            val decoded = DecisionRefusalFrame.decode(bytes)
            assertEquals(scope, decoded.payload.scope)
            assertEquals(sequences[index], decoded.payload.sequence)
            assertEquals(reason, decoded.payload.reason)
            assertContentEquals(signing[index].bytes(), decoded.payload.signingInput(), row.name)
        }
    }

    @Test fun rejectsInvalidDecisionRefusalVectors() {
        val rows = CommandCarrierVectors.rows("decisionRefusalFrame", "invalid")
        assertEquals(8, rows.size)
        for (row in rows) assertFails(row.name) { DecisionRefusalFrame.decode(row.bytes()) }
    }
}
