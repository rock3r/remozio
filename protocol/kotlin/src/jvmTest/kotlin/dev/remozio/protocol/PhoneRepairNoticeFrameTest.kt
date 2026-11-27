package dev.remozio.protocol

import kotlin.test.*

class PhoneRepairNoticeFrameTest {
    @Test fun sharedRepairNoticeVectorsAuthenticateTheExactScopeAndReason() {
        val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 })
        val key = CommandCarrierVectors.rows("phoneRepairNotice", "decisionKey").single().bytes()
        val valid = CommandCarrierVectors.rows("phoneRepairNotice", "valid")
        val inputs = CommandCarrierVectors.rows("phoneRepairNotice", "signingInput")
        assertEquals(PhoneRepairNoticeFrame.Reason.entries.size, valid.size)
        assertEquals(valid.size, inputs.size)
        for ((index, reason) in PhoneRepairNoticeFrame.Reason.entries.withIndex()) {
            val bytes = valid[index].bytes()
            val frame = PhoneRepairNoticeFrame.decode(bytes)
            assertEquals(scope, frame.scope)
            assertEquals(reason, frame.reason)
            assertContentEquals(bytes, frame.encode())
            assertContentEquals(inputs[index].bytes(), PhoneRepairNoticeFrame.signingInput(scope, reason))
            assertTrue(frame.verify(key))
            val changed = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 5 })
            assertFalse(PhoneRepairNoticeFrame(changed, reason, frame.signature.copyBytes()).verify(key))
        }
    }

    @Test fun rejectsInvalidSharedRepairNoticeVectors() {
        val invalid = CommandCarrierVectors.rows("phoneRepairNotice", "invalid")
        assertEquals(5, invalid.size)
        for (row in invalid) assertFailsWith<IllegalArgumentException>(row.name) { PhoneRepairNoticeFrame.decode(row.bytes()) }
    }
}
