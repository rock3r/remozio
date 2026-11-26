package dev.remozio.protocol

import kotlin.test.*

class ApprovalMessageTest {
    @Test fun exactOpaqueBytesAndSignatureUseTheSharedWireEncoding() {
        val body = byteArrayOf(1, 2, 3)
        val signature = ByteArray(64) { 0xaa.toByte() }
        val message = ApprovalMessage(1u, ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST, body, signature)
        body.fill(0); signature.fill(0)
        val row = CommandCarrierVectors.rows("approvalMessage", "valid").single()
        val encoded = row.bytes()
        assertContentEquals(encoded, message.encode(3), row.name)
        val decoded = ApprovalMessage.decode(encoded, 3)
        assertEquals(message.wireVersion, decoded.wireVersion)
        assertEquals(message.type, decoded.type)
        assertEquals(message.purpose, decoded.purpose)
        assertEquals(message.body, decoded.body)
        assertEquals(message.signature, decoded.signature)
        assertEquals("ApprovalMessage(redacted)", decoded.toString())
    }
    @Test fun onlyDefinedSigningDomainsAndWireVersionsAreCarried() {
        for (type in ApprovalMessageType.entries) for (purpose in SigningPurpose.entries) {
            val valid = when (type) {
                ApprovalMessageType.REQUEST -> purpose == SigningPurpose.ISSUED_REQUEST
                ApprovalMessageType.STATUS -> purpose == SigningPurpose.STATUS
                ApprovalMessageType.DECISION -> purpose in setOf(SigningPurpose.CANCELLATION, SigningPurpose.ONE_TIME_UI, SigningPurpose.BIOMETRIC_AUTHORIZATION)
            }
            val result = runCatching { ApprovalMessage(1u, type, purpose, byteArrayOf(1), ByteArray(64)).encode(1) }
            assertEquals(valid, result.isSuccess)
        }
        assertFails { ApprovalMessage(2u, ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST, byteArrayOf(1), ByteArray(64)) }
    }
    @Test fun malformedUnsupportedAndOversizedCarriersFail() {
        val message = ApprovalMessage(1u, ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST, byteArrayOf(1), ByteArray(64))
        val encoded = message.encode(1)
        val rows = CommandCarrierVectors.rows("approvalMessage", "invalid")
        assertEquals(10, rows.size)
        for (row in rows) {
            val bytes = row.bytes()
            assertFails(row.name) { ApprovalMessage.decode(bytes, 1) }
        }
        assertFails { ApprovalMessage.decode(encoded, Int.MAX_VALUE) }
        assertFails { message.encode(0) }
    }
}
