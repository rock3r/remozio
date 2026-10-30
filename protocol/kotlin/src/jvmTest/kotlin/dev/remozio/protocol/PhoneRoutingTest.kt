package dev.remozio.protocol

import java.io.File
import kotlin.test.*
import kotlinx.serialization.json.*

class PhoneRoutingTest {
    private val limits = CborLimits(3200, 2, 16)
    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.phoneRoutingVectors"))).readText()).jsonObject
    private fun hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    private fun verify(signature: ByteArray, key: ByteArray, body: ByteArray) = RoutingStatusSignature.verify(signature, key, 1u, body, limits)

    @Test fun sharedResponseBytesAndHistoricalReceiptRemainDistinctFromCurrentState() {
        val rows = vectors().getValue("responsesValid").jsonArray; assertEquals(17, rows.size)
        for (row in rows) {
            val f = row.jsonObject; val bytes = hex(f.text("hex")); val value = RoutingStatusResponse.decode(bytes)
            assertContentEquals(bytes, value.encode(), f.text("name")); assertContentEquals(ByteArray(32) { 20 }, value.queryNonce.copyBytes())
            if (f.text("name") == "applied-historical-present") {
                assertEquals(RoutingStatusOutcome.APPLIED, value.outcome); assertEquals(3uL, value.appliedRevision)
                assertEquals(RoutingStatusMode.PRESENT, value.state.mode); assertEquals(5uL, value.state.revision)
            }
            if (f.text("name") == "unsigned-max") { assertEquals(ULong.MAX_VALUE, value.state.revision); assertEquals(ULong.MAX_VALUE, value.sampledAtMilliseconds) }
        }
    }
    @Test fun signedMalformedResponseClaimsRemainRejected() {
        val v = vectors(); val rows = v.getValue("responsesInvalid").jsonArray; assertTrue(rows.size > 100)
        for (row in rows) {
            val f = row.jsonObject; val bytes = hex(f.text("hex")); val signature = hex(f.text("signature")); val key = hex(v.text("publicKey"))
            assertTrue(P256Verification.verify(signature, key, hex(f.text("signingInput"))), f.text("name"))
            assertFails(f.text("name")) { RoutingStatusResponse.decode(bytes) }
            assertFails(f.text("name")) { verify(signature, key, bytes) }
        }
    }
    @Test fun signaturesSeparateKeysTypesPurposesVersionsAndDomains() {
        val v = vectors()
        for (row in v.getValue("responsesValid").jsonArray) {
            val f = row.jsonObject; val bytes = hex(f.text("hex")); val key = hex(v.text("publicKey"))
            assertContentEquals(hex(f.text("signingInput")), RoutingStatusSigningInput.make(1u, bytes, limits))
            assertTrue(verify(hex(f.text("signature")), key, bytes), f.text("name"))
            assertFalse(verify(hex(f.text("signature")), hex(v.text("otherPublicKey")), bytes), f.text("name"))
            for (name in listOf("wrongPurposeSignature","wrongTypeSignature","wrongVersionSignature","approvalSignature","gatewaySignature")) {
                assertFalse(verify(hex(f.text(name)), key, bytes), f.text("name"))
            }
            assertFalse(verify(byteArrayOf(), key, bytes)); assertFalse(verify(hex(f.text("signature")), byteArrayOf(), bytes))
        }
    }
    @Test fun signatureRejectsEveryChangedBoundField() {
        val v = vectors(); val row = v.getValue("responsesValid").jsonArray.map { it.jsonObject }.single { it.text("name") == "applied-historical-present" }
        val original = (DeterministicCbor.decode(hex(row.text("hex")), RoutingStatusResponse.LIMITS) as CborValue.Fields).values
        for (key in 0uL..16uL) {
            val changed = when (val value = original.getValue(key)) {
                is CborValue.Bytes -> CborValue.Bytes(value.copyBytes().also { it[0] = (it[0].toInt() xor 1).toByte() })
                is CborValue.Unsigned -> CborValue.Unsigned(value.value + 1u)
                CborValue.Null -> CborValue.Bytes(byteArrayOf())
                else -> error("Unexpected fixture")
            }
            val bytes = DeterministicCbor.encode(CborValue.Fields(original + (key to changed)), RoutingStatusResponse.LIMITS)
            assertFalse(runCatching { verify(hex(row.text("signature")), hex(v.text("publicKey")), bytes) }.getOrDefault(false), "field $key")
        }
    }
    @Test fun framesRoundTripAndRejectMalformedOrMismatchedNestedNonce() {
        val v = vectors(); val valid = v.getValue("framesValid").jsonArray; assertEquals(23, valid.size)
        for (row in valid) {
            val f = row.jsonObject; val bytes = hex(f.text("hex")); val frame = PhoneRoutingFrame.decode(bytes)
            assertContentEquals(bytes, frame.encode(), f.text("name")); assertEquals("PhoneRoutingFrame(redacted)", frame.toString())
        }
        val invalid = v.getValue("framesInvalid").jsonArray; assertTrue(invalid.size > 15)
        for (row in invalid) { val f = row.jsonObject; assertFails(f.text("name")) { PhoneRoutingFrame.decode(hex(f.text("hex"))) } }
    }
    @Test fun versionAndSigningResourceLimits() {
        val row = vectors().getValue("responsesValid").jsonArray[0].jsonObject; val bytes = hex(row.text("hex"))
        for (version in listOf(0uL,2uL,ULong.MAX_VALUE)) { assertFails { RoutingStatusSigningInput.make(version, bytes, limits) } }
        assertFails { RoutingStatusSigningInput.make(1u, bytes, CborLimits(hex(row.text("signingInput")).size-1,2,16)) }
        assertFails { RoutingStatusSigningInput.make(1u, bytes, CborLimits(3200,1,2)) }
    }
    @Test fun constructorsAndGettersCopyMutableArraysAndRedactDescriptions() {
        val v = vectors(); val row = v.getValue("responsesValid").jsonArray.map { it.jsonObject }.single { it.text("name") == "applied-historical-present" }
        val original = RoutingStatusResponse.decode(hex(row.text("hex"))); val nonce = original.queryNonce.copyBytes(); val epoch = original.clockEpoch.copyBytes(); val digest = original.controlDigest!!.copyBytes()
        val value = RoutingStatusResponse(original.scope,nonce,original.outcome,epoch,original.sampledAtMilliseconds,original.state,controlDigest=digest,appliedRevision=original.appliedRevision)
        nonce.fill(0);epoch.fill(0);digest.fill(0);value.queryNonce.copyBytes().fill(0);value.clockEpoch.copyBytes().fill(0);value.controlDigest!!.copyBytes().fill(0)
        assertContentEquals(original.encode(),value.encode()); assertEquals("RoutingStatusResponse(redacted)",value.toString());assertEquals("RoutingStatusState(redacted)",value.state.toString())
        val signature=ByteArray(64) { 1 };val body=value.encode();val frame=PhoneRoutingFrame.Response(value.queryNonce.copyBytes(),body,signature);val encoded=frame.encode();body.fill(0);signature.fill(0)
        assertContentEquals(encoded,frame.encode())
    }
}
