package dev.remozio.protocol

import java.io.File
import kotlin.test.*
import kotlinx.serialization.json.*

private fun updateChannelVectors(property: String) = Json.parseToJsonElement(File(checkNotNull(System.getProperty(property))).readText()).jsonObject
private fun JsonObject.channelText(name: String) = getValue(name).jsonPrimitive.content
private fun channelHex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

class UpdateSchedulingStatusResponseTest {
    private val limits = CborLimits(4096, 2, 32)
    private fun vectors() = updateChannelVectors("remozio.updateSchedulingStatusVectors")
    private fun verify(signature: ByteArray, key: ByteArray, payload: ByteArray) =
        UpdateSchedulingStatusSignature.verify(signature, key, 1u, payload, limits)
    @Test fun sharedStatusClaimsPreserveAllUnsignedValuesAndExactBytes() {
        val v = vectors(); val rows = v.getValue("valid").jsonArray; assertEquals(6, rows.size)
        for (element in rows) {
            val row = element.jsonObject; val bytes = channelHex(row.channelText("hex")); val value = UpdateSchedulingStatusResponse.decode(bytes)
            assertContentEquals(bytes, value.encode()); assertEquals(row.channelText("generation").toULong(), value.generation)
            assertEquals(row.channelText("revision").toULong(), value.revision)
            assertEquals(row["action"].takeUnless { it == JsonNull }?.jsonPrimitive?.content?.toULong(), value.requestedAction?.tag)
            assertContentEquals(channelHex(row.channelText("signingInput")), UpdateSchedulingStatusSigningInput.make(1u, bytes, limits))
            assertTrue(verify(channelHex(row.channelText("signature")), channelHex(v.channelText("publicKey")), bytes))
        }
    }
    @Test fun malformedSignedClaimsFailBeforeSignatureVerification() {
        val v = vectors(); val rows = v.getValue("invalid").jsonArray; assertEquals(54, rows.size); var signed = 0
        for (element in rows) {
            val row = element.jsonObject; val bytes = channelHex(row.channelText("hex"))
            assertFails(row.channelText("name")) { UpdateSchedulingStatusResponse.decode(bytes) }
            assertFails(row.channelText("name")) { UpdateSchedulingStatusSigningInput.make(1u, bytes, limits) }
            if ("signature" in row) {
                signed += 1
                assertTrue(P256Verification.verify(channelHex(row.channelText("signature")), channelHex(v.channelText("publicKey")), channelHex(row.channelText("signingInput"))))
                assertFails { verify(channelHex(row.channelText("signature")), channelHex(v.channelText("publicKey")), bytes) }
            }
        }
        assertEquals(6, signed)
    }
    @Test fun signatureBindsEveryFieldTheRootKeyAndTheStatusDomain() {
        val v = vectors(); val key = channelHex(v.channelText("publicKey"))
        for (element in v.getValue("valid").jsonArray) {
            val row = element.jsonObject; val bytes = channelHex(row.channelText("hex")); val signature = channelHex(row.channelText("signature"))
            assertFalse(verify(signature, channelHex(v.channelText("otherPublicKey")), bytes))
            for (name in listOf("wrongVersionSignature", "wrongTypeSignature", "wrongPurposeSignature", "phoneControlDomainSignature"))
                assertFalse(verify(channelHex(row.channelText(name)), key, bytes))
            val fields = (DeterministicCbor.decode(bytes, UpdateSchedulingStatusResponse.LIMITS) as CborValue.Fields).values
            for (field in 1uL..10uL) {
                val changed = when (val value = fields.getValue(field)) {
                    is CborValue.Bytes -> CborValue.Bytes(value.copyBytes().also { it[0] = (it[0].toInt() xor 1).toByte() })
                    is CborValue.Unsigned -> CborValue.Unsigned(if (value.value == ULong.MAX_VALUE) 1u else value.value + 1u)
                    CborValue.Null -> if (field == 10uL) CborValue.Bytes(ByteArray(32) { 5 }) else CborValue.Unsigned(0u)
                    else -> error("Unexpected fixture")
                }
                val mutated = DeterministicCbor.encode(CborValue.Fields(fields + (field to changed)), UpdateSchedulingStatusResponse.LIMITS)
                assertFalse(runCatching { verify(signature, key, mutated) }.getOrDefault(false))
            }
        }
    }
    @Test fun resourceLimitsWireVersionAndDescriptionsRemainStrict() {
        val row = vectors().getValue("valid").jsonArray[0].jsonObject; val bytes = channelHex(row.channelText("hex"))
        for (wire in listOf(0uL, 2uL, ULong.MAX_VALUE)) assertFails { UpdateSchedulingStatusSigningInput.make(wire, bytes, limits) }
        assertFails { UpdateSchedulingStatusResponse.decode(ByteArray(2049)) }
        assertFails { UpdateSchedulingStatusSigningInput.make(1u, bytes, CborLimits(channelHex(row.channelText("signingInput")).size - 1, 2, 32)) }
        assertEquals("UpdateSchedulingStatusResponse(redacted)", UpdateSchedulingStatusResponse.decode(bytes).toString())
    }
    @Test fun arraysAreCopiedAndObservationCannotClaimACommittedControl() {
        val first = UpdateSchedulingStatusResponse.decode(channelHex(vectors().getValue("valid").jsonArray[0].jsonObject.channelText("hex")))
        val nonce = first.queryNonce.copyBytes(); val update = first.updateID.copyBytes()
        val value = UpdateSchedulingStatusResponse(first.scope, nonce, update, 1u, 0u, null)
        nonce.fill(0); update.fill(0); value.queryNonce.copyBytes().fill(0); value.updateID.copyBytes().fill(0)
        assertContentEquals(first.encode(), value.encode()); assertNull(value.controlDigest)
        assertFails { UpdateSchedulingStatusResponse(first.scope, first.queryNonce.copyBytes(), first.updateID.copyBytes(), 1u, 0u, UpdateSchedulingAction.DEFER_UPDATE) }
        assertFails { UpdateSchedulingStatusResponse(first.scope, first.queryNonce.copyBytes(), first.updateID.copyBytes(), 1u, 1u, null) }
    }
}
