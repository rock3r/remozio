package dev.remozio.protocol

import java.io.File
import kotlin.test.*
import kotlinx.serialization.json.*

class UpdateSchedulingTest {
    private val limits = CborLimits(1024, 8, 64)
    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.updateSchedulingVectors"))).readText()).jsonObject
    private fun hex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    private fun verify(signature: ByteArray, key: ByteArray, payload: ByteArray) =
        UpdateSchedulingSignature.verify(signature, key, 1u, payload, limits, limits)
    private fun identities(value: UpdateSchedulingControl) = listOf(value.macID, value.accountID, value.phoneID,
        value.enrollmentEpoch, value.operationID, value.challenge, value.keyID, value.updateID)
    private fun make(fields: List<ByteArray>, generation: ULong = 7u, issued: ULong = 1000u, expires: ULong = 2000u) =
        UpdateSchedulingControl(fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7],
            generation, 12u, issued, expires, UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES)

    @Test fun sharedFieldsActionsAndUnsignedBoundariesRoundTrip() {
        val rows = vectors().getValue("valid").jsonArray; assertEquals(5, rows.size)
        val actions = mutableSetOf<ULong>()
        for (row in rows) {
            val f = row.jsonObject; val bytes = hex(f.text("hex")); val value = UpdateSchedulingControl.decode(bytes, limits)
            assertContentEquals(bytes, value.encode(limits)); assertEquals(f.text("action").toULong(), value.action.tag)
            actions += value.action.tag
            assertEquals(f.text("generation").toULong(), value.expectedGeneration)
            assertEquals(f.text("revision").toULong(), value.expectedRevision)
            assertEquals(f.text("issued").toULong(), value.issuedAtUnixMillis)
            assertEquals(f.text("expires").toULong(), value.expiresAtUnixMillis)
            identities(value).forEachIndexed { i, field ->
                assertContentEquals(ByteArray(if (i in listOf(5, 7)) 32 else 16) { (i + 16).toByte() }, field)
            }
        }
        assertEquals(UpdateSchedulingAction.entries.map { it.tag }.toSet(), actions)
    }

    @Test fun malformedControlsRejectEvenWhenTheirSignatureIsValid() {
        val vectors = vectors(); val rows = vectors.getValue("invalid").jsonArray; assertEquals(102, rows.size)
        var signedInvalid = 0
        for (row in rows) {
            val f = row.jsonObject; val bytes = hex(f.text("hex"))
            assertFailsWith<IllegalArgumentException>(f.text("name")) { UpdateSchedulingControl.decode(bytes, limits) }
            assertFailsWith<IllegalArgumentException>(f.text("name")) { UpdateSchedulingSigningInput.make(1u, bytes, limits, limits) }
            if ("signature" in f) {
                signedInvalid++
                val signature = hex(f.text("signature")); val key = hex(vectors.text("publicKey"))
                assertTrue(P256Verification.verify(signature, key, hex(f.text("signingInput"))))
                assertFailsWith<UpdateSchedulingControlException> { verify(signature, key, bytes) }
            }
        }
        assertEquals(6, signedInvalid)
    }

    @Test fun sharedSignaturesSeparateKeysPurposesTypesVersionsAndDomains() {
        val vectors = vectors()
        for (row in vectors.getValue("valid").jsonArray) {
            val f = row.jsonObject; val bytes = hex(f.text("hex")); val signature = hex(f.text("signature")); val key = hex(vectors.text("publicKey"))
            assertContentEquals(hex(f.text("signingInput")), UpdateSchedulingSigningInput.make(1u, bytes, limits, limits))
            assertTrue(verify(signature, key, bytes)); assertFalse(verify(signature, hex(vectors.text("otherPublicKey")), bytes))
            for (wrong in listOf("wrongPurposeSignature", "wrongTypeSignature", "wrongVersionSignature",
                                 "approvalSignature", "routingSignature", "gatewaySignature")) {
                assertFalse(verify(hex(f.text(wrong)), key, bytes))
            }
            assertFalse(verify(byteArrayOf(0), key, bytes)); assertFalse(verify(signature, byteArrayOf(0), bytes))
        }
    }

    @Test fun signatureBindsEveryMutableControlField() {
        val vectors = vectors(); val row = vectors.getValue("valid").jsonArray[0].jsonObject
        val original = (DeterministicCbor.decode(hex(row.text("hex")), limits) as CborValue.Fields).values
        for (key in 1uL..13uL) {
            val changed = when (val value = original.getValue(key)) {
                is CborValue.Bytes -> CborValue.Bytes(value.copyBytes().also { it[0] = (it[0].toInt() xor 1).toByte() })
                is CborValue.Unsigned -> CborValue.Unsigned(value.value + 1u)
                else -> error("Unexpected fixture")
            }
            val bytes = DeterministicCbor.encode(CborValue.Fields(original + (key to changed)), limits)
            assertFalse(verify(hex(row.text("signature")), hex(vectors.text("publicKey")), bytes))
        }
    }

    @Test fun resourceAndWireVersionBounds() {
        val row = vectors().getValue("valid").jsonArray[0].jsonObject; val bytes = hex(row.text("hex"))
        assertContentEquals(bytes, UpdateSchedulingControl.decode(bytes, CborLimits(bytes.size, 8, 64)).encode(limits))
        for (bounds in listOf(CborLimits(bytes.size - 1, 8, 64), CborLimits(1024, 1, 2))) {
            assertFailsWith<CborException> { UpdateSchedulingControl.decode(bytes, bounds) }
            assertFailsWith<CborException> { UpdateSchedulingSigningInput.make(1u, bytes, bounds, limits) }
        }
        for (version in listOf(0uL, 2uL, ULong.MAX_VALUE)) {
            assertFailsWith<SigningInputException> { UpdateSchedulingSigningInput.make(version, bytes, limits, limits) }
        }
        val short = CborLimits(hex(row.text("signingInput")).size - 1, 8, 64)
        assertFailsWith<CborException> { UpdateSchedulingSigningInput.make(1u, bytes, limits, short) }
    }

    @Test fun constructorsRejectInvalidIdentitiesGenerationAndTime() {
        val value = UpdateSchedulingControl.decode(hex(vectors().getValue("valid").jsonArray[0].jsonObject.text("hex")), limits)
        val fields = identities(value)
        for (index in fields.indices) {
            val invalid = fields.toMutableList(); invalid[index] = byteArrayOf()
            assertFailsWith<UpdateSchedulingControlException> { make(invalid) }
        }
        assertFailsWith<UpdateSchedulingControlException> { make(fields, generation = 0u) }
        assertFailsWith<UpdateSchedulingControlException> { make(fields, expires = 1000u) }
        assertFailsWith<UpdateSchedulingControlException> { make(fields, expires = 999u) }
    }

    @Test fun constructorsAndGettersCopyArraysAndDescriptionsRedact() {
        val original = UpdateSchedulingControl.decode(hex(vectors().getValue("valid").jsonArray[0].jsonObject.text("hex")), limits)
        val fields = identities(original); val value = make(fields)
        fields.forEach { it[0] = 0 }
        identities(value).forEach { it[0] = 0 }
        assertContentEquals(original.encode(limits), value.encode(limits))
        assertEquals("UpdateSchedulingControl(redacted)", value.toString())
    }
}
