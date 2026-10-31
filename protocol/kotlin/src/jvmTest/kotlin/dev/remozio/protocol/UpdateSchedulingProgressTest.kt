package dev.remozio.protocol

import java.io.File
import kotlin.test.*
import kotlinx.serialization.json.*

private fun progressHex(text: String) = text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
private fun JsonObject.progressText(name: String) = getValue(name).jsonPrimitive.content

class UpdateSchedulingProgressTest {
    private val signingLimits = CborLimits(8192, 2, 32)
    private fun vectors() = Json.parseToJsonElement(
        File(checkNotNull(System.getProperty("remozio.updateSchedulingProgressVectors"))).readText(),
    ).jsonObject
    private fun verify(signature: ByteArray, key: ByteArray, payload: ByteArray) =
        UpdateSchedulingProgressSignature.verify(signature, key, 1u, payload, signingLimits)

    @Test fun sharedObservationsPreserveCanonicalBytesAndRootSignatures() {
        val data = vectors()
        val rows = data.getValue("valid").jsonArray
        assertEquals(10, rows.size)
        for (entry in rows) {
            val row = entry.jsonObject
            val bytes = progressHex(row.progressText("hex"))
            val value = UpdateSchedulingProgressResponse.decode(bytes)
            assertContentEquals(bytes, value.encode(), row.progressText("name"))
            assertNull(value.status.controlDigest)
            assertContentEquals(progressHex(row.progressText("signingInput")),
                UpdateSchedulingProgressSigningInput.make(1u, bytes, signingLimits))
            assertTrue(verify(progressHex(row.progressText("signature")), progressHex(data.progressText("publicKey")), bytes))
            assertEquals("UpdateSchedulingProgressResponse(redacted)", value.toString())
            assertTrue(value.blockers.all { it.toString() == "UpdateSchedulingBlocker(redacted)" })
        }
    }

    @Test fun malformedAndContradictoryObservationsFailBeforeValidSignatureAcceptance() {
        val data = vectors()
        val rows = data.getValue("invalid").jsonArray
        assertEquals(118, rows.size)
        var signed = 0
        for (entry in rows) {
            val row = entry.jsonObject
            val bytes = progressHex(row.progressText("hex"))
            assertFails(row.progressText("name")) { UpdateSchedulingProgressResponse.decode(bytes) }
            assertFails(row.progressText("name")) { UpdateSchedulingProgressSigningInput.make(1u, bytes, signingLimits) }
            if ("signature" in row) {
                signed++
                val signature = progressHex(row.progressText("signature"))
                assertTrue(P256Verification.verify(signature, progressHex(data.progressText("publicKey")),
                    progressHex(row.progressText("signingInput"))))
                assertFails { verify(signature, progressHex(data.progressText("publicKey")), bytes) }
            }
        }
        assertEquals(22, signed)
    }

    @Test fun signaturesBindEnrollmentCandidateProgressAndEveryPresentationField() {
        val data = vectors()
        val key = progressHex(data.progressText("publicKey"))
        for (entry in data.getValue("valid").jsonArray) {
            val row = entry.jsonObject
            val bytes = progressHex(row.progressText("hex"))
            val signature = progressHex(row.progressText("signature"))
            assertFalse(verify(signature, progressHex(data.progressText("otherPublicKey")), bytes))
            for (field in listOf("wrongVersionSignature", "wrongTypeSignature", "wrongPurposeSignature", "oldStatusDomainSignature"))
                assertFalse(verify(progressHex(row.progressText(field)), key, bytes))
            for (item in row.getValue("mutations").jsonArray) {
                val mutation = item.jsonObject
                val changed = progressHex(mutation.progressText("hex"))
                UpdateSchedulingProgressResponse.decode(changed)
                assertFalse(verify(signature, key, changed), row.progressText("name") + ":" + mutation.progressText("name"))
            }
        }
    }

    @Test fun explicitUnknownAgesAndSecurityNeverBecomeZeroOrOrdinary() {
        val rows = vectors().getValue("valid").jsonArray
        fun value(name: String) = UpdateSchedulingProgressResponse.decode(progressHex(
            rows.single { it.jsonObject.progressText("name") == name }.jsonObject.progressText("hex")))
        val unknown = value("unknown")
        assertNull(unknown.readyAgeMillisecondsAfterObservation(1u))
        assertEquals(UpdateSchedulingSecurityStatus.UNKNOWN, unknown.security)
        assertEquals(UpdateSchedulingDesignation.UNKNOWN, unknown.designation)
        assertEquals(UpdateSchedulingAdmissionState.UNKNOWN, unknown.admission)
        assertEquals(0uL, unknown.availableActions)
        val ready = value("ready-owner")
        assertEquals(0uL, ready.readyAgeMillisecondsAfterObservation(0u))
        assertEquals(5uL, ready.readyAgeMillisecondsAfterObservation(5u))
        assertNull(ready.readyAgeMillisecondsAfterObservation(null))
        val maximum = value("maximum-values")
        assertEquals(ULong.MAX_VALUE, maximum.readyAgeMillisecondsAfterObservation(0u))
        assertNull(maximum.readyAgeMillisecondsAfterObservation(1u))
        assertNull(maximum.blockers[0].oldestAgeMillisecondsAfterObservation(1u))
        assertNull(maximum.blockers[1].oldestAgeMillisecondsAfterObservation(0u))
        assertEquals(2uL, maximum.blockers[2].oldestAgeMillisecondsAfterObservation(2u))
        assertNull(maximum.blockers[3].count)
        assertNull(maximum.blockers[3].oldestAgeMilliseconds)
    }

    @Test fun irreversiblePhasesExposeProgressWithoutOfferingReversibleActions() {
        val rows = vectors().getValue("valid").jsonArray
        for (entry in rows.filter { it.jsonObject.progressText("name").startsWith("irreversible-") }) {
            val value = UpdateSchedulingProgressResponse.decode(progressHex(entry.jsonObject.progressText("hex")))
            assertTrue(value.phase.irreversible)
            assertFalse(value.canInstallWhenCurrentWorkFinishes)
            assertFalse(value.canDeferUpdate)
            assertFalse(value.canCancelDrain)
        }
        val other = UpdateSchedulingProgressResponse.decode(progressHex(
            rows.single { it.jsonObject.progressText("name") == "draining-other-owner" }.jsonObject.progressText("hex")))
        assertFalse(other.canDeferUpdate)
        assertTrue(other.canCancelDrain)
    }

    @Test fun callerMutationAndHistoricalStatusCannotGrantObservationAuthority() {
        val first = UpdateSchedulingProgressResponse.decode(progressHex(vectors().getValue("valid").jsonArray[0].jsonObject.progressText("hex")))
        val supplied = mutableListOf(UpdateSchedulingBlocker(UpdateSchedulingBlocker.Kind.ACTIVE_COMMANDS, 1u, 0u))
        val value = UpdateSchedulingProgressResponse(first.status, first.phase, first.designation, first.security,
            first.readyAgeMilliseconds, first.availableActions, supplied, first.admission)
        val bytes = value.encode()
        supplied.clear()
        runCatching { (value.blockers as MutableList).clear() }
        assertContentEquals(bytes, value.encode())
        val old = UpdateSchedulingStatusResponse(first.status.scope, first.status.queryNonce.copyBytes(),
            first.status.updateID.copyBytes(), 1u, 1u, UpdateSchedulingAction.INSTALL_WHEN_CURRENT_WORK_FINISHES, ByteArray(32))
        assertFails { UpdateSchedulingProgressResponse(old, first.phase, first.designation, first.security,
            null, 0u, emptyList(), first.admission) }
        assertFails { UpdateSchedulingStatusResponse.decode(bytes) }
    }

    @Test fun resourceAndVersionLimitsRemainStrict() {
        val bytes = progressHex(vectors().getValue("valid").jsonArray[0].jsonObject.progressText("hex"))
        for (wire in listOf(0uL, 2uL, ULong.MAX_VALUE))
            assertFails { UpdateSchedulingProgressSigningInput.make(wire, bytes, signingLimits) }
        assertFails { UpdateSchedulingProgressResponse.decode(ByteArray(4097)) }
        val size = UpdateSchedulingProgressSigningInput.make(1u, bytes, signingLimits).size
        assertFails { UpdateSchedulingProgressSigningInput.make(1u, bytes, CborLimits(size - 1, 2, 32)) }
    }
}
