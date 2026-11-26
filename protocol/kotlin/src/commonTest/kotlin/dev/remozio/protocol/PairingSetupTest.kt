package dev.remozio.protocol

import kotlinx.serialization.json.*
import kotlin.test.*

class PairingSetupTest {
    private fun vectors() = Json.parseToJsonElement(TestVectors.pairingSetup).jsonObject
    private fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    @Test fun sharedProposalAndEverySetupFrameAgree() {
        val v = vectors(); val proposal = PairingPhoneProposal.decode(hex(v.getValue("proposal").jsonPrimitive.content))
        assertContentEquals(hex(v.getValue("proposal").jsonPrimitive.content), proposal.encode())
        proposal.validate(PairingTranscript.decode(hex(v.getValue("transcript").jsonPrimitive.content)))
        for (row in v.getValue("frames").jsonArray) {
            val bytes = hex(row.jsonObject.getValue("hex").jsonPrimitive.content)
            assertContentEquals(bytes, PairingSetupFrame.decode(bytes).encode())
            assertEquals("PairingSetupFrame(redacted)", PairingSetupFrame.decode(bytes).toString())
        }
        assertEquals("PairingPhoneProposal(redacted)", proposal.toString())
    }
    @Test fun rePairProposalBindsTheExactPredecessor() {
        val vectors = vectors()
        val rePair = vectors.getValue("rePair").jsonObject
        fun fixture(key: String) = hex(rePair.getValue(key).jsonPrimitive.content)
        val v1 = PairingPhoneProposal.decode(hex(vectors.getValue("proposal").jsonPrimitive.content))
        val transcript = PairingTranscript.decode(fixture("transcript"))
        val replacement = requireNotNull(transcript.replacement)
        val proposal = PairingPhoneProposal(v1.phone, v1.transportKey, v1.decisionKey, v1.biometricKey, replacement)
        assertContentEquals(fixture("proposal"), proposal.encode())
        PairingPhoneProposal.decode(fixture("proposal")).validate(transcript)
        assertContentEquals(fixture("frame"), PairingSetupFrame.Proposal(proposal).encode())
        assertContentEquals(fixture("frame"), PairingSetupFrame.decode(fixture("frame")).encode())
        assertContentEquals(fixture("digest"), transcript.digest())
        assertFails { v1.validate(transcript) }
        assertFails { proposal.validate(PairingTranscript.decode(hex(vectors.getValue("transcript").jsonPrimitive.content))) }

        val wrongEpoch = PairingReplacement(replacement.phoneID.copyBytes(), ByteArray(16) { 91 })
        assertFails {
            PairingPhoneProposal(v1.phone, v1.transportKey, v1.decisionKey, v1.biometricKey, wrongEpoch).validate(transcript)
        }
        val currentEpoch = (v1.phone.scope.value.values[3] as CborValue.Bytes).copyBytes()
        val invalidTargets = listOf(
            PairingReplacement(ByteArray(16) { 92 }, replacement.epoch.copyBytes()),
            PairingReplacement(replacement.phoneID.copyBytes(), currentEpoch),
        )
        for (target in invalidTargets) {
            assertFails { PairingPhoneProposal(v1.phone, v1.transportKey, v1.decisionKey, v1.biometricKey, target) }
        }
    }

    @Test fun unknownVersionsFieldsKindsAndAuthorityConfusionFail() {
        val v = vectors()
        for (row in v.getValue("invalidProposals").jsonArray) assertFails(row.jsonObject.getValue("name").jsonPrimitive.content) {
            PairingPhoneProposal.decode(hex(row.jsonObject.getValue("hex").jsonPrimitive.content))
        }
        for (row in v.getValue("invalidFrames").jsonArray) assertFails(row.jsonObject.getValue("name").jsonPrimitive.content) {
            PairingSetupFrame.decode(hex(row.jsonObject.getValue("hex").jsonPrimitive.content))
        }
        assertFails { PairingSetupFrame.decode(ByteArray(PairingSetupFrame.MAXIMUM_BYTES + 1)) }
        assertFails { PairingPhoneProposal.decode(ByteArray(66_001)) }
    }
    @Test fun sharedDecisionProofBindsTheKeyPurposeAndTranscript() {
        val vectors = Json.parseToJsonElement(TestVectors.pairingDecisionProof).jsonObject
        val transcripts = Json.parseToJsonElement(TestVectors.pairing).jsonObject.getValue("valid").jsonArray
            .map { it.jsonObject }.associateBy { it.getValue("name").jsonPrimitive.content }
        val rows = vectors.getValue("valid").jsonArray.map { it.jsonObject }
        assertEquals(listOf("add", "replace"), rows.map { it.getValue("name").jsonPrimitive.content })
        for (row in rows) {
            val name = row.getValue("name").jsonPrimitive.content
            val source = transcripts.getValue(name)
            val other = transcripts.entries.single { it.key != name }.value
            val transcript = PairingTranscript.decode(hex(source.getValue("hex").jsonPrimitive.content))
            val otherTranscript = PairingTranscript.decode(hex(other.getValue("hex").jsonPrimitive.content))
            val encoded = hex(row.getValue("frame").jsonPrimitive.content)
            val proof = assertIs<PairingSetupFrame.DualProof>(PairingSetupFrame.decode(encoded))
            val biometric = proof.biometricSignature.copyBytes()
            val decision = proof.decisionSignature.copyBytes()
            val decisionKey = transcript.decisionKey.publicKey.copyBytes()
            val biometricKey = transcript.biometricKey.publicKey.copyBytes()
            assertContentEquals(encoded, proof.encode())
            assertEquals("PairingSetupFrame(redacted)", proof.toString())
            assertEquals(transcript.setupID, proof.setupID)
            assertContentEquals(transcript.digest(), proof.digest.copyBytes())
            assertContentEquals(hex(row.getValue("decisionInput").jsonPrimitive.content),
                transcript.signingInput(PairingProofPurpose.PHONE_DECISION))
            assertTrue(transcript.verify(biometric, biometricKey, PairingProofPurpose.PHONE_BIOMETRIC))
            assertTrue(transcript.verify(decision, decisionKey, PairingProofPurpose.PHONE_DECISION))
            assertFalse(transcript.verify(biometric, decisionKey, PairingProofPurpose.PHONE_DECISION))
            assertFalse(transcript.verify(decision, biometricKey, PairingProofPurpose.PHONE_BIOMETRIC))
            assertFalse(transcript.verify(decision, biometricKey, PairingProofPurpose.PHONE_DECISION))
            assertFalse(transcript.verify(decision, decisionKey, PairingProofPurpose.PHONE_BIOMETRIC))
            assertFalse(otherTranscript.verify(decision, decisionKey, PairingProofPurpose.PHONE_DECISION))
        }
    }

    @Test fun malformedDualProofFramesFail() {
        val vectors = Json.parseToJsonElement(TestVectors.pairingDecisionProof).jsonObject
        for (entry in vectors.getValue("invalidFrames").jsonArray) {
            val row = entry.jsonObject
            assertFails(row.getValue("name").jsonPrimitive.content) {
                PairingSetupFrame.decode(hex(row.getValue("hex").jsonPrimitive.content))
            }
        }
        assertFails { PairingSetupFrame.DualProof(ByteArray(16), ByteArray(32), ByteArray(64), ByteArray(63)) }
    }

    @Test fun phoneClaimsBindOfferNonceAndEachKeyRole() {
        val v = vectors(); val transcript = PairingTranscript.decode(hex(v.getValue("transcript").jsonPrimitive.content))
        val proposal = PairingPhoneProposal.decode(hex(v.getValue("proposal").jsonPrimitive.content))
        val limits = CborLimits(66000, 3, 24)
        val f = (DeterministicCbor.decode(proposal.encode(), limits) as CborValue.Fields).values
        val offerLimits = CborLimits(65536, 5, 5000)
        val offer = (DeterministicCbor.decode(proposal.phone.encode(), offerLimits) as CborValue.Fields).values
        val changedOffer = DeterministicCbor.encode(CborValue.Fields(offer + (3uL to CborValue.Bytes(ByteArray(32) { 8 }))), offerLimits)
        val keys = (f.getValue(3u) as CborValue.ArrayValue).values
        for (changed in listOf(f + (2uL to CborValue.Bytes(changedOffer)), f + (3uL to CborValue.ArrayValue(listOf(keys[1],keys[0],keys[2]))))) {
            assertFails { PairingPhoneProposal.decode(DeterministicCbor.encode(CborValue.Fields(changed), limits)).validate(transcript) }
        }
        val invitation = PairingInvitation(ByteArray(16) { 9 }, ByteArray(16) { 2 }, "Other", transcript.macAuthorityKey.copyBytes(), transcript.macTransportKey.copyBytes(), 1u)
        assertFails { proposal.validateMacScope(invitation) }
    }
}
