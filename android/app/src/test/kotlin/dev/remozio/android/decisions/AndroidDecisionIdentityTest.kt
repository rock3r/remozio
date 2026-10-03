package dev.remozio.android.decisions

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.requests.RequestLimits
import dev.remozio.protocol.*
import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import org.junit.Test
import kotlin.test.*

class AndroidDecisionIdentityTest {
    private val bound = CborLimits(32768, 32, 4096)
    private val limits = RequestLimits(bound, bound, bound, bound)
    private val capture = File(checkNotNull(System.getProperty("remozio.test.commandCapture"))).readBytes()
    private fun id(n: Int, size: Int = 16) = ByteArray(size) { n.toByte() }
    private fun pair() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val authority = pair()
    private val decisionKey = pair()
    private fun reference(role: EnrollmentKeyRole) = pair().let { pair ->
        EnrollmentKeyReference(role, id(role.ordinal + 10), "remozio.${role.aliasPart}.v1.${"%032x".format(role.ordinal + 10)}",
            if (role == EnrollmentKeyRole.TRANSPORT) pair.public.encoded else decisionPublicPoint(pair.public as ECPublicKey))
    }
    private val enrollment = PhoneEnrollment(id(1), id(2), id(3), id(4), id(5), "Synthetic Mac",
        decisionPublicPoint(authority.public as ECPublicKey), pair().public.encoded, reference(EnrollmentKeyRole.TRANSPORT),
        EnrollmentKeyReference(EnrollmentKeyRole.DECISION, id(11), "remozio.decision.v1.${"b".repeat(32)}",
            decisionPublicPoint(decisionKey.public as ECPublicKey)), reference(EnrollmentKeyRole.BIOMETRIC), id(6, 32), null)
    private val decline = CapturedAction(ActionChoice.DECLINE, ActionScope.CurrentRequest)
    private val execute = CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)
    private fun request(mac: Int = 2, account: Int = 3, requestID: Int = 7, actions: List<CapturedAction> = listOf(decline, execute),
                        kind: RequestKind = RequestKind.COMMAND, schema: ULong = 1u, features: Set<ULong> = emptySet(),
                        bytes: ByteArray = capture) =
        IssuedRequestPayload(RequestContract(kind, 1u, schema), id(mac), id(account), id(requestID), id(8, 32), features,
            1u, 60001u, bytes, actions, bound, bound)
    private fun sign(request: IssuedRequestPayload, key: java.security.PrivateKey = authority.private): ByteArray =
        P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
            initSign(key); update(SigningInput.make(1u, ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST,
                request.encode(bound), bound, bound)); sign()
        })
    private fun identity() = AndroidDecisionIdentity(enrollment, decisionKey.private, DecisionKeySecurity.TRUSTED_ENVIRONMENT)

    @Test fun declineBindsTheWholeAuthenticatedRequestAndTheEnrolledPhoneKey() {
        identity().use { signer ->
            val request = request()
            val carrier = signer.declineCommand(request.encode(bound), sign(request), limits)
            val decision = DecisionPayload.decode(carrier.body.copyBytes(), bound)
            assertEquals(ApprovalMessageType.DECISION, carrier.type)
            assertEquals(SigningPurpose.CANCELLATION, carrier.purpose)
            assertEquals(decline, decision.action)
            assertContentEquals(request.macID, decision.macID)
            assertContentEquals(request.accountID, decision.accountID)
            assertContentEquals(request.requestID, decision.requestID)
            assertContentEquals(request.challenge, decision.challenge)
            assertContentEquals(request.requestDigest(bound, bound), decision.requestDigest)
            assertContentEquals(enrollment.phoneID.copyBytes(), decision.phoneID)
            assertContentEquals(enrollment.decisionKey.keyID.copyBytes(), decision.keyID)
            assertTrue(ApprovalSignature.verify(carrier.signature.copyBytes(), enrollment.decisionKey.publicKey.copyBytes(), 1u,
                carrier.type, carrier.purpose, carrier.body.copyBytes(), bound, bound))
            assertFalse(ApprovalSignature.verify(carrier.signature.copyBytes(), enrollment.decisionKey.publicKey.copyBytes(), 1u,
                carrier.type, SigningPurpose.BIOMETRIC_AUTHORIZATION, carrier.body.copyBytes(), bound, bound))
        }
    }

    @Test fun refusesOtherMacAccountsChangedRequestsAndWrongAuthoritySignatures() {
        identity().use { signer ->
            for (request in listOf(request(mac = 99), request(account = 99))) {
                assertFailsWith<DecisionIdentityUnavailable> { signer.declineCommand(request.encode(bound), sign(request), limits) }
            }
            val request = request()
            assertFailsWith<DecisionIdentityUnavailable> { signer.declineCommand(request.encode(bound), sign(request, pair().private), limits) }
            assertFailsWith<DecisionIdentityUnavailable> { signer.declineCommand(request(requestID = 99).encode(bound), sign(request), limits) }
        }
    }

    @Test fun refusesAbsentDeclineUnsupportedContractsFeaturesAndInvalidCapture() {
        identity().use { signer ->
            val requests = listOf(request(actions = listOf(execute)), request(schema = 2u), request(features = setOf(1u)),
                request(kind = RequestKind.ONE_PASSWORD_ACCESS, actions = listOf(decline)), request(bytes = byteArrayOf(0xa0.toByte())))
            requests.forEach { request ->
                assertFailsWith<DecisionIdentityUnavailable> { signer.declineCommand(request.encode(bound), sign(request), limits) }
            }
        }
    }

    @Test fun closeInvalidatesOnlyItsHandleAndWrongLocalKeyCannotProduceACarrier() {
        val first = identity(); val second = identity(); val request = request(); val signature = sign(request)
        first.close(); first.close()
        assertFailsWith<DecisionIdentityUnavailable> { first.declineCommand(request.encode(bound), signature, limits) }
        second.use { assertEquals(SigningPurpose.CANCELLATION, it.declineCommand(request.encode(bound), signature, limits).purpose) }
        AndroidDecisionIdentity(enrollment, pair().private, DecisionKeySecurity.TRUSTED_ENVIRONMENT).use { wrong ->
            assertFailsWith<DecisionIdentityUnavailable> { wrong.declineCommand(request.encode(bound), signature, limits) }
        }
    }

    @Test fun boundsRequestsAndDoesNotEchoTheirContentsOnFailure() {
        identity().use { signer ->
            val request = request()
            for ((body, signature) in listOf(ByteArray(bound.maxBytes + 1) to ByteArray(64),
                request.encode(bound) to ByteArray(63), "private synthetic request".toByteArray() to ByteArray(64))) {
                assertEquals("Decision identity unavailable", assertFailsWith<DecisionIdentityUnavailable> {
                    signer.declineCommand(body, signature, limits)
                }.message)
            }
            assertEquals("AndroidDecisionIdentity(redacted)", signer.toString())
        }
    }

    @Test fun inactiveRecordsCannotLoadKeys() {
        for (phase in listOf(EnrollmentPhase.PREPARED, EnrollmentPhase.REMOVED)) {
            assertFailsWith<DecisionIdentityUnavailable> { AndroidDecisionIdentities.load(StoredPhoneEnrollment(enrollment, phase)) }
        }
    }

    @Test fun publicEncodingRejectsOtherCurves() {
        val other = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }.generateKeyPair()
        assertFailsWith<IllegalArgumentException> { decisionPublicPoint(other.public as ECPublicKey) }
        assertContentEquals(decisionKey.public.encoded.takeLast(65).toByteArray(), decisionPublicPoint(decisionKey.public as ECPublicKey))
    }
}
