package dev.remozio.phone.transport

import dev.remozio.phone.enrollment.*
import dev.remozio.protocol.*
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.*
import kotlinx.coroutines.test.runTest
import org.junit.Test
import kotlin.test.*

class PhoneRoutingChannelTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun sign(key: KeyPair, bytes: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSAinP1363Format").run {
        initSign(key.private); update(bytes); sign()
    }
    private val controlLimits = CborLimits(1024, 2, 32)
    private val inputLimits = CborLimits(3200, 2, 16)
    private inner class Fixture(private val phone: Int = 3) {
        val root = key(); val decision = key(); val biometric = key()
        var nanos = 1_000_000L
        fun local(role: EnrollmentKeyRole, pair: KeyPair) = EnrollmentKeyReference(role, id(role.ordinal + 10),
            "remozio.${role.aliasPart}.v1.${"%032x".format(role.ordinal + 10)}",
            if (role == EnrollmentKeyRole.TRANSPORT) pair.public.encoded else pair.public.encoded.takeLast(65).toByteArray())
        val record = StoredPhoneEnrollment(PhoneEnrollment(id(1), id(20), id(21), id(phone), id(4), "Synthetic host",
            root.public.encoded.takeLast(65).toByteArray(), key().public.encoded,
            local(EnrollmentKeyRole.TRANSPORT, key()), local(EnrollmentKeyRole.DECISION, decision), local(EnrollmentKeyRole.BIOMETRIC, biometric),
            ByteArray(32) { 5 }, null), EnrollmentPhase.ACTIVE)
        val scope = ChannelScope(id(20), id(21), id(phone), id(4))
        fun control(expected: ULong = 0u, wrongKey: Boolean = false): ByteArray = RoutingAwayControl(id(20), id(21), id(phone), id(4),
            id(6), ByteArray(32) { 7 }, (if (wrongKey) record.enrollment.biometricKey else record.enrollment.decisionKey).keyID.copyBytes(),
            expected, 1000u, 31_000u).encode(controlLimits)
        fun reply(query: PhoneRoutingFrame, outcome: RoutingStatusOutcome = RoutingStatusOutcome.STATUS,
                  scope: ChannelScope = this.scope, nonce: ByteArray = query.queryNonce.copyBytes(), revision: ULong = 0u,
                  challenge: ByteArray? = null, digest: ByteArray? = null, applied: ULong? = null, signer: KeyPair = root): ByteArray {
            val body = RoutingStatusResponse(scope, nonce, outcome, id(30), 100u,
                RoutingStatusState(RoutingStatusMode.PRESENT, revision, RoutingStatusDestination.LOCAL_MAC, RoutingStatusReason.MANUAL_PRESENT, false),
                challenge, digest, applied).encode()
            return PhoneRoutingFrame.Response(nonce, body, sign(signer, RoutingStatusSigningInput.make(1u, body, inputLimits))).encode()
        }
    }
    private fun frame(bytes: ByteArray) = ByteBuffer.allocate(bytes.size + 4).putInt(bytes.size).put(bytes).array()
    private inner class Peer(val fixture: Fixture, requests: List<ChannelRequestCapability> = emptyList(),
                             private val reply: (PhoneRoutingFrame) -> ByteArray?) : ApprovalByteStream {
        val owner = ChannelNegotiation(ChannelOffer(ChannelRole.MAC, fixture.scope, ByteArray(32) { 12 }, setOf(1u), requests, emptySet()), 1u)
        private val offer = owner.offer()
        private val output = ByteArrayOutputStream()
        private val input = ArrayDeque<ByteArray>()
        val waiting = CompletableDeferred<Unit>()
        var phase = 0; var queries = 0; var closes = 0
        override suspend fun awaitOpen() = Unit
        override suspend fun send(bytes: ByteArray) {
            output.write(bytes); val all = output.toByteArray()
            if (all.size < 4) return
            val count = ByteBuffer.wrap(all).int
            if (all.size < count + 4) return
            check(all.size == count + 4); output.reset()
            val body = all.copyOfRange(4, all.size)
            when (phase++) {
                0 -> { owner.receiveOffer(body); input.add(frame(offer)) }
                1 -> { owner.receiveConfirmation(body); input.add(frame(owner.confirmation())) }
                else -> {
                    val envelope = SessionEnvelope.decode(body, PhoneRoutingFrame.MAXIMUM_BYTES)
                    assertEquals(owner.confirmed().sessionID, envelope.sessionID); assertEquals(0uL, envelope.sequence)
                    val request = PhoneRoutingFrame.decode(envelope.payload.copyBytes()); queries++
                    reply(request)?.let { input.add(frame(SessionEnvelope(envelope.sessionID.copyBytes(), 0u, it).encode(PhoneRoutingFrame.MAXIMUM_BYTES))) }
                }
            }
        }
        override suspend fun receive(): ByteArray {
            if (input.isNotEmpty()) return input.removeFirst()
            waiting.complete(Unit); awaitCancellation()
        }
        override fun close() { closes++; owner.close() }
        override suspend fun awaitClosed() = Unit
    }
    private suspend fun connect(peer: Peer, purpose: EnrolledChannelPurpose = EnrolledChannelPurpose.ROUTING,
                                maximum: Int = PhoneRoutingFrame.MAXIMUM_BYTES, requests: List<ChannelRequestCapability> = emptyList()) =
        NegotiatedTLSChannel.connect(peer, peer.fixture.scope, requests, emptySet(), maximum, purpose = purpose)
    private suspend fun bind(f: Fixture, peer: Peer, timeout: Long = 1000) =
        PhoneRoutingChannel.bind(f.record, connect(peer), { f.nanos }, timeout) { ByteArray(32) { 31 } }
    private suspend fun challenge(f: Fixture): PhoneRoutingChallenge {
        val peer = Peer(f) { f.reply(it, RoutingStatusOutcome.CHALLENGE, challenge = f.control()) }
        return assertIs<PhoneRoutingResult.Verified>(bind(f, peer).challenge(0u)).challenge!!
    }
    @Test fun signedStatusBindsScopeNonceAndRootKeyThenClosesOneExchange() = runTest {
        val f = Fixture(); val peer = Peer(f) { f.reply(it) }; val channel = bind(f, peer)
        val result = assertIs<PhoneRoutingResult.Verified>(channel.status())
        assertEquals(RoutingStatusMode.PRESENT, result.response.state.mode); assertTrue(result.matchesEnrollment(f.record))
        assertTrue(result.isFresh(1000)); assertNull(result.challenge)
        assertEquals(1, peer.queries); assertEquals(1, peer.closes)
        assertFails { channel.status() }; assertEquals(1, peer.queries)
    }
    @Test fun rootKeyScopeNonceRoleAndMalformedResponsesCannotEstablishState() = runTest {
        val f = Fixture()
        val replies: List<(PhoneRoutingFrame) -> ByteArray?> = listOf(
            { f.reply(it, signer = key()) }, { f.reply(it, scope = Fixture(99).scope) }, { f.reply(it, nonce = ByteArray(32) { 99 }) },
            { it.encode() }, { byteArrayOf(1) }, { f.reply(it, RoutingStatusOutcome.CONFLICT) },
        )
        for (reply in replies) {
            val peer = Peer(f, reply = reply); val channel = bind(f, peer)
            assertFails { channel.status() }; assertEquals(1, peer.queries); assertEquals(1, peer.closes)
            assertFails { channel.status() }; assertEquals(1, peer.queries)
        }
    }
    @Test fun unsignedFailureNeverBecomesAVerifiedMode() = runTest {
        val f = Fixture(); val peer = Peer(f) { PhoneRoutingFrame.Failure(it.queryNonce.copyBytes(), PhoneRoutingFailure.INCOMPATIBLE).encode() }
        assertEquals(PhoneRoutingFailure.INCOMPATIBLE, assertIs<PhoneRoutingResult.Failure>(bind(f, peer).status()).reason)
        assertEquals(1, peer.closes)
    }
    @Test fun challengeRequiresExpectedRevisionAndDecisionKey() = runTest {
        val f = Fixture()
        for (wrongKey in listOf(false, true)) {
            val peer = Peer(f) { f.reply(it, RoutingStatusOutcome.CHALLENGE, revision = if (wrongKey) 0u else 1u,
                challenge = f.control(if (wrongKey) 0u else 1u, wrongKey)) }
            assertFails { bind(f, peer).challenge(0u) }; assertEquals(1, peer.closes)
        }
        val peer = Peer(f) { f.reply(it, RoutingStatusOutcome.CONFLICT, revision = 5u) }
        val conflict = assertIs<PhoneRoutingResult.Verified>(bind(f, peer).challenge(0u))
        assertEquals(RoutingStatusOutcome.CONFLICT, conflict.response.outcome); assertNull(conflict.challenge)
    }
    @Test fun decisionSignedAwayAcknowledgesOriginalRevisionWithoutReplacingLaterPresent() = runTest {
        val f = Fixture(); val challenge = challenge(f); val signature = sign(f.decision, challenge.signingInput())
        val peer = Peer(f) {
            val request = assertIs<PhoneRoutingFrame.Apply>(it)
            f.reply(it, RoutingStatusOutcome.APPLIED, revision = 5u,
                digest = MessageDigest.getInstance("SHA-256").digest(request.canonicalControl.copyBytes()), applied = 1u)
        }
        val result = assertIs<PhoneRoutingResult.Verified>(bind(f, peer).apply(challenge, signature))
        assertEquals(RoutingStatusMode.PRESENT, result.response.state.mode); assertEquals(5uL, result.response.state.revision)
        assertEquals(1uL, result.response.appliedRevision); assertEquals(1, peer.queries)
    }
    @Test fun biometricWrongEnrollmentAndExpiredChallengeStopBeforeSendingAway() = runTest {
        val f = Fixture(); val challenge = challenge(f)
        val decision = sign(f.decision, challenge.signingInput()); val biometric = sign(f.biometric, challenge.signingInput())
        for (mode in 0..2) {
            val current = if (mode == 1) Fixture(99) else f
            if (mode == 2) f.nanos += 30_000_000_000L
            val peer = Peer(current) { error("Invalid Away must not leave phone") }
            assertFails { bind(current, peer).apply(challenge, if (mode == 0) biometric else decision) }
            assertEquals(0, peer.queries); assertEquals(1, peer.closes)
        }
    }
    @Test fun wrongDigestAndWrongHistoricalRevisionCannotAcknowledgeAway() = runTest {
        val f = Fixture(); val challenge = challenge(f); val signature = sign(f.decision, challenge.signingInput())
        for (wrongDigest in listOf(false, true)) {
            val peer = Peer(f) {
                val bytes = assertIs<PhoneRoutingFrame.Apply>(it).canonicalControl.copyBytes()
                f.reply(it, RoutingStatusOutcome.APPLIED, revision = 5u,
                    digest = if (wrongDigest) ByteArray(32) else MessageDigest.getInstance("SHA-256").digest(bytes), applied = if (wrongDigest) 1u else 2u)
            }
            assertFails { bind(f, peer).apply(challenge, signature) }; assertEquals(1, peer.queries)
        }
    }
    @Test fun responseDeadlineAndDeviceSleepCannotRefreshAnOldObservation() = runTest {
        val f = Fixture(); val late = Peer(f) { query -> f.nanos += 1_000_000_000; f.reply(query) }
        assertFails { bind(f, late).status() }; assertEquals(1, late.queries)
        val peer = Peer(f) { f.reply(it) }; val result = assertIs<PhoneRoutingResult.Verified>(bind(f, peer).status())
        f.nanos += 500_000_001; assertEquals(501L, result.ageMilliseconds()); assertTrue(result.isFresh(1000))
        f.nanos += 1_000_000_000; assertFalse(result.isFresh(1000))
        assertEquals(1, peer.queries)
    }
    @Test fun clockRegressionPermanentlyRetiresTheObservationAndItsChallenge() = runTest {
        val f = Fixture(); val peer = Peer(f) { f.reply(it, RoutingStatusOutcome.CHALLENGE, challenge = f.control()) }
        val result = assertIs<PhoneRoutingResult.Verified>(bind(f, peer).challenge(0u)); val challenge = result.challenge!!
        f.nanos += 10_000_000; assertTrue(result.isFresh(1000))
        f.nanos -= 1_000_000; assertNull(result.ageMilliseconds()); assertFails { challenge.signingInput() }
        f.nanos += 20_000_000; assertFalse(result.isFresh(1000)); assertFails { challenge.signingInput() }
    }
    @Test fun timeoutAndCancellationCloseWithoutAnotherApplicationMessage() = runTest {
        for (cancel in listOf(false, true)) {
            val f = Fixture(); val peer = Peer(f) { null }; val channel = bind(f, peer, if (cancel) 1000 else 100)
            if (cancel) {
                val operation = async { channel.status() }; peer.waiting.await(); operation.cancelAndJoin()
            } else { assertFailsWith<TimeoutCancellationException> { channel.status() } }
            assertEquals(1, peer.queries); assertEquals(1, peer.closes)
            assertFails { channel.status() }; assertEquals(1, peer.queries)
        }
    }
    @Test fun inactiveWrongPurposeScopeAndTooSmallCarriersSendNoRoutingData() = runTest {
        val f = Fixture()
        for (mode in 0..3) {
            val peer = Peer(f) { error("Must not send routing data") }
            val channel = connect(peer, if (mode == 1) EnrolledChannelPurpose.APPROVALS else EnrolledChannelPurpose.ROUTING,
                if (mode == 3) 4095 else 4096)
            val record = when (mode) { 0 -> StoredPhoneEnrollment(f.record.enrollment, EnrollmentPhase.PREPARED); 2 -> Fixture(99).record; else -> f.record }
            assertFails { PhoneRoutingChannel.bind(record, channel, { f.nanos }) }
            assertEquals(0, peer.queries); assertEquals(1, peer.closes)
        }
    }
    @Test fun invalidClockAndNonceStopBeforeAnApplicationQuery() = runTest {
        val f = Fixture(); val peer = Peer(f) { error("Invalid clock sent routing") }; val raw = connect(peer)
        val channel = PhoneRoutingChannel.bind(f.record, raw, { -1L }, 1000) { ByteArray(32) }
        assertFails { channel.status() }; assertEquals(0, peer.queries); assertEquals(1, peer.closes)
        val other = Peer(f) { error("Invalid nonce sent routing") }
        val malformed = PhoneRoutingChannel.bind(f.record, connect(other), { f.nanos }, 1000) { ByteArray(31) }
        assertFails { malformed.status() }; assertEquals(0, other.queries)
    }
}
