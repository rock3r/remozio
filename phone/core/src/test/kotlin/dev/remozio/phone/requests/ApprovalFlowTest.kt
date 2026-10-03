package dev.remozio.phone.requests

import dev.remozio.phone.audit.*
import dev.remozio.protocol.*
import java.io.Closeable
import java.io.EOFException
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.*
import kotlinx.coroutines.runBlocking
import org.junit.Test
import kotlin.test.*

/** Actual Swift/Kotlin exchange with synthetic trust. No device, enrollment flow, or target executor. */
class ApprovalFlowTest {
    private val limits = CborLimits(32768, 32, 4096)
    private val requestLimits = RequestLimits(limits, limits, limits, limits)
    private val capabilities = ContractCapabilities(mapOf(RequestContract(RequestKind.COMMAND, 1u, 1u) to emptySet()))
    private fun id(value: Int, count: Int = 16) = ByteArray(count) { value.toByte() }
    private fun instant(ms: ULong = 100u) = ElapsedInstant(0, ms)

    @Test fun nativeCarriersReachTheOwnedInboxAndKeepTerminalStateAcrossReconnect() = withPeer { peer ->
        val enrollment = CommandRequestInbox(1, 4).add(id(1), id(2), peer.authorityKey, requestLimits)
        fun receive(vararg messages: ByteArray) = runBlocking {
            val channel = object : RequestMessageChannel {
                override val scope = ChannelScope(id(1), id(2), id(5), id(25))
                override val supportsCommands = true
                override val maximumPayloadBytes = 65536
                val remaining = messages.iterator()
                var closed = false
                override suspend fun receive() = if (remaining.hasNext()) remaining.next() else null
                override fun close() { closed = true }
            }
            CommandRequestReceiver.bind(enrollment, channel, id(5), id(25)) { instant() }.run()
            assertTrue(channel.closed)
        }
        receive(peer.initial.bytes("requestMessage"), peer.initial.bytes("statusMessage"))
        val owner = enrollment.requestSessions.value.single()
        assertEquals(RequestPhase.PRESENTED, owner.snapshot(instant()).status!!.status.phase)
        peer.send(peer.decision(5))
        receive(peer.receive().bytes("statusMessage"))
        peer.send(mapOf("command" to "loseOutcome"))
        receive(peer.receive().bytes("statusMessage"), peer.initial.bytes("requestMessage"))
        assertSame(owner, enrollment.requestSessions.value.single())
        assertEquals(RequestPhase.UNKNOWN, owner.snapshot(instant()).status!!.status.phase)
        assertNull(owner.snapshot(instant()).capture)
    }

    @Test fun eitherPhoneCanWinAndBothReceiveTheSameTerminalOutcome() {
        for (first in listOf(5, 6)) withPeer { peer ->
            val a = peer.session()
            val b = peer.session()
            peer.apply(a, peer.initial)
            peer.apply(b, peer.initial)
            // Queue both before reading either response. The Swift loop defines arrival order.
            peer.send(peer.decision(first))
            peer.send(peer.decision(if (first == 5) 6 else 5))
            val accepted = peer.receive()
            assertEquals("accepted", accepted.text("decision"))
            assertEquals("notPending", peer.receive().text("rejection"))
            for (session in listOf(a, b)) {
                peer.apply(session, accepted, 110u)
                val snapshot = session.snapshot(instant(110u))
                assertNotNull(snapshot.capture)
                assertContentEquals(id(first), assertNotNull(snapshot.status).status.decisionPhoneID)
            }
            peer.send(peer.decision(first))
            assertEquals("notPending", peer.receive().text("rejection"))
            val committed = peer.snapshot()
            assertEquals("4", committed.text("head"))
            assertContentEquals(id(first), committed.bytes("winner"))
            peer.send(mapOf("command" to "loseOutcome"))
            val terminal = peer.receive()
            for (session in listOf(a, b)) {
                peer.apply(session, terminal, 120u)
                assertNull(session.snapshot(instant(120u)).capture)
                assertEquals(RequestPhase.UNKNOWN, session.snapshot(instant(120u)).status!!.status.phase)
                assertEquals(StatusAcceptance.OLDER, peer.apply(session, peer.initial, 130u))
                assertNull(session.snapshot(instant(130u)).capture)
            }
        }
    }

    @Test fun revokingOnePhoneLeavesTheOtherAbleToDecide() = withPeer { peer ->
        peer.send(mapOf("command" to "revokeA"))
        assertEquals("revokedA", peer.receive().text("control"))
        assertEquals("1", peer.snapshot().text("activeDeliveries"))
        assertEquals("1", peer.snapshot().text("withdrawnDeliveries"))
        peer.send(peer.decision(5))
        assertEquals("unavailableEnrollment", peer.receive().text("rejection"))
        peer.send(peer.decision(6))
        assertEquals("accepted", peer.receive().text("decision"))
    }

    @Test fun expiredMacDeadlineRejectsAnOtherwiseValidPhoneSignature() = withPeer { peer ->
        peer.send(mapOf("command" to "expireClock"))
        assertEquals("expiredClock", peer.receive().text("control"))
        peer.send(peer.decision(5))
        assertEquals("expired", peer.receive().text("rejection"))
        val snapshot = peer.snapshot()
        assertEquals("expired", snapshot.text("ownedPhase"))
        assertEquals("false", snapshot.text("retainedCapture"))
        assertEquals("0", snapshot.text("activeDeliveries"))
        assertEquals("2", snapshot.text("withdrawnDeliveries"))
        val session = peer.session()
        peer.apply(session, peer.exchange(mapOf("command" to "status")))
        assertEquals(RequestStatusReason.AUTHORIZATION_EXPIRED, session.snapshot(instant()).status!!.status.reason)
        assertNull(session.snapshot(instant()).capture)
    }

    @Test fun changedBindingAndWrongSigningPurposeDoNotConsumeTheRequest() = withPeer { peer ->
        peer.send(peer.decision(5, wrongDigest = true))
        assertEquals("wrongRequest", peer.receive().text("rejection"))
        peer.send(peer.decision(5, purpose = SigningPurpose.ONE_TIME_UI))
        assertEquals("invalidSignature", peer.receive().text("rejection"))
        peer.send(peer.decision(5))
        assertEquals("accepted", peer.receive().text("decision"))
    }

    @Test fun decisionKeyCannotAuthorizeACommand() = withPeer { peer ->
        peer.send(peer.decision(5, useDecisionKey = true))
        assertEquals("wrongKeyClass", peer.receive().text("rejection"))
        peer.send(peer.decision(6))
        assertEquals("accepted", peer.receive().text("decision"))
    }

    @Test fun tamperedSwiftStatusCannotReplaceVerifiedPendingDetails() = withPeer { peer ->
        val session = peer.session()
        peer.apply(session, peer.initial)
        peer.send(peer.decision(5))
        val accepted = peer.receive()
        val signature = accepted.bytes("statusSignature").apply { this[0] = (this[0].toInt() xor 1).toByte() }
        assertFailsWith<StatusTrackingException> {
            session.observe(accepted.bytes("status"), signature, instant())
        }
        assertEquals(RequestPhase.PRESENTED, session.snapshot(instant()).status!!.status.phase)
        assertNotNull(session.snapshot(instant()).capture)
        peer.apply(session, accepted)
        assertEquals(RequestPhase.AUTHORIZED, session.snapshot(instant()).status!!.status.phase)
    }

    @Test fun rolledBackConsumptionNeverPublishesAcceptedAndAnotherPhoneCanWin() = withPeer { peer ->
        val session = peer.session()
        peer.apply(session, peer.initial)
        peer.send(mapOf("command" to "failNextConsumption"))
        assertEquals("consumptionFailureArmed", peer.receive().text("control"))
        peer.send(peer.decision(5))
        val failure = peer.receive()
        assertEquals("injectedPrecommitFailure", failure.text("rejection"))
        assertFalse("status" in failure || "decision" in failure)
        val rolledBack = peer.snapshot()
        assertEquals("false", rolledBack.text("consumed"))
        assertEquals("3", rolledBack.text("head"))
        assertEquals("true", rolledBack.text("retainedCapture"))
        assertEquals("2", rolledBack.text("activeDeliveries"))
        assertEquals("0", rolledBack.text("withdrawnDeliveries"))
        assertEquals(RequestPhase.PRESENTED, session.snapshot(instant()).status!!.status.phase)
        peer.send(peer.decision(6))
        val accepted = peer.receive()
        assertEquals("accepted", accepted.text("decision"))
        peer.apply(session, accepted, 110u)
        assertContentEquals(id(6), session.snapshot(instant(110u)).status!!.status.decisionPhoneID)
        val committed = peer.snapshot()
        assertEquals("4", committed.text("head"))
        val event = AuditEventMetadata.decode(committed.bytes("consumptionEvent"), limits)
        assertEquals(AuditEventKind.CONSUMED, event.kind)
        assertEquals(AuditOutcome.ACCEPTED, event.outcome)
        assertContentEquals(id(6), event.decisionPhoneID)
    }

    @Test fun rolledBackOutcomeNeverPublishesUnknownOrClearsTheCapture() = withPeer { peer ->
        val session = peer.session()
        peer.apply(session, peer.initial)
        peer.send(peer.decision(5))
        peer.apply(session, peer.receive(), 110u)
        peer.send(mapOf("command" to "failNextOutcome"))
        assertEquals("outcomeFailureArmed", peer.receive().text("control"))
        peer.send(mapOf("command" to "loseOutcome"))
        val failure = peer.receive()
        assertEquals("injectedPrecommitFailure", failure.text("rejection"))
        assertFalse("status" in failure)
        val before = peer.snapshot()
        assertEquals("authorized", before.text("phase"))
        assertEquals("0", before.text("outcomeRevision"))
        assertEquals("4", before.text("head"))
        assertEquals("true", before.text("retainedCapture"))
        assertNotNull(session.snapshot(instant(110u)).capture)
        peer.send(mapOf("command" to "loseOutcome"))
        peer.apply(session, peer.receive(), 120u)
        val after = peer.snapshot()
        assertEquals("unknown", after.text("phase"))
        assertEquals("5", after.text("head"))
        assertEquals("false", after.text("retainedCapture"))
        assertNull(session.snapshot(instant(120u)).capture)
    }

    @Test fun reopenedJournalPreservesWinnerAndReportsUnknownInAFreshEpoch() {
        for (attempted in listOf(false, true)) withPeer { peer ->
            val session = peer.session()
            peer.apply(session, peer.initial)
            peer.send(peer.decision(6))
            val accepted = peer.receive()
            peer.apply(session, accepted, 110u)
            if (attempted) {
                peer.send(mapOf("command" to "beginDispatch"))
                peer.apply(session, peer.receive(), 120u)
            }
            val before = peer.snapshot()
            peer.send(mapOf("command" to "reopenJournal"))
            peer.apply(session, peer.receive(), 130u)
            val status = session.snapshot(instant(130u)).status!!.status
            assertEquals(RequestPhase.UNKNOWN, status.phase)
            assertEquals(RequestStatusReason.AUTHORITY_RESTARTED, status.reason)
            assertContentEquals(id(6), status.decisionPhoneID)
            assertNull(session.snapshot(instant(130u)).capture)
            val after = peer.snapshot()
            assertNotEquals(before.text("epoch"), after.text("epoch"))
            assertEquals("1", after.text("head"))
            assertEquals(if (attempted) "2" else "1", after.text("outcomeRevision"))
            assertEquals(before.text("consumptionEvent"), after.text("consumptionEvent"))
            assertEquals("false", after.text("retainedCapture"))
            assertEquals("false", after.text("liveOwned"))
            val event = AuditEventMetadata.decode(after.bytes("outcomeEvent"), limits)
            assertEquals(AuditEventKind.UNKNOWN_OUTCOME, event.kind)
            assertEquals(AuditReason.AUTHORITY_RESTARTED, event.reason)
            assertContentEquals(after.bytes("epoch"), event.journalEpoch)
            peer.send(peer.decision(5))
            assertEquals("notPending", peer.receive().text("rejection"))
            assertEquals(StatusAcceptance.OLDER, peer.apply(session, accepted, 140u))
            peer.send(mapOf("command" to "reopenJournal"))
            peer.apply(session, peer.receive(), 150u)
            val again = peer.snapshot()
            assertEquals(after.text("outcomeEvent"), again.text("outcomeEvent"))
            assertEquals("0", again.text("head"))
            assertNull(session.snapshot(instant(150u)).capture)
        }
    }

    @Test fun reopeningPendingJournalCancelsRatherThanResurrectsTheCapture() = withPeer { peer ->
        val session = peer.session()
        peer.apply(session, peer.initial)
        peer.send(mapOf("command" to "reopenJournal"))
        peer.apply(session, peer.receive(), 110u)
        val status = session.snapshot(instant(110u)).status!!.status
        assertEquals(RequestPhase.CANCELLED, status.phase)
        assertEquals(RequestStatusReason.AUTHORITY_RESTARTED, status.reason)
        assertNull(status.decisionPhoneID)
        assertNull(session.snapshot(instant(110u)).capture)
        val snapshot = peer.snapshot()
        assertEquals("false", snapshot.text("consumed"))
        assertEquals("false", snapshot.text("retainedCapture"))
        assertEquals("0", snapshot.text("head"))
        peer.send(peer.decision(5))
        assertEquals("notPending", peer.receive().text("rejection"))
    }

    @Test fun verifiedSyntheticOutcomeSurvivesReopenWithoutDowngradingToUnknown() = withPeer { peer ->
        val session = peer.session()
        peer.apply(session, peer.initial)
        peer.send(peer.decision(5))
        peer.apply(session, peer.receive(), 110u)
        peer.send(mapOf("command" to "beginDispatch"))
        peer.apply(session, peer.receive(), 120u)
        assertEquals(RequestPhase.EXECUTING, session.snapshot(instant(120u)).status!!.status.phase)
        peer.send(mapOf("command" to "verifySuccess"))
        peer.apply(session, peer.receive(), 130u)
        assertEquals(RequestPhase.SUCCEEDED, session.snapshot(instant(130u)).status!!.status.phase)
        assertNull(session.snapshot(instant(130u)).capture)
        val before = peer.snapshot()
        assertEquals("6", before.text("head"))
        peer.send(mapOf("command" to "reopenJournal"))
        peer.apply(session, peer.receive(), 140u)
        val after = peer.snapshot()
        assertEquals("succeeded", after.text("phase"))
        assertEquals(before.text("outcomeEvent"), after.text("outcomeEvent"))
        assertEquals("false", after.text("retainedCapture"))
        assertEquals("0", after.text("head"))
        assertEquals(RequestPhase.SUCCEEDED, session.snapshot(instant(140u)).status!!.status.phase)
    }

    @Test fun committedDecisionsAndOutcomesReachEncryptedPhoneHistory() = withPeer { peer ->
        peer.send(peer.decision(5))
        assertEquals("accepted", peer.receive().text("decision"))
        peer.send(peer.decision(6))
        assertEquals("notPending", peer.receive().text("rejection"))
        peer.send(mapOf("command" to "beginDispatch")); peer.receive()
        peer.send(mapOf("command" to "verifySuccess")); peer.receive()
        val stored = peer.snapshot()
        val disk = CommittedAuditDisk()
        CommittedAuditPhone(peer.authorityKey, disk).use { phone ->
            phone.sync(peer::exchange)
            val state = phone.session.state.value
            assertEquals(AuditSyncPhase.COMPLETE, state.phase)
            val records = state.history.epochs.single().records
            assertEquals(listOf(AuditEventKind.ENROLLMENT_ADDED, AuditEventKind.ENROLLMENT_ADDED, AuditEventKind.REQUEST_CREATED,
                AuditEventKind.CONSUMED, AuditEventKind.DISPATCHED, AuditEventKind.VERIFIED_RESULT), records.map { it.kind })
            assertEquals((1uL..6uL).toList(), records.map { it.sequence })
            assertContentEquals(stored.bytes("consumptionEvent"), records[3].encode(limits))
            assertContentEquals(stored.bytes("outcomeEvent"), records.last().encode(limits))
            records.take(3).forEach { assertNull(it.decisionPhoneID) }
            records.drop(3).forEach { assertContentEquals(id(5), it.decisionPhoneID) }
            assertTrue(state.history.epochs.single().gaps.isEmpty())
            assertNotNull(state.lastCompletedAt)
            val encrypted = assertNotNull(disk.ciphertext)
            val plain = AuditArchiveCipher(disk.key, limits.maxBytes).decrypt(encrypted, phone.binding)
            assertFalse(encrypted.contentEquals(plain))
        }
        CommittedAuditPhone(peer.authorityKey, disk).use { restored ->
            val offline = restored.session.state.value
            assertEquals(AuditSyncPhase.IDLE, offline.phase)
            assertEquals(6, offline.history.epochs.single().records.size)
            assertNull(offline.lastCompletedAt); assertNull(offline.currentObservation)
            restored.sync(peer::exchange)
            assertEquals(6, restored.session.state.value.history.epochs.single().records.size)
            assertNotNull(restored.session.state.value.lastCompletedAt)
        }
    }

    @Test fun rolledBackEventsStayAbsentAndReopenedJournalSyncKeepsTheWinner() = withPeer { peer ->
        val request = peer.session()
        peer.apply(request, peer.initial)
        CommittedAuditPhone(peer.authorityKey, CommittedAuditDisk()).use { phone ->
            peer.send(mapOf("command" to "failNextConsumption")); peer.receive()
            peer.send(peer.decision(5))
            assertEquals("injectedPrecommitFailure", peer.receive().text("rejection"))
            phone.sync(peer::exchange)
            assertEquals(listOf(AuditEventKind.ENROLLMENT_ADDED, AuditEventKind.ENROLLMENT_ADDED, AuditEventKind.REQUEST_CREATED),
                phone.session.state.value.history.epochs.single().records.map { it.kind })
            peer.send(peer.decision(6))
            peer.apply(request, peer.receive(), 110u)
            phone.sync(peer::exchange)
            val consumed = phone.session.state.value.history.epochs.single().records.single { it.kind == AuditEventKind.CONSUMED }
            assertEquals(AuditEventKind.CONSUMED, consumed.kind)
            assertContentEquals(id(6), consumed.decisionPhoneID)
            peer.send(mapOf("command" to "failNextOutcome")); peer.receive()
            peer.send(mapOf("command" to "loseOutcome"))
            assertEquals("injectedPrecommitFailure", peer.receive().text("rejection"))
            phone.sync(peer::exchange)
            assertContentEquals(consumed.encode(limits), phone.session.state.value.history.epochs.single().records.single { it.kind == AuditEventKind.CONSUMED }.encode(limits))
            assertNotNull(request.snapshot(instant(110u)).capture)
            peer.send(mapOf("command" to "reopenJournal"))
            peer.apply(request, peer.receive(), 120u)
            assertNull(request.snapshot(instant(120u)).capture)
            val stored = peer.snapshot()
            phone.sync(peer::exchange)
            val linked = phone.session.state.value.history
            assertEquals(2, linked.epochs.size)
            assertEquals(1, AuditHistory.list(listOf(linked)).single().chains.size)
            val records = linked.epochs.flatMap { it.records }
            assertEquals(5, records.size)
            val unknown = records.single { it.kind == AuditEventKind.UNKNOWN_OUTCOME }
            assertEquals(AuditReason.AUTHORITY_RESTARTED, unknown.reason)
            assertContentEquals(stored.bytes("outcomeEvent"), unknown.encode(limits))
            records.filter { it.kind == AuditEventKind.CONSUMED || it.kind == AuditEventKind.UNKNOWN_OUTCOME }.forEach { assertContentEquals(id(6), it.decisionPhoneID) }
            assertTrue(linked.proofs.all { it.conflicts.isEmpty() })
            phone.sync(peer::exchange)
            assertEquals(5, phone.session.state.value.history.epochs.sumOf { it.records.size })
            peer.send(mapOf("command" to "reopenJournal"))
            peer.apply(request, peer.receive(), 130u)
            phone.sync(peer::exchange)
            assertEquals(3, phone.session.state.value.history.epochs.size)
            assertEquals(5, phone.session.state.value.history.epochs.sumOf { it.records.size })
            assertNull(request.snapshot(instant(130u)).capture)
            peer.send(peer.decision(5))
            assertEquals("notPending", peer.receive().text("rejection"))
        }
    }

    @Test fun eachAdmissionGeneratesFreshRequestBindings() = withPeer { first ->
        withPeer { second ->
            val a = IssuedRequestPayload.decode(first.initial.bytes("request"), limits, limits, capabilities)
            val b = IssuedRequestPayload.decode(second.initial.bytes("request"), limits, limits, capabilities)
            assertFalse(a.requestID.contentEquals(b.requestID))
            assertFalse(a.challenge.contentEquals(b.challenge))
            assertContentEquals(a.macID, b.macID)
            assertContentEquals(a.accountID, b.accountID)
            assertEquals("3", first.snapshot().text("head"))
            assertEquals("2", first.snapshot().text("activeDeliveries"))
        }
    }

    @Test fun channelIdentityAndEnrollmentEpochCannotBeTakenFromTheDecision() = withPeer { peer ->
        peer.send(peer.decision(5, channelPhone = 6))
        assertEquals("wrongPhone", peer.receive().text("rejection"))
        peer.send(peer.decision(5, channelEpoch = 26))
        assertEquals("unavailableEnrollment", peer.receive().text("rejection"))
        val untouched = peer.snapshot()
        assertEquals("3", untouched.text("head"))
        assertEquals("false", untouched.text("consumed"))
        assertEquals("2", untouched.text("activeDeliveries"))
        peer.send(peer.decision(6))
        assertEquals("accepted", peer.receive().text("decision"))
        assertEquals("0", peer.snapshot().text("activeDeliveries"))
    }

    @Test fun disappearanceReconcilesBothPhonesAndKeepsTerminalAgeOnRefresh() = withPeer { peer ->
        val sessions = listOf(peer.session(), peer.session())
        sessions.forEach { peer.apply(it, peer.initial) }
        val terminal = peer.exchange(mapOf("command" to "disappear"))
        sessions.forEach {
            peer.apply(it, terminal, 110u)
            val snapshot = it.snapshot(instant(110u))
            assertNull(snapshot.capture)
            val status = assertNotNull(snapshot.status).status
            assertEquals(RequestPhase.CANCELLED, status.phase)
            assertEquals(RequestStatusReason.TARGET_DISAPPEARED, status.reason)
            assertEquals(60uL, status.terminalAgeMs)
            assertNull(status.decisionPhoneID)
        }
        val owned = peer.snapshot()
        assertEquals("unknown", owned.text("ownedPhase"))
        assertEquals("false", owned.text("consumed"))
        assertEquals("false", owned.text("retainedCapture"))
        assertEquals("0", owned.text("activeDeliveries"))
        assertEquals("2", owned.text("withdrawnDeliveries"))
        val refreshed = peer.exchange(mapOf("command" to "status"))
        val reconnected = peer.session()
        peer.apply(reconnected, refreshed, 120u)
        assertNull(reconnected.snapshot(instant(120u)).capture)
        sessions.forEach {
            peer.apply(it, refreshed, 120u)
            val status = it.snapshot(instant(120u)).status!!.status
            assertEquals(60uL, status.terminalAgeMs)
            assertEquals(70uL, status.observedAgeMs)
            assertEquals(StatusAcceptance.OLDER, peer.apply(it, peer.initial, 130u))
        }
        peer.send(peer.decision(5))
        assertEquals("notPending", peer.receive().text("rejection"))
        assertEquals("4", peer.snapshot().text("head"))
        peer.apply(reconnected, peer.exchange(mapOf("command" to "reopenJournal")), 140u)
        val afterRestart = reconnected.snapshot(instant(140u))
        assertNull(afterRestart.capture)
        val restoredStatus = assertNotNull(afterRestart.status).status
        assertEquals(RequestStatusReason.TARGET_DISAPPEARED, restoredStatus.reason)
        assertEquals(60uL, restoredStatus.terminalAgeMs)
        assertEquals("false", peer.snapshot().text("liveOwned"))
    }

    @Test fun decisionKeyDeclineClosesDeliveriesAndCannotBeOverridden() = withPeer { peer ->
        val sessions = listOf(peer.session(), peer.session())
        sessions.forEach { peer.apply(it, peer.initial) }
        peer.send(peer.decision(5, decline = true))
        val declined = peer.receive()
        assertEquals("accepted", declined.text("decision"))
        sessions.forEach {
            peer.apply(it, declined, 110u)
            val state = it.snapshot(instant(110u))
            val status = assertNotNull(state.status).status
            assertEquals(RequestPhase.DECLINED, status.phase)
            assertContentEquals(id(5), status.decisionPhoneID)
            assertNull(state.capture)
        }
        peer.send(peer.decision(6))
        assertEquals("notPending", peer.receive().text("rejection"))
        val stored = peer.snapshot()
        assertEquals("false", stored.text("retainedCapture"))
        assertEquals("0", stored.text("activeDeliveries"))
        assertEquals("2", stored.text("withdrawnDeliveries"))
        assertEquals("4", stored.text("head"))
        assertEquals(AuditOutcome.NO_DISPATCH, AuditEventMetadata.decode(stored.bytes("consumptionEvent"), limits).outcome)
    }

    private fun withPeer(block: (Peer) -> Unit) = Peer().use { peer -> peer.start(); block(peer) }

    private inner class Peer : Closeable {
        private val mac = newKey()
        val authorityKey: ByteArray get() = publicKey(mac)
        private val a = newKey()
        private val b = newKey()
        private val aDecision = newKey()
        private val bDecision = newKey()
        private val directory = Files.createTempDirectory("remozio-approval-flow-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        private val process = try { ProcessBuilder(
            checkNotNull(System.getProperty("remozio.test.swiftPeer")),
            checkNotNull(System.getProperty("remozio.test.commandCapture")), directory.toString(),
        ).redirectErrorStream(true).start() } catch (failure: Throwable) {
            try { Files.deleteIfExists(directory) } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
            throw failure
        }
        private val input = process.outputStream.bufferedWriter()
        private val output = process.inputStream.bufferedReader()
        private val reader = Executors.newSingleThreadExecutor()
        lateinit var initial: JsonObject
        private lateinit var request: IssuedRequestPayload

        fun start() {
            send(mapOf("command" to "setup", "authoritySeed" to scalar((mac.private as ECPrivateKey).s).hex(),
                "phoneA" to publicKey(a).hex(), "phoneB" to publicKey(b).hex(),
                "phoneADecision" to publicKey(aDecision).hex(), "phoneBDecision" to publicKey(bDecision).hex()))
            initial = receive()
            // Trust is provisioned by this test controller, not learned from the response key field.
            assertContentEquals(publicKey(mac), initial.bytes("authorityKey"))
            session()
            request = IssuedRequestPayload.decode(initial.bytes("request"), limits, limits, capabilities)
        }

        fun session() = CommandRequestSession.open(initial.bytes("request"), initial.bytes("requestSignature"),
            id(1), id(2), publicKey(mac), requestLimits)

        fun apply(session: CommandRequestSession, frame: JsonObject, at: ULong = 100u) =
            session.observe(frame.bytes("status"), frame.bytes("statusSignature"), instant(at))

        fun decision(phone: Int, wrongDigest: Boolean = false,
            purpose: SigningPurpose = SigningPurpose.BIOMETRIC_AUTHORIZATION, useDecisionKey: Boolean = false,
            decline: Boolean = false, channelPhone: Int = phone, channelEpoch: Int = phone + 20): Map<String, String> {
            val digest = request.requestDigest(limits, limits).apply { if (wrongDigest) this[0] = (this[0].toInt() xor 1).toByte() }
            val payload = DecisionPayload(request.macID, request.accountID, request.requestID, digest,
                request.challenge, id(phone), id(phone + if (useDecisionKey || decline) 8 else 6),
                CapturedAction(if (decline) ActionChoice.DECLINE else ActionChoice.EXECUTE, ActionScope.CurrentRequest)).encode(limits)
            val signature = Signature.getInstance("SHA256withECDSA").run {
                initSign((if (useDecisionKey || decline) { if (phone == 5) aDecision else bDecision } else { if (phone == 5) a else b }).private)
                update(SigningInput.make(1u, ApprovalMessageType.DECISION, if (decline) SigningPurpose.CANCELLATION else purpose, payload, limits, limits))
                sign()
            }
            return mapOf("command" to "decision", "body" to payload.hex(), "signature" to P256SignatureEncoding.fromDer(signature).hex(),
                "channelPhone" to id(channelPhone).hex(), "channelEpoch" to id(channelEpoch).hex())
        }

        fun send(fields: Map<String, String>) {
            input.write(buildJsonObject { fields.forEach { (key, value) -> put(key, value) } }.toString())
            input.newLine()
            input.flush()
        }

        private fun readFrame(): String {
            val frame = StringBuilder()
            while (true) {
                val char = output.read()
                if (char < 0) throw EOFException("Synthetic approval peer closed its output")
                if (char == 10) return frame.toString()
                check(frame.length < 140_000) { "Synthetic approval response exceeded its bound" }
                frame.append(char.toChar())
            }
        }

        fun exchange(fields: Map<String, String>): JsonObject { send(fields); return receive() }

        fun snapshot(): JsonObject { send(mapOf("command" to "journalSnapshot")); return receive() }

        fun receive(): JsonObject {
            val line = try { reader.submit<String> { readFrame() }.get(10, TimeUnit.SECONDS) }
                catch (failure: Exception) { process.destroyForcibly(); throw failure }
            return Json.parseToJsonElement(line).jsonObject
        }

        override fun close() {
            var exitStatus: Int? = null
            try {
                input.close()
                if (process.waitFor(3, TimeUnit.SECONDS)) exitStatus = process.exitValue()
            } finally {
                try {
                    check(process.destroyForcibly().waitFor(3, TimeUnit.SECONDS)) { "Synthetic peer remains alive; fixture retained at $directory" }
                } finally {
                    reader.shutdownNow()
                    try { output.close() } finally {
                        if (!process.isAlive) Files.walk(directory).use { paths ->
                            paths.sorted(Comparator.reverseOrder()).forEach { Files.delete(it) }
                        }
                    }
                }
            }
            check(exitStatus == 0) { "Synthetic peer did not exit cleanly" }
        }
    }

    private fun newKey(): KeyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
    private fun scalar(value: BigInteger) = value.toByteArray().let {
        ByteArray(32 - minOf(it.size, 32)) + it.takeLast(32).toByteArray()
    }
    private fun publicKey(pair: KeyPair): ByteArray = (pair.public as ECPublicKey).w.let {
        byteArrayOf(4) + scalar(it.affineX) + scalar(it.affineY)
    }
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    private fun JsonObject.bytes(key: String) = text(key).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
