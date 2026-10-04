package dev.remozio.phone.requests

import dev.remozio.protocol.*
import java.io.File
import java.io.IOException
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlin.test.*

class CommandRequestReceiverTest {
    private val bound = CborLimits(32768, 32, 4096)
    private val limits = RequestLimits(bound, bound, bound, bound)
    private val capture = File(checkNotNull(System.getProperty("remozio.test.commandCapture"))).readBytes()
    private fun id(value: Int, count: Int = 16) = ByteArray(count) { value.toByte() }
    private fun scope(mac: Int = 1) = ChannelScope(id(mac), id(2), id(3), id(4))
    private class Wire(override val scope: ChannelScope, override val supportsCommands: Boolean = true,
                       override val maximumPayloadBytes: Int = 65536) : RequestMessageChannel {
        val queue = Channel<ByteArray>(8)
        var closed = false
        override suspend fun receive() = queue.receiveCatching().getOrNull()
        override fun close() { closed = true; queue.cancel() }
    }
    private inner class Mac(val identity: Int = 1) {
        private val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val publicKey: ByteArray get() = (key.public as ECPublicKey).w.let { point ->
            fun scalar(n: java.math.BigInteger) = n.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
            byteArrayOf(4) + scalar(point.affineX) + scalar(point.affineY)
        }
        var requestID = 5
        var challengeValue = 6
        val request get() = IssuedRequestPayload(RequestContract(RequestKind.COMMAND, 1u, 1u), id(identity), id(2), id(requestID), id(challengeValue, 32),
            emptySet(), 1000u, 61000u, capture, listOf(CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)), bound, bound)
        fun envelope(body: ByteArray, type: ApprovalMessageType, purpose: SigningPurpose): ByteArray {
            val signature = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
                initSign(key.private); update(SigningInput.make(1u, type, purpose, body, bound, bound)); sign()
            })
            return ApprovalMessage(1u, type, purpose, body, signature).encode(bound.maxBytes)
        }
        fun issued() = envelope(request.encode(bound), ApprovalMessageType.REQUEST, SigningPurpose.ISSUED_REQUEST)
        fun status(terminal: Boolean = false) = envelope(RequestStatusPayload(id(identity), id(2), id(requestID), request.requestDigest(bound, bound),
            request.challenge, if (terminal) 2u else 1u, if (terminal) RequestPhase.EXPIRED else RequestPhase.PRESENTED,
            if (terminal) RequestStatusReason.AUTHORIZATION_EXPIRED else RequestStatusReason.NONE, id(7),
            if (terminal) 60000u else 10u, if (terminal) null else 60000u, null, false, if (terminal) 60000u else null, null).encode(bound),
            ApprovalMessageType.STATUS, SigningPurpose.STATUS)
        fun enroll(inbox: CommandRequestInbox = CommandRequestInbox(2, 4), retired: RetiredCommandRequests? = null) =
            inbox.add(id(identity), id(2), publicKey, limits, retired)
    }
    private fun bind(enrollment: CommandRequestEnrollment, wire: RequestMessageChannel, time: ULong = 100u) =
        CommandRequestReceiver.bind(enrollment, wire, id(3), id(4)) { ElapsedInstant(0, time) }
    private suspend fun deliver(enrollment: CommandRequestEnrollment, mac: Mac, vararg messages: ByteArray, time: ULong = 100u) {
        val wire = Wire(scope(mac.identity))
        messages.forEach { wire.queue.send(it) }; wire.queue.close()
        bind(enrollment, wire, time).run()
        assertTrue(wire.closed)
    }
    @Test fun sharedMemoryCapacityPreservesExistingOwnersAndTerminalStatusReleasesCapture() = runBlocking<Unit> {
        val budget = CommandMemoryBudget(capture.size.toLong() + 2048, 10000)
        val firstInbox = CommandRequestInbox(1, 128, budget)
        val secondInbox = CommandRequestInbox(1, 128, budget)
        val a = Mac(); val b = Mac(8)
        val first = a.enroll(firstInbox); val second = b.enroll(secondInbox)
        deliver(first, a, a.issued(), a.status())
        val retained = first.sessions().single()
        // A duplicate needs no additional retained reservation.
        deliver(first, a, a.issued())
        assertSame(retained, first.sessions().single())
        assertFailsWith<RequestCapacityException> { deliver(second, b, b.issued()) }
        assertTrue(second.sessions().isEmpty()); assertFalse(retained.closed.value)
        deliver(first, a, a.status(true))
        deliver(second, b, b.issued())
        assertEquals(1, second.sessions().size)
        firstInbox.close(); secondInbox.close()
        val third = a.enroll(CommandRequestInbox(1, 128, budget))
        deliver(third, a, a.issued()); third.close()
    }

    @Test fun itemBudgetAndReservationReleaseAreIndependentOfByteCapacity() {
        val budget = CommandMemoryBudget(100000, 100)
        val first = budget.retain(100, 36)
        assertEquals(InboxRejection.CAPACITY, assertFailsWith<InboxException> { budget.retain(1, 1) }.reason)
        first.releaseCapture()
        // Terminal metadata remains reserved until retirement or closure.
        assertFailsWith<InboxException> { budget.retain(1, 1) }
        first.close(); first.close()
        budget.retain(999, 36).close()
    }

    @Test fun reconnectPreservesTimersAndTerminalOwnersInObservableState() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll()
        deliver(enrollment, mac, mac.issued(), mac.status())
        val owner = enrollment.requestSessions.value.single()
        assertSame(owner, enrollment.sessions().single())
        val initial = owner.snapshot(ElapsedInstant(0, 100u)).status!!
        assertTrue(initial.timing.deliveryDelayUnknown)
        deliver(enrollment, mac, mac.issued(), mac.status(), time = 200u)
        assertSame(owner, enrollment.requestSessions.value.single())
        assertEquals(110uL, owner.snapshot(ElapsedInstant(0, 200u)).status!!.timing.ageLowerBoundMs)
        deliver(enrollment, mac, mac.status(true), mac.issued(), time = 300u)
        assertSame(owner, enrollment.requestSessions.value.single())
        assertNull(owner.snapshot(ElapsedInstant(0, 300u)).capture)
        assertEquals(RequestPhase.EXPIRED, owner.snapshot(ElapsedInstant(0, 300u)).status!!.status.phase)
    }
    @Test fun invalidSignatureAndCrossMacMessagesCannotPublishRequests() = runBlocking<Unit> {
        val mac = Mac(); val other = Mac(8); val enrollment = mac.enroll()
        val message = ApprovalMessage.decode(mac.issued(), bound.maxBytes)
        val bad = ApprovalMessage(1u, message.type, message.purpose, message.body.copyBytes(), ByteArray(64)).encode(bound.maxBytes)
        for (bytes in listOf(bad, other.issued())) {
            assertFailsWith<IOException> { deliver(enrollment, mac, bytes) }
            assertTrue(enrollment.requestSessions.value.isEmpty())
        }
    }
    @Test fun statusesCannotCreateRequestsAndDecisionsCannotEnterPhoneInbox() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll()
        assertFailsWith<IOException> { deliver(enrollment, mac, mac.status()) }
        val decision = mac.envelope(byteArrayOf(0xa0.toByte()), ApprovalMessageType.DECISION, SigningPurpose.CANCELLATION)
        assertFailsWith<IOException> { deliver(enrollment, mac, decision) }
        assertTrue(enrollment.sessions().isEmpty())
    }
    @Test fun replacementClosesOldSocketAndRejectsItsLateCallback() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll()
        val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<ByteArray>()
        val oldWire = object : RequestMessageChannel {
            override val scope = scope()
            override val supportsCommands = true
            override val maximumPayloadBytes = 65536
            var closed = false
            override suspend fun receive(): ByteArray? { entered.complete(Unit); return release.await() }
            override fun close() { closed = true }
        }
        val old = bind(enrollment, oldWire)
        val running = async { old.run() }
        entered.await()
        val replacement = Wire(scope()); val next = bind(enrollment, replacement)
        assertTrue(oldWire.closed)
        release.complete(mac.issued()); running.await()
        assertTrue(enrollment.sessions().isEmpty()); assertFalse(replacement.closed)
        replacement.queue.send(mac.issued()); replacement.queue.close(); next.run()
        assertEquals(1, enrollment.sessions().size)
    }
    @Test fun removingOneMacClosesItsPendingReadAndKeepsOtherMacState() = runBlocking<Unit> {
        val inbox = CommandRequestInbox(2, 4); val a = Mac(); val b = Mac(8)
        val first = a.enroll(inbox); val second = b.enroll(inbox)
        deliver(first, a, a.issued()); deliver(second, b, b.issued())
        val captured = first.sessions().single()
        val wire = Wire(scope()); val receiver = bind(first, wire)
        val running = async(start = CoroutineStart.UNDISPATCHED) { receiver.run() }
        assertTrue(inbox.remove(first)); running.await()
        assertTrue(wire.closed); assertTrue(captured.closed.value); assertTrue(first.requestSessions.value.isEmpty())
        assertFalse(second.sessions().single().closed.value)
    }
    @Test fun failedBindingClosesNewChannelWithoutDisplacingExistingReceiver() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll()
        val current = Wire(scope()); val owner = bind(enrollment, current)
        for (wrong in listOf(Wire(scope(8)), Wire(scope(), supportsCommands = false), Wire(scope(), maximumPayloadBytes = 10))) {
            assertFails { bind(enrollment, wrong) }
            assertTrue(wrong.closed); assertFalse(current.closed)
        }
        current.queue.send(mac.issued()); current.queue.close(); owner.run()
        assertEquals(1, enrollment.sessions().size)
    }
    @Test fun cancellationClosesConnectionWithoutInventingTerminalOutcome() = runBlocking<Unit> {
        val mac = Mac(); val enrollment = mac.enroll()
        deliver(enrollment, mac, mac.issued(), mac.status())
        val wire = Wire(scope()); val receiver = bind(enrollment, wire)
        val running = launch(start = CoroutineStart.UNDISPATCHED) { receiver.run() }
        running.cancelAndJoin()
        assertTrue(wire.closed)
        val snapshot = enrollment.sessions().single().snapshot(ElapsedInstant(0, 100u))
        assertEquals(RequestPhase.PRESENTED, snapshot.status!!.status.phase); assertNotNull(snapshot.capture)
    }
    private class Retired : RetiredCommandRequests {
        val digests = mutableMapOf<CborValue.Bytes, ByteArray>()
        var failWrite = false
        var failRead = false
        var closed = false
        override fun lookup(requestID: ByteArray): ByteArray? {
            check(!closed && !failRead)
            return digests[CborValue.Bytes(requestID)]?.copyOf()
        }
        override fun remember(requestID: ByteArray, requestDigest: ByteArray) {
            check(!closed && !failWrite)
            val key = CborValue.Bytes(requestID)
            val previous = digests[key]
            check(previous == null || previous.contentEquals(requestDigest))
            digests[key] = requestDigest.copyOf()
        }
        override fun close() { closed = true }
    }

    @Test fun terminalReplacementReusesMetadataCapacityAndFailedPersistenceKeepsTheOwner() =
        checkTerminalReplacement(1)

    @Test fun sharedCapacityRetiresTerminalBeforeTheLocalWindowFills() = checkTerminalReplacement(128)

    private fun checkTerminalReplacement(window: Int) = runBlocking<Unit> {
        val budget = CommandMemoryBudget(capture.size.toLong() + 1024, 10000)
        val index = Retired(); val mac = Mac()
        val inbox = CommandRequestInbox(1, window, budget)
        val enrollment = mac.enroll(inbox, index)
        deliver(enrollment, mac, mac.issued(), mac.status(true))
        val previous = enrollment.sessions().single()
        mac.requestID = 9; index.failWrite = true
        assertFailsWith<IOException> { deliver(enrollment, mac, mac.issued()) }
        assertSame(previous, enrollment.sessions().single())
        assertFalse(previous.closed.value)
        index.failWrite = false
        deliver(enrollment, mac, mac.issued())
        assertTrue(previous.closed.value)
        assertEquals(CborValue.Bytes(id(9)), enrollment.sessions().single().identity.requestID)
        inbox.close()
    }

    @Test fun moreThan128RequestsRetireOnlyTerminalHandlesAndRejectReplays() = runBlocking<Unit> {
        val mac = Mac(); val index = Retired(); val inbox = CommandRequestInbox(1, 128)
        val enrollment = mac.enroll(inbox, index)
        var first: CommandRequestSession? = null
        for (requestID in 1..200) {
            mac.requestID = requestID
            deliver(enrollment, mac, mac.issued(), mac.status(true))
            if (requestID == 1) first = enrollment.sessions().single()
        }
        assertEquals(128, enrollment.sessions().size)
        assertEquals(72, index.digests.size)
        assertTrue(checkNotNull(first).closed.value)
        val retained = enrollment.sessions()
        mac.requestID = 1
        deliver(enrollment, mac, mac.issued(), mac.status(), mac.status(true))
        assertEquals(retained, enrollment.sessions())
        assertEquals(128, enrollment.requestSessions.value.size)
        inbox.close(); assertTrue(index.closed)
    }

    @Test fun fullActiveWindowAndFailedRetirementKeepExistingRequests() = runBlocking<Unit> {
        val mac = Mac(); val index = Retired(); val enrollment = mac.enroll(CommandRequestInbox(1, 2), index)
        mac.requestID = 1; deliver(enrollment, mac, mac.issued(), mac.status())
        mac.requestID = 2; deliver(enrollment, mac, mac.issued(), mac.status())
        val pending = enrollment.sessions()
        mac.requestID = 3
        assertFailsWith<IOException> { deliver(enrollment, mac, mac.issued()) }
        assertEquals(pending, enrollment.sessions()); assertTrue(index.digests.isEmpty())
        mac.requestID = 1; deliver(enrollment, mac, mac.status(true))
        index.failWrite = true; mac.requestID = 3
        assertFailsWith<IOException> { deliver(enrollment, mac, mac.issued()) }
        assertEquals(pending, enrollment.sessions()); assertFalse(pending.first().closed.value)
        assertEquals(RequestPhase.EXPIRED, pending.first().snapshot(ElapsedInstant(0, 100u)).status!!.status.phase)
        index.failWrite = false
        deliver(enrollment, mac, mac.issued())
        assertTrue(pending.first().closed.value); assertFalse(pending.last().closed.value)
        assertEquals(RequestPhase.PRESENTED, pending.last().snapshot(ElapsedInstant(0, 100u)).status!!.status.phase)
    }

    @Test fun retiredMembershipNeverBypassesAuthenticationOrStorageErrors() = runBlocking<Unit> {
        val mac = Mac(); val index = Retired(); val enrollment = mac.enroll(CommandRequestInbox(1, 1), index)
        mac.requestID = 1; deliver(enrollment, mac, mac.issued(), mac.status(true))
        mac.requestID = 2; deliver(enrollment, mac, mac.issued())
        mac.requestID = 1
        val message = ApprovalMessage.decode(mac.status(), bound.maxBytes)
        val bad = ApprovalMessage(1u, message.type, message.purpose, message.body.copyBytes(), ByteArray(64)).encode(bound.maxBytes)
        assertFailsWith<IOException> { deliver(enrollment, mac, bad) }
        val request = ApprovalMessage.decode(mac.issued(), bound.maxBytes)
        val badRequest = ApprovalMessage(1u, request.type, request.purpose, request.body.copyBytes(), ByteArray(64)).encode(bound.maxBytes)
        assertFailsWith<IOException> { deliver(enrollment, mac, badRequest) }
        mac.challengeValue = 9
        assertFailsWith<IOException> { deliver(enrollment, mac, mac.issued()) }
        mac.challengeValue = 6
        index.failRead = true
        assertFailsWith<IOException> { deliver(enrollment, mac, mac.issued()) }
        assertEquals(1, enrollment.sessions().size)
    }

}
