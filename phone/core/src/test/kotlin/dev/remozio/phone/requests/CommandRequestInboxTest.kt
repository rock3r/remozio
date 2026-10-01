package dev.remozio.phone.requests

import dev.remozio.protocol.*
import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.*

class CommandRequestInboxTest {
    private val bound = CborLimits(32768, 32, 4096)
    private val limits = RequestLimits(bound, bound, bound, bound)
    private val time = ElapsedInstant(0, 100u)
    private val capture = File(checkNotNull(System.getProperty("remozio.test.commandCapture"))).readBytes()
    private fun id(value: Int) = ByteArray(16) { value.toByte() }
    private inner class Mac(val mac: ByteArray = id(1), val account: ByteArray = id(2)) {
        private val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
        val publicKey: ByteArray get() = (key.public as ECPublicKey).w.let { point ->
            fun scalar(value: java.math.BigInteger) = value.toByteArray().takeLast(32).toByteArray().let {
                ByteArray(32 - it.size) + it
            }
            byteArrayOf(4) + scalar(point.affineX) + scalar(point.affineY)
        }
        fun request(requestID: Int = 3, challenge: Int = 4) = IssuedRequestPayload(
            RequestContract(RequestKind.COMMAND, 1u, 1u), mac, account, id(requestID), ByteArray(32) { challenge.toByte() },
            emptySet(), 1000u, 61000u, capture,
            listOf(CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)), bound, bound)
        fun sign(bytes: ByteArray, status: Boolean = false): ByteArray = P256SignatureEncoding.fromDer(
            Signature.getInstance("SHA256withECDSA").run {
                initSign(key.private)
                update(SigningInput.make(1u, if (status) ApprovalMessageType.STATUS else ApprovalMessageType.REQUEST,
                    if (status) SigningPurpose.STATUS else SigningPurpose.ISSUED_REQUEST, bytes, bound, bound))
                sign()
            })
        fun enroll(inbox: CommandRequestInbox) = inbox.add(mac, account, publicKey, limits)
        fun accept(enrollment: CommandRequestEnrollment, request: IssuedRequestPayload = request()): CommandRequestSession {
            val body = request.encode(bound)
            return enrollment.accept(body, sign(body))
        }
        fun terminal(session: CommandRequestSession, request: IssuedRequestPayload = request()) {
            val body = RequestStatusPayload(mac, account, request.requestID, request.requestDigest(bound, bound),
                request.challenge, 7u, RequestPhase.EXPIRED, RequestStatusReason.AUTHORIZATION_EXPIRED,
                id(5), 60000u, null, null, false, 60000u, null).encode(bound)
            assertEquals(StatusAcceptance.APPLIED, session.observe(body, sign(body, status = true), time))
        }
    }
    private fun rejected(reason: InboxRejection, block: () -> Unit) =
        assertEquals(reason, assertFailsWith<InboxException>(block = block).reason)

    @Test fun requestIDsAreIsolatedAcrossMacsAndAccounts() {
        val inbox = CommandRequestInbox(3, 2)
        val first = Mac(); val second = Mac(id(8)); val otherAccount = Mac(account = id(9))
        val a = first.enroll(inbox); val b = second.enroll(inbox); val c = otherAccount.enroll(inbox)
        val sessions = listOf(first.accept(a), second.accept(b), otherAccount.accept(c))
        assertEquals(3, sessions.map { it.identity }.toSet().size)
        val wrong = second.request().encode(bound)
        assertFailsWith<CommandSessionException> { a.accept(wrong, second.sign(wrong)) }
        first.terminal(sessions[0])
        assertNull(sessions[0].snapshot(time).capture)
        assertNotNull(sessions[1].snapshot(time).capture)
        assertNotNull(sessions[2].snapshot(time).capture)
    }

    @Test fun duplicateDeliveryKeepsTerminalOwnerAndStillAuthenticates() {
        val mac = Mac(); val enrollment = mac.enroll(CommandRequestInbox(1, 1))
        val original = mac.accept(enrollment)
        mac.terminal(original)
        assertSame(original, mac.accept(enrollment))
        assertNull(original.snapshot(time).capture)
        assertEquals(7uL, original.revisions.value)
        val body = mac.request().encode(bound)
        assertFailsWith<CommandSessionException> { enrollment.accept(body, ByteArray(64)) }
        assertSame(original, enrollment.sessions().single())
    }

    @Test fun conflictingSignedRequestCannotReplaceOwnerButNewIDCanRefresh() {
        val mac = Mac(); val enrollment = mac.enroll(CommandRequestInbox(1, 2))
        val original = mac.accept(enrollment)
        rejected(InboxRejection.CONFLICTING_REQUEST) { mac.accept(enrollment, mac.request(challenge = 9)) }
        assertSame(original, enrollment.sessions().single())
        val refreshed = mac.accept(enrollment, mac.request(requestID = 6, challenge = 9))
        assertNotSame(original, refreshed)
        assertEquals(2, enrollment.sessions().size)
    }

    @Test fun removalClearsOldHandlesAndLeavesOtherMacUsable() {
        val inbox = CommandRequestInbox(2, 1)
        val first = Mac(); val second = Mac(id(8))
        val a = first.enroll(inbox); val b = second.enroll(inbox)
        val old = first.accept(a); val other = second.accept(b)
        assertTrue(inbox.remove(a))
        assertTrue(old.closed.value)
        assertEquals(CommandRequestSnapshot(null, null, closed = true), old.snapshot(time))
        assertFailsWith<CommandSessionException> { old.observe(ByteArray(0), ByteArray(0), time) }
        rejected(InboxRejection.CLOSED) { first.accept(a) }
        assertTrue(a.sessions().isEmpty())
        assertFalse(inbox.remove(a))
        assertFalse(other.closed.value)
        assertSame(other, second.accept(b))
    }

    @Test fun replacementClosesOldIncarnationAndStaleHandlesCannotRemoveIt() {
        val inbox = CommandRequestInbox(1, 1)
        val mac = Mac(); val newMacKey = Mac()
        val oldEnrollment = mac.enroll(inbox); val old = mac.accept(oldEnrollment)
        assertFailsWith<IllegalArgumentException> { inbox.replace(oldEnrollment, ByteArray(0), limits) }
        assertFalse(old.closed.value)
        rejected(InboxRejection.ALREADY_ENROLLED) { newMacKey.enroll(inbox) }
        val replacement = inbox.replace(oldEnrollment, newMacKey.publicKey, limits)
        assertTrue(old.closed.value)
        assertFalse(inbox.remove(oldEnrollment))
        rejected(InboxRejection.STALE_ENROLLMENT) { inbox.replace(oldEnrollment, mac.publicKey, limits) }
        rejected(InboxRejection.CLOSED) { mac.accept(oldEnrollment) }
        assertFailsWith<CommandSessionException> { mac.accept(replacement) }
        assertNotNull(newMacKey.accept(replacement).snapshot(time).capture)
    }

    @Test fun capacityDoesNotEvictOwnersOrRejectAuthenticatedDuplicates() {
        val inbox = CommandRequestInbox(1, 1)
        val mac = Mac(); val enrollment = mac.enroll(inbox)
        val session = mac.accept(enrollment)
        rejected(InboxRejection.CAPACITY) { Mac(id(8)).enroll(inbox) }
        rejected(InboxRejection.CAPACITY) { mac.accept(enrollment, mac.request(requestID = 9)) }
        assertSame(session, mac.accept(enrollment))
        mac.terminal(session)
        rejected(InboxRejection.CAPACITY) { mac.accept(enrollment, mac.request(requestID = 9)) }
        assertSame(session, mac.accept(enrollment))
    }

    @Test fun mutableInputsAndReturnedIdentityCopiesCannotChangeScope() {
        val inbox = CommandRequestInbox(1, 1)
        val mac = Mac()
        val macID = mac.mac.copyOf(); val accountID = mac.account.copyOf(); val publicKey = mac.publicKey
        val enrollment = inbox.add(macID, accountID, publicKey, limits)
        macID.fill(0); accountID.fill(0); publicKey.fill(0)
        val session = mac.accept(enrollment)
        session.identity.macID.copyBytes().fill(0)
        enrollment.accountID.copyBytes().fill(0)
        assertSame(session, mac.accept(enrollment))
        assertTrue(inbox.remove(enrollment))
    }

    @Test fun concurrentDuplicatesHaveOneOwnerAndCloseCannotResurrectIt() {
        val inbox = CommandRequestInbox(1, 1)
        val mac = Mac(); val enrollment = mac.enroll(inbox)
        val body = mac.request().encode(bound); val signature = mac.sign(body)
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(4)
        try {
            val tasks = (1..8).map { executor.submit<CommandRequestSession> {
                start.await(); enrollment.accept(body, signature)
            } }
            start.countDown()
            val results = tasks.map { it.get(10, TimeUnit.SECONDS) }
            results.forEach { assertSame(results.first(), it) }
            inbox.close()
            results.forEach { assertTrue(it.closed.value); assertNull(it.snapshot(time).capture) }
            rejected(InboxRejection.CLOSED) { mac.enroll(inbox) }
            rejected(InboxRejection.CLOSED) { enrollment.accept(body, signature) }
        } finally { executor.shutdownNow() }
    }
}
