package dev.remozio.phone.requests

import dev.remozio.protocol.*
import java.io.Closeable
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
import org.junit.Test
import kotlin.test.*

/** Actual Swift/Kotlin exchange with synthetic trust. No device, enrollment flow, or target executor. */
class ApprovalFlowTest {
    private val limits = CborLimits(32768, 32, 4096)
    private val requestLimits = RequestLimits(limits, limits, limits, limits)
    private val capabilities = ContractCapabilities(mapOf(RequestContract(RequestKind.COMMAND, 1u, 1u) to emptySet()))
    private fun id(value: Int, count: Int = 16) = ByteArray(count) { value.toByte() }
    private fun instant(ms: ULong = 100u) = ElapsedInstant(0, ms)

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
            assertEquals("unavailableRequest", peer.receive().text("rejection"))
            for (session in listOf(a, b)) {
                peer.apply(session, accepted, 110u)
                val snapshot = session.snapshot(instant(110u))
                assertNotNull(snapshot.capture)
                assertContentEquals(id(first), assertNotNull(snapshot.status).status.decisionPhoneID)
            }
            peer.send(peer.decision(first))
            assertEquals("unavailableRequest", peer.receive().text("rejection"))
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
        peer.send(mapOf("command" to "narrowA"))
        assertEquals("narrowedA", peer.receive().text("control"))
        peer.send(peer.decision(5))
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

    private fun withPeer(block: (Peer) -> Unit) = Peer().use { peer -> peer.start(); block(peer) }

    private inner class Peer : Closeable {
        private val mac = newKey()
        private val a = newKey()
        private val b = newKey()
        private val process = ProcessBuilder(
            checkNotNull(System.getProperty("remozio.test.swiftPeer")),
            checkNotNull(System.getProperty("remozio.test.commandCapture")),
        ).redirectErrorStream(true).start()
        private val input = process.outputStream.bufferedWriter()
        private val output = process.inputStream.bufferedReader()
        private val reader = Executors.newSingleThreadExecutor()
        lateinit var initial: JsonObject
        private lateinit var request: IssuedRequestPayload

        fun start() {
            send(mapOf("command" to "setup", "authoritySeed" to scalar((mac.private as ECPrivateKey).s).hex(),
                "phoneA" to publicKey(a).hex(), "phoneB" to publicKey(b).hex()))
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
            purpose: SigningPurpose = SigningPurpose.BIOMETRIC_AUTHORIZATION): Map<String, String> {
            val digest = request.requestDigest(limits, limits).apply { if (wrongDigest) this[0] = (this[0].toInt() xor 1).toByte() }
            val payload = DecisionPayload(request.macID, request.accountID, request.requestID, digest,
                request.challenge, id(phone), id(if (phone == 5) 11 else 12),
                CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)).encode(limits)
            val signature = Signature.getInstance("SHA256withECDSAinP1363Format").run {
                initSign((if (phone == 5) a else b).private)
                update(SigningInput.make(1u, ApprovalMessageType.DECISION, purpose, payload, limits, limits))
                sign()
            }
            return mapOf("command" to "decision", "body" to payload.hex(), "signature" to signature.hex())
        }

        fun send(fields: Map<String, String>) {
            input.write(buildJsonObject { fields.forEach { (key, value) -> put(key, value) } }.toString())
            input.newLine()
            input.flush()
        }

        fun receive(): JsonObject {
            val line = try { reader.submit<String> { output.readLine() }.get(10, TimeUnit.SECONDS) }
                catch (failure: Exception) { process.destroyForcibly(); throw failure }
            check(line != null && line.length <= 140_000) { "Synthetic peer returned no bounded response" }
            return Json.parseToJsonElement(line).jsonObject
        }

        override fun close() {
            var exitStatus: Int? = null
            try {
                input.close()
                if (process.waitFor(3, TimeUnit.SECONDS)) exitStatus = process.exitValue()
            } finally {
                process.destroyForcibly().waitFor(3, TimeUnit.SECONDS)
                reader.shutdownNow()
                output.close()
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
