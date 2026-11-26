package dev.remozio.phone.transport

import dev.remozio.pairing.PairingSetupChannel
import dev.remozio.protocol.*
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.flowOf
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Test
import kotlin.test.*

class PairingTLSTest {
    private fun key(): KeyPair = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun point(key: KeyPair = key()): ByteArray {
        val w = (key.public as ECPublicKey).w
        fun scalar(n: java.math.BigInteger): ByteArray = n.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
        return byteArrayOf(4) + scalar(w.affineX) + scalar(w.affineY)
    }
    @Test fun productionV2UsesBiometricProofWhenMacSelectsV2(): Unit = runBlocking {
        verifyProductionProofProfile(PairingSetupPreludeV2.APPLICATION_PROTOCOL, decisionRequired = false)
    }

    @Test fun productionV2UsesBothProofsWhenMacRequiresDecisionProof(): Unit = runBlocking {
        verifyProductionProofProfile(PairingSetupPreludeV2.DECISION_PROOF_APPLICATION_PROTOCOL, decisionRequired = true)
    }

    private suspend fun verifyProductionProofProfile(serverProtocol: String, decisionRequired: Boolean) = coroutineScope {
        val phone = HeldCertificate.Builder().ecdsa256().commonName("pairing-phone").build()
        val mac = HeldCertificate.Builder().ecdsa256().commonName("pairing-mac").build()
        val server = HandshakeCertificates.Builder().heldCertificate(mac).addTrustedCertificate(phone.certificate).build()
        val keys = arrayOf<KeyManager>(HandshakeCertificates.Builder().heldCertificate(phone).build().keyManager)
        val authority = key()
        val biometric = key()
        val decision = key()
        val transportPin = point(mac.keyPair)
        val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 })
        val invitation = PairingInvitation(ByteArray(16) { 1 }, ByteArray(16) { 2 }, "Fixture", point(authority), transportPin, 1u)
        val credentials = PairingInvitationV2(invitation, ByteArray(16) { 5 }, ByteArray(32) { 6 }, lifetimeMilliseconds = 60_000u)
        val offer = ChannelOffer(ChannelRole.PHONE, scope, ByteArray(32) { 7 }, setOf(1u), emptyList(), emptySet())
        val proposal = PairingPhoneProposal(offer, PairingKey(ByteArray(16) { 8 }, point(phone.keyPair)),
            PairingKey(ByteArray(16) { 9 }, point(decision)), PairingKey(ByteArray(16) { 10 }, point(biometric)))
        val transcript = PairingTranscript(ByteArray(16) { 11 }, ByteArray(32) { 12 }, offer,
            ChannelOffer(ChannelRole.MAC, scope, ByteArray(32) { 13 }, setOf(1u), emptyList(), emptySet()), 1u, 1u,
            point(authority), transportPin, proposal.transportKey, proposal.decisionKey, proposal.biometricKey,
            ByteArray(32) { 14 }, null, ByteArray(16) { 15 }, 1000u, 2000u)
        val digest = transcript.digest()
        val setupID = transcript.setupID.copyBytes()
        fun sign(key: KeyPair, purpose: PairingProofPurpose): ByteArray =
            P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
                initSign(key.private)
                update(transcript.signingInput(purpose))
                sign()
            })
        val challenge = ByteArray(32) { 16 }
        // Use a fixed exporter with real pinned TLS to isolate ALPN and proof framing from the device provider.
        val exporter = ByteArray(32) { 17 }
        val provider = object : PairingV2TLSProvider {
            override fun configure(engine: SSLEngine) = Unit
            override fun export(engine: SSLEngine) = exporter.copyOf()
        }
        val address = InetAddress.getLoopbackAddress()
        (server.sslContext().serverSocketFactory.createServerSocket(0, 1, address) as SSLServerSocket).use { listener ->
            listener.soTimeout = 8_000
            listener.needClientAuth = true
            listener.enabledProtocols = arrayOf("TLSv1.3")
            listener.sslParameters = listener.sslParameters.apply { applicationProtocols = arrayOf(serverProtocol) }
            val peer = async(Dispatchers.IO) {
                (listener.accept() as SSLSocket).use { socket ->
                    socket.soTimeout = 8_000
                    socket.handshakeApplicationProtocolSelector = java.util.function.BiFunction { _, offered ->
                        assertEquals(listOf(PairingSetupPreludeV2.DECISION_PROOF_APPLICATION_PROTOCOL,
                            PairingSetupPreludeV2.APPLICATION_PROTOCOL), offered)
                        serverProtocol
                    }
                    socket.startHandshake()
                    assertEquals(serverProtocol, socket.applicationProtocol)
                    val input = DataInputStream(socket.inputStream)
                    val output = DataOutputStream(socket.outputStream)
                    fun read(maximum: Int): ByteArray {
                        val size = input.readInt()
                        require(size in 1..maximum)
                        return ByteArray(size).also(input::readFully)
                    }
                    fun send(body: ByteArray) {
                        output.writeInt(body.size)
                        output.write(body)
                        output.flush()
                    }
                    send(PairingSetupPreludeV2.Challenge(challenge).encode())
                    val proved = assertIs<PairingSetupPreludeV2.Proposal>(
                        PairingSetupPreludeV2.decode(read(PairingSetupPreludeV2.MAXIMUM_BYTES)))
                    assertEquals(CborValue.Bytes(credentials.proof(proposal, challenge, exporter)), proved.tag)
                    send(PairingSetupFrame.Transcript(transcript).encode())
                    val frame = PairingSetupFrame.decode(read(PairingSetupFrame.MAXIMUM_BYTES))
                    val biometricSignature = if (decisionRequired) {
                        val dual = assertIs<PairingSetupFrame.DualProof>(frame)
                        assertEquals(transcript.setupID, dual.setupID)
                        assertEquals(CborValue.Bytes(digest), dual.digest)
                        assertTrue(transcript.verify(dual.decisionSignature.copyBytes(), point(decision), PairingProofPurpose.PHONE_DECISION))
                        dual.biometricSignature
                    } else {
                        val single = assertIs<PairingSetupFrame.Proof>(frame)
                        assertEquals(transcript.setupID, single.setupID)
                        assertEquals(CborValue.Bytes(digest), single.digest)
                        single.signature
                    }
                    assertTrue(transcript.verify(biometricSignature.copyBytes(), point(biometric), PairingProofPurpose.PHONE_BIOMETRIC))
                    send(PairingSetupFrame.Receipt(setupID, digest, sign(authority, PairingProofPurpose.MAC_COMMIT)).encode())
                }
            }
            val channel = authenticatePairingV2Routes(this, flowOf(ApprovalCarrierRoute { owner ->
                DirectTCPConnector().connect(owner, InetSocketAddress(address, listener.localPort))
            }), keys, credentials, proposal, 8_000, provider, offerDecisionProof = true)
            try {
                assertEquals(decisionRequired, channel.requiresDecisionProof)
                withTimeout(8_000) {
                    val actual = channel.awaitTranscriptV2(credentials)
                    assertContentEquals(digest, actual.digest())
                    val biometricSignature = sign(biometric, PairingProofPurpose.PHONE_BIOMETRIC)
                    val receipt = if (channel.requiresDecisionProof) {
                        channel.submitDualProof(digest, biometricSignature, sign(decision, PairingProofPurpose.PHONE_DECISION))
                    } else {
                        channel.submitProof(digest, biometricSignature)
                    }
                    assertTrue(transcript.verify(receipt, point(authority), PairingProofPurpose.MAC_COMMIT))
                }
                peer.await()
            } finally {
                channel.closeAndJoin()
            }
        }
    }

    private class Carrier : EncryptedRecordTransport {
        override val maximumMessageBytes = 16_384
        private val inbound = Channel<ByteArray?>(Channel.UNLIMITED)
        @Volatile var closes = 0
        @Volatile var joins = 0
        @Volatile var sends = 0
        override suspend fun send(ciphertext: ByteArray) { sends++ }
        override suspend fun receive(): ByteArray? = inbound.receive()
        override suspend fun awaitClosed() { joins++ }
        override fun close() { closes++; inbound.trySend(null) }
    }

    @Test fun aProposalForAnotherMacStillClosesAndJoinsTheCarrier(): Unit = runBlocking {
        val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 })
        val offer = ChannelOffer(ChannelRole.PHONE, scope, ByteArray(32) { 5 }, setOf(1u), emptyList(), emptySet())
        val proposal = PairingPhoneProposal(offer, PairingKey(ByteArray(16) { 6 }, point()),
            PairingKey(ByteArray(16) { 7 }, point()), PairingKey(ByteArray(16) { 8 }, point()))
        val other = PairingInvitation(ByteArray(16) { 0x55 }, ByteArray(16) { 0x66 }, "Other", point(), point(), 1u)
        val carrier = Carrier(); val parent = SupervisorJob()
        try {
            assertFails { PairingSetupChannel.connect(CoroutineScope(parent), carrier, arrayOf<KeyManager>(), other, proposal) }
            val second = Carrier()
            assertFails { PairingSetupChannel.authenticate(CoroutineScope(parent), second, arrayOf<KeyManager>(), other, proposal) }
            assertTrue(second.closes >= 1 && second.joins >= 1 && second.sends == 0, "second closes=${second.closes} sends=${second.sends}")
        } finally { parent.cancelAndJoin() }
        assertTrue(carrier.closes >= 1 && carrier.joins >= 1 && carrier.sends == 0, "closes=${carrier.closes} joins=${carrier.joins} sends=${carrier.sends}")
    }
}
