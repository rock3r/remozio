package dev.remozio.phone.crypto

import dev.remozio.pairing.PairingSetupChannel
import dev.remozio.phone.enrollment.*
import dev.remozio.phone.transport.*
import dev.remozio.protocol.*
import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Security
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.flowOf
import kotlinx.serialization.json.*
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.conscrypt.Conscrypt
import org.junit.Test
import kotlin.test.*

/** Native/JVM TLS with disposable software keys. Decision-proof cases use the checkpointed Root owner
 * with logical authorization and no installed services or hardware. */
class PairingSetupInteropTest {
    private fun key(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun point(pair: KeyPair): ByteArray {
        val p = (pair.public as ECPublicKey).w
        fun scalar(n: java.math.BigInteger): ByteArray = n.toByteArray().takeLast(32).toByteArray().let { ByteArray(32 - it.size) + it }
        return byteArrayOf(4) + scalar(p.affineX) + scalar(p.affineY)
    }
    private suspend fun rejectedWithin(timeoutMillis: Long, operation: suspend () -> Unit) {
        val failure = assertFails { withTimeout(timeoutMillis) { operation() } }
        assertFalse(failure is TimeoutCancellationException, "A timeout does not prove rejection")
    }
    private inner class Fixture(
        holdPairingStage: Boolean = false,
        rePair: Boolean = false,
        dropRePairReceipt: Boolean = false,
        decisionProof: Boolean = false,
        legacyCommit: Boolean = false,
        private val pairingV2: Boolean = decisionProof,
    ) : AutoCloseable {
        val phone = HeldCertificate.Builder().ecdsa256().commonName("disposable-pairing-phone").build()
        val mac = HeldCertificate.Builder().ecdsa256().commonName("disposable-pairing-mac").build()
        val biometric = key(); val decision = key()
        val directory = Files.createTempDirectory("remozio-pairing-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        private val process: Process
        private val stdout: BufferedReader
        val port: Int
        val receiptPort: Int?
        val invitation: PairingInvitation
        val rePairInvitation: RePairInvitation?
        val v2Invitation: PairingInvitationV2?
        val keys: Array<KeyManager> = arrayOf(HandshakeCertificates.Builder().heldCertificate(phone).build().keyManager)
        init {
            var started: Process? = null
            try {
                val identity = directory.resolve("identity.p12")
                Files.createFile(identity, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
                val password = "synthetic-only".toCharArray()
                val store = KeyStore.getInstance("PKCS12").apply {
                    load(null, password); setKeyEntry("fixture", mac.keyPair.private, password, arrayOf(mac.certificate))
                }
                Files.newOutputStream(identity).use { store.store(it, password) }
                started = ProcessBuilder(System.getProperty("remozio.test.tlsPeer"), identity.toString())
                    .redirectError(directory.resolve("stderr.log").toFile()).start()
                process = started
                stdout = process.inputStream.bufferedReader()
                val arguments = buildJsonObject {
                    put("peerPublicKey", Base64.getEncoder().encodeToString(phone.certificate.publicKey.encoded))
                    put("pairing", true)
                    put("holdPairingStage", holdPairingStage)
                    put("rePair", rePair)
                    put("dropRePairReceipt", dropRePairReceipt)
                    put("pairingV2", pairingV2)
                    put("decisionProof", decisionProof)
                    put("legacyCommit", legacyCommit)
                }
                process.outputStream.write((arguments.toString() + "\n").encodeToByteArray())
                process.outputStream.flush()
                val output = buildMap {
                    repeat(if (dropRePairReceipt) 2 else 1) { putAll(readPeerLine()) }
                }
                receiptPort = output["receiptPort"]?.jsonPrimitive?.int
                port = output.getValue("port").jsonPrimitive.int
                val text = output.getValue("invitation").jsonPrimitive.content
                rePairInvitation = if (rePair && !pairingV2) RePairInvitation.importText(text) else null
                v2Invitation = if (pairingV2) PairingInvitationV2.importText(text) else null
                invitation = v2Invitation?.invitation ?: rePairInvitation?.invitation ?: PairingInvitation.importText(text)
            } catch (failure: Throwable) {
                started?.destroyForcibly(); started?.waitFor(5, TimeUnit.SECONDS)
                directory.toFile().deleteRecursively(); throw failure
            }
        }
        fun readPeerLine(): JsonObject {
            val executor = Executors.newSingleThreadExecutor()
            return try {
                executor.submit<JsonObject> {
                    val line = checkNotNull(stdout.readLine()) { "Native pairing fixture ended before reporting its result" }
                    Json.parseToJsonElement(line).jsonObject
                }.get(10, TimeUnit.SECONDS)
            } finally { executor.shutdownNow() }
        }

        fun proposal(invite: PairingInvitation = invitation, transport: KeyPair = phone.keyPair,
                     replacement: PairingReplacement? = null): PairingPhoneProposal {
            val requests = if (pairingV2) listOf(ChannelRequestCapability(0u, 1u, 1u, emptySet())) else emptyList()
            val offer = ChannelOffer(ChannelRole.PHONE, ChannelScope(invite.macID.copyBytes(), invite.accountID.copyBytes(),
                ByteArray(16) { 3 }, ByteArray(16) { 4 }), ByteArray(32).also(java.security.SecureRandom()::nextBytes),
                setOf(1u), requests, emptySet())
            return PairingPhoneProposal(offer, PairingKey(ByteArray(16) { 5 }, point(transport)),
                PairingKey(ByteArray(16) { 6 }, point(decision)), PairingKey(ByteArray(16) { 7 }, point(biometric)), replacement)
        }
        suspend fun open(parent: CoroutineScope, destination: Int = port): EncryptedRecordTransport = DirectTCPConnector().connect(parent,
            InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127,0,0,1)), destination))
        fun proof(transcript: PairingTranscript): ByteArray = P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
            initSign(biometric.private); update(transcript.signingInput(PairingProofPurpose.PHONE_BIOMETRIC)); sign()
        })
        fun decisionProof(transcript: PairingTranscript, signer: KeyPair = decision): ByteArray =
            P256SignatureEncoding.fromDer(Signature.getInstance("SHA256withECDSA").run {
                initSign(signer.private)
                update(transcript.signingInput(PairingProofPurpose.PHONE_DECISION))
                sign()
            })

        override fun close() {
            runCatching { process.outputStream.write('q'.code); process.outputStream.flush(); process.outputStream.close() }
            val drained = process.waitFor(5, TimeUnit.SECONDS)
            if (!drained) { process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS) }
            directory.toFile().deleteRecursively()
            assertTrue(drained, "Native setup fixture did not drain its handlers")
            assertEquals(0, process.exitValue(), "Native setup fixture did not stop cleanly")
        }
    }
    private inline fun <T> withNativeExporter(body: (PairingV2TLSProvider) -> T): T {
        val provider = Conscrypt.newProvider()
        check(Security.insertProviderAt(provider, 1) == 1)
        try {
            val exporter = object : PairingV2TLSProvider {
                override fun configure(engine: SSLEngine) = Conscrypt.setUseSessionTickets(engine, false)
                override fun export(engine: SSLEngine): ByteArray? =
                    Conscrypt.exportKeyingMaterial(engine, PairingInvitationV2.EXPORTER_LABEL, ByteArray(0), 32)
            }
            return body(exporter)
        } finally {
            Security.removeProvider(provider.name)
        }
    }

    private enum class RootOutcome(val phase: Int, val committed: Int) {
        PROOF_REJECTED(1, 0),
        COMMIT_REJECTED(2, 0),
        RECEIPT(3, 1),
    }

    private fun assertRootOutcome(fixture: Fixture, outcome: RootOutcome, rePair: Boolean = false) {
        val report = fixture.readPeerLine()
        assertEquals(outcome.phase, report["phase"]?.jsonPrimitive?.int, report.toString())
        for (name in listOf("commits", "auditDelta", "active", "receiptSignatures", "receipts")) {
            assertEquals(outcome.committed, report.getValue(name).jsonPrimitive.int, name)
        }
        assertEquals(if (rePair) 1 else 0, report.getValue("predecessorRevoked").jsonPrimitive.int)
    }

    private suspend fun assertV2Pairing(scope: CoroutineScope, rePair: Boolean, decisionProof: Boolean) {
        Fixture(rePair = rePair, decisionProof = decisionProof, pairingV2 = true).use { fixture ->
            withNativeExporter { provider ->
                val invitation = checkNotNull(fixture.v2Invitation)
                assertEquals(rePair, invitation.replacement != null)
                val proposal = fixture.proposal(replacement = invitation.replacement)
                val channel = authenticatePairingV2Routes(scope, flowOf(ApprovalCarrierRoute { owner -> fixture.open(owner) }),
                    fixture.keys, invitation, proposal, 5_000, provider, offerDecisionProof = true)
                try {
                    assertEquals(decisionProof, channel.requiresDecisionProof)
                    val transcript = withTimeout(8_000) { channel.awaitTranscriptV2(invitation) }
                    assertEquals(invitation.replacement?.phoneID, transcript.replacement?.phoneID)
                    assertEquals(invitation.replacement?.epoch, transcript.replacement?.epoch)
                    val receipt = withTimeout(8_000) {
                        val biometric = fixture.proof(transcript)
                        if (decisionProof) {
                            channel.submitDualProof(transcript.digest(), biometric, fixture.decisionProof(transcript))
                        } else {
                            channel.submitProof(transcript.digest(), biometric)
                        }
                    }
                    assertTrue(transcript.verify(receipt, fixture.invitation.authorityPublicKey.copyBytes(), PairingProofPurpose.MAC_COMMIT))
                    assertRootOutcome(fixture, RootOutcome.RECEIPT, rePair)
                } finally {
                    channel.closeAndJoin()
                }
            }
        }
    }

    @Test fun decisionProofPairingCommitsAndReturnsAVerifiedReceipt(): Unit = runBlocking {
        assertV2Pairing(this, rePair = false, decisionProof = true)
    }

    @Test fun decisionProofRePairCommitsTheNewEpochAndKeepsThePredecessorRevoked(): Unit = runBlocking {
        assertV2Pairing(this, rePair = true, decisionProof = true)
    }

    @Test fun nativeV2SelectsBiometricProofWhenClientOffersBothProfiles(): Unit = runBlocking {
        assertV2Pairing(this, rePair = false, decisionProof = false)
    }

    private suspend fun readPairingFrame(session: TLSRecordSession, limit: Int): ByteArray {
        val bytes = ByteArrayOutputStream()
        while (true) {
            val chunk = session.receive() ?: throw IOException("Incomplete pairing frame")
            require(chunk.size <= limit + Int.SIZE_BYTES - bytes.size())
            bytes.write(chunk)
            if (bytes.size() < Int.SIZE_BYTES) continue
            val framed = bytes.toByteArray()
            val size = ByteBuffer.wrap(framed).int
            require(size in 1..limit && framed.size <= Int.SIZE_BYTES + size)
            if (framed.size == Int.SIZE_BYTES + size) return framed.copyOfRange(Int.SIZE_BYTES, framed.size)
        }
    }

    private suspend fun sendPairingFrame(session: TLSRecordSession, payload: ByteArray) {
        // Every fixture proposal and proof fits within one record-session chunk.
        session.send(ByteBuffer.allocate(Int.SIZE_BYTES + payload.size).putInt(payload.size).put(payload).array())
    }

    private enum class RejectedProof { MISSING, WRONG_KEY, LEGACY_COMMIT }

    private suspend fun assertDecisionProofRejection(scope: CoroutineScope, rejection: RejectedProof) {
        Fixture(decisionProof = true, legacyCommit = rejection == RejectedProof.LEGACY_COMMIT).use { fixture ->
            withNativeExporter { provider ->
                val invitation = requireNotNull(fixture.v2Invitation)
                val proposal = fixture.proposal()
                val engine = PinnedTLSClient.forPairingV2(fixture.keys, fixture.mac.certificate.publicKey.encoded,
                    provider, offerDecisionProof = true)
                val carrier = try { fixture.open(scope) } catch (failure: Throwable) { engine.close(); throw failure }
                val session = TLSRecordSession(scope, engine, carrier, handshakeTimeoutMillis = 5_000)
                try {
                    withTimeout(8_000) {
                        session.awaitOpen()
                        val challenge = assertIs<PairingSetupPreludeV2.Challenge>(PairingSetupPreludeV2.decode(
                            readPairingFrame(session, PairingSetupPreludeV2.MAXIMUM_BYTES)))
                        val exporter = engine.pairingExporter()
                        val tag = try { invitation.proof(proposal, challenge.value.copyBytes(), exporter) }
                            finally { exporter.fill(0) }
                        sendPairingFrame(session, PairingSetupPreludeV2.Proposal(proposal, tag).encode())
                        val transcript = assertIs<PairingSetupFrame.Transcript>(PairingSetupFrame.decode(
                            readPairingFrame(session, PairingSetupFrame.MAXIMUM_BYTES))).value
                        proposal.validate(transcript)
                        fixture.invitation.validateMacClaims(transcript)
                        val biometric = fixture.proof(transcript)
                        val id = transcript.setupID.copyBytes()
                        val digest = transcript.digest()
                        val invalid = when (rejection) {
                            RejectedProof.MISSING -> PairingSetupFrame.Proof(id, digest, biometric)
                            RejectedProof.WRONG_KEY -> PairingSetupFrame.DualProof(id, digest, biometric,
                                fixture.decisionProof(transcript, signer = fixture.biometric))
                            RejectedProof.LEGACY_COMMIT -> PairingSetupFrame.DualProof(id, digest, biometric,
                                fixture.decisionProof(transcript))
                        }
                        // Exercise the Swift boundary directly. The ordinary Kotlin API already blocks malformed proofs.
                        sendPairingFrame(session, invalid.encode())
                        try {
                            assertNull(session.receive(), "Rejected pairing emitted a receipt or other data")
                        } catch (_: IOException) {
                            // An abrupt TLS close also rejects the exchange. The Swift report below identifies the boundary.
                        }
                    }
                    assertRootOutcome(fixture, if (rejection == RejectedProof.LEGACY_COMMIT) RootOutcome.COMMIT_REJECTED
                        else RootOutcome.PROOF_REJECTED)
                } finally {
                    session.closeAndJoin()
                }
            }
        }
    }

    @Test fun missingDecisionProofLeavesNoCommitOrReceipt(): Unit = runBlocking {
        assertDecisionProofRejection(this, RejectedProof.MISSING)
    }

    @Test fun wrongDecisionSigningKeyLeavesNoCommitOrReceipt(): Unit = runBlocking {
        assertDecisionProofRejection(this, RejectedProof.WRONG_KEY)
    }

    @Test fun legacyRootCommitIsRefusedEvenAfterTheTransportVerifiedDualProof(): Unit = runBlocking {
        assertDecisionProofRejection(this, RejectedProof.LEGACY_COMMIT)
    }

    @Test fun unpairedTLSCandidateReceivesAndVerifiesTheExactSetupReceipt(): Unit = runBlocking {
        Fixture().use { f ->
            val owner = SupervisorJob(); val scope = CoroutineScope(owner)
            var channel: PairingSetupChannel? = null
            try {
                channel = withTimeout(15000) { PairingSetupChannel.connect(scope, f.open(scope), f.keys, f.invitation, f.proposal()) }
                val transcript = channel.transcript
                val receipt = withTimeout(5000) { channel.submitProof(transcript.digest(), f.proof(transcript)) }
                assertTrue(transcript.verify(receipt, f.invitation.authorityPublicKey.copyBytes(), PairingProofPurpose.MAC_COMMIT))
                assertFails { channel.submitProof(transcript.digest(), f.proof(transcript)) }
            } finally { channel?.closeAndJoin(); owner.cancelAndJoin() }
        }
    }
    // The synthetic peer checks the transmitted bytes and the client imports the invitation.
    @Test fun rePairClientImportsTheInvitationAndSendsTheSelectedPredecessorToTheSyntheticPeer(): Unit = runBlocking {
        Fixture(rePair = true).use { f ->
            val owner = SupervisorJob(); val scope = CoroutineScope(owner)
            var channel: PairingSetupChannel? = null
            try {
                val replacement = checkNotNull(f.rePairInvitation).predecessor
                val wrong = PairingReplacement(replacement.phoneID.copyBytes(), ByteArray(16) { 11 })
                for (proposal in listOf(f.proposal(), f.proposal(replacement = wrong))) {
                    rejectedWithin(10000) {
                        PairingSetupChannel.connect(scope, f.open(scope), f.keys, f.invitation, proposal).closeAndJoin()
                    }
                }
                channel = withTimeout(15000) {
                    PairingSetupChannel.connect(scope, f.open(scope), f.keys, f.invitation, f.proposal(replacement = replacement))
                }
                val transcript = channel.transcript
                assertEquals(replacement.phoneID, transcript.replacement?.phoneID)
                assertEquals(replacement.epoch, transcript.replacement?.epoch)
                val receipt = withTimeout(5000) { channel.submitProof(transcript.digest(), f.proof(transcript)) }
                assertTrue(transcript.verify(receipt, f.invitation.authorityPublicKey.copyBytes(), PairingProofPurpose.MAC_COMMIT))
            } finally { channel?.closeAndJoin(); owner.cancelAndJoin() }
        }
    }

    // Uses the archive and transport APIs with software keys. Android's setup owner is covered separately.
    @Test fun rePairRecoversTheLostReceiptOverTheNewKeyAfterArchiveReopen(): Unit = runBlocking {
        Fixture(rePair = true, dropRePairReceipt = true).use { f ->
            fun id(value: Int) = ByteArray(16) { value.toByte() }
            val invitation = checkNotNull(f.rePairInvitation)
            val proposal = f.proposal(replacement = invitation.predecessor)
            val cipher = EnrollmentCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey(), 65_536)
            val storage = object : EnrollmentStorage {
                var contents: ByteArray? = null
                override fun read(maximumBytes: Int) = contents?.copyOf()
                override fun replace(ciphertext: ByteArray) { contents = ciphertext.copyOf() }
                override fun close() = Unit
            }
            fun oldKey(role: EnrollmentKeyRole): EnrollmentKeyReference {
                val pair = key()
                return EnrollmentKeyReference(role, id(30 + role.ordinal),
                    "remozio.${role.aliasPart}.v1.${"%032x".format(30 + role.ordinal)}",
                    if (role == EnrollmentKeyRole.TRANSPORT) pair.public.encoded else point(pair))
            }
            val predecessor = PhoneEnrollment(id(40), f.invitation.macID.copyBytes(), f.invitation.accountID.copyBytes(),
                invitation.predecessor.phoneID.copyBytes(), invitation.predecessor.epoch.copyBytes(), f.invitation.label,
                f.invitation.authorityPublicKey.copyBytes(), f.mac.certificate.publicKey.encoded,
                oldKey(EnrollmentKeyRole.TRANSPORT), oldKey(EnrollmentKeyRole.DECISION), oldKey(EnrollmentKeyRole.BIOMETRIC),
                ByteArray(32) { 41 }, null)
            val reservation = RePairReservation(id(42), predecessor.recordID.copyBytes(), id(4), invitation,
                listOf(proposal.transportKey.keyID, proposal.decisionKey.keyID, proposal.biometricKey.keyID))
            val material = RePairProposalMaterial(proposal, listOf(f.phone.keyPair, f.decision, f.biometric).mapIndexed { i, key ->
                val role = EnrollmentKeyRole.entries[i]
                EnrollmentKeyReference(role, reservation.keyIDs[i].copyBytes(), reservation.alias(role),
                    if (role == EnrollmentKeyRole.TRANSPORT) key.public.encoded else point(key))
            })
            val owner = SupervisorJob()
            val scope = CoroutineScope(owner)
            try {
                EncryptedEnrollmentStore.create(storage, cipher, 10).use { archive ->
                    archive.prepare(predecessor, 0u)
                    archive.remove(predecessor.recordID.copyBytes(), 1u)
                    archive.reserveRePair(reservation, 2u)
                    val channel = withTimeout(15_000) {
                        PairingSetupChannel.authenticate(scope, f.open(scope), f.keys, f.invitation, proposal)
                    }
                    try {
                        val transcript = channel.awaitTranscript {
                            archive.prepareRePairProposal(reservation.recordID, material, 3u)
                        }
                        archive.checkpointRePair(reservation.recordID, transcript, 4u)
                        rejectedWithin(5_000) {
                            channel.submitProof(transcript.digest(), f.proof(transcript)) {
                                archive.markRePairProof(reservation.recordID, 5u)
                            }
                        }
                    } finally { channel.closeAndJoin() }
                }
                EncryptedEnrollmentStore.open(storage, cipher, 10).use { archive ->
                    val row = archive.snapshot().entries.single { it.enrollment.recordID == reservation.recordID }
                    assertTrue(checkNotNull(row.rePair).proofMayHaveBeenSent)
                    val exchange = checkNotNull(row.pairing).transcript
                    val connector = ApprovalChannelConnector(f.keys, row.enrollment.transportPublicKey.copyBytes(),
                        exchange.phone.scope, emptyList(), emptySet(), PairingReceiptFrame.MAXIMUM_BYTES,
                        purpose = EnrolledChannelPurpose.PAIRING_RECEIPT)
                    val channel = connector.connect(scope, flowOf(ApprovalCarrierRoute { f.open(it, checkNotNull(f.receiptPort)) }), null)
                    val receipt = PairingReceiptChannel.bind(row, channel)
                    val proof = try { checkNotNull(receipt.recover()) } finally { receipt.closeAndJoin() }
                    val activated = archive.recoverPairing(reservation.recordID.copyBytes()).activate(archive, proof)
                    assertEquals(reservation.recordID, activated.entries.first().successorRecordID)
                    assertEquals(listOf(EnrollmentPhase.REMOVED, EnrollmentPhase.ACTIVE), activated.entries.map { it.phase })
                    assertEquals(activated.revision, archive.recoverPairing(reservation.recordID.copyBytes()).activate(archive, proof).revision)
                }
            } finally { owner.cancelAndJoin() }
        }
    }

    @Test fun nativeSetupRejectsATransportClaimThatDiffersFromTheTLSClient(): Unit = runBlocking {
        Fixture().use { f ->
            val owner = SupervisorJob(); val scope = CoroutineScope(owner)
            try {
                rejectedWithin(10000) { PairingSetupChannel.connect(scope, f.open(scope), f.keys, f.invitation, f.proposal(transport = key())) }
            } finally { owner.cancelAndJoin() }
        }
    }
    @Test fun invitationPinAndAuthorityChangesFailBeforeABiometricProof(): Unit = runBlocking {
        Fixture().use { f ->
            for (changeAuthority in listOf(false, true)) {
                val other = point(key())
                val invitation = PairingInvitation(f.invitation.macID.copyBytes(), f.invitation.accountID.copyBytes(), "changed",
                    if (changeAuthority) other else f.invitation.authorityPublicKey.copyBytes(),
                    if (changeAuthority) f.invitation.transportPublicKey.copyBytes() else other, 1u)
                val owner = SupervisorJob(); val scope = CoroutineScope(owner)
                try { rejectedWithin(10000) { PairingSetupChannel.connect(scope, f.open(scope), f.keys, invitation, f.proposal(invitation)) } }
                finally { owner.cancelAndJoin() }
            }
        }
    }
    @Test fun idleNativeSetupReleasesDisconnectedCandidatesBeforeTheTimeout(): Unit = runBlocking {
        Fixture(holdPairingStage = true).use { f ->
            repeat(3) {
                val owner = SupervisorJob(); val scope = CoroutineScope(owner)
                var session: TLSRecordSession? = null
                try {
                    session = TLSRecordSession(scope, PinnedTLSClient(f.keys, f.mac.certificate.publicKey.encoded,
                        PairingSetupFrame.APPLICATION_PROTOCOL, 1_048_576), f.open(scope))
                    withTimeout(5000) {
                        session.awaitOpen()
                        val incoming = checkNotNull(session.receive())
                        assertTrue(incoming.size >= 4)
                        val length = incoming.take(4).fold(0) { n, b -> (n shl 8) or (b.toInt() and 255) }
                        val body = incoming.drop(4).toMutableList()
                        while (body.size < length) { body.addAll(checkNotNull(session.receive()).toList()) }
                        assertEquals(PairingSetupFrame.Hello, PairingSetupFrame.decode(body.toByteArray()))
                        val proposal = PairingSetupFrame.Proposal(f.proposal()).encode()
                        val size = proposal.size
                        session.send(byteArrayOf((size ushr 24).toByte(), (size ushr 16).toByte(), (size ushr 8).toByte(), size.toByte()) + proposal)
                        delay(200)
                    }
                } finally { session?.closeAndJoin(); owner.cancelAndJoin() }
                delay(300)
            }
        }
    }
    @Test fun approvalALPNCannotUseTheSetupListener(): Unit = runBlocking {
        Fixture().use { f ->
            val owner = SupervisorJob(); val scope = CoroutineScope(owner)
            var session: TLSRecordSession? = null
            try {
                session = TLSRecordSession(scope, PinnedTLSClient(f.keys, f.mac.certificate.publicKey.encoded, "remozio/1", 1_048_576), f.open(scope))
                rejectedWithin(5000) { session.awaitOpen(); session.receive() }
            } finally { session?.closeAndJoin(); owner.cancelAndJoin() }
        }
    }
    @Test fun v2WaitsForTheTranscriptAfterTheRouteSelectionBudgetElapses(): Unit = runBlocking {
        val phone = HeldCertificate.Builder().ecdsa256().commonName("v2-fixture-phone").build()
        val mac = HeldCertificate.Builder().ecdsa256().commonName("v2-fixture-mac").build()
        val server = HandshakeCertificates.Builder().heldCertificate(mac).addTrustedCertificate(phone.certificate).build()
        val keys = arrayOf<KeyManager>(HandshakeCertificates.Builder().heldCertificate(phone).build().keyManager)
        val scope = ChannelScope(ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 })
        val authority = point(key())
        val pin = point(mac.keyPair)
        val invitation = PairingInvitation(ByteArray(16) { 1 }, ByteArray(16) { 2 }, "Fixture", authority, pin, 1u)
        val credentials = PairingInvitationV2(invitation, ByteArray(16) { 5 }, ByteArray(32) { 6 },
            lifetimeMilliseconds = 60_000u)
        val offer = ChannelOffer(ChannelRole.PHONE, scope, ByteArray(32) { 7 }, setOf(1u), emptyList(), emptySet())
        val proposal = PairingPhoneProposal(offer, PairingKey(ByteArray(16) { 8 }, point(phone.keyPair)),
            PairingKey(ByteArray(16) { 9 }, point(key())), PairingKey(ByteArray(16) { 10 }, point(key())))
        val transcript = PairingTranscript(ByteArray(16) { 11 }, ByteArray(32) { 12 }, offer,
            ChannelOffer(ChannelRole.MAC, scope, ByteArray(32) { 13 }, setOf(1u), emptyList(), emptySet()), 1u, 1u,
            authority, pin, proposal.transportKey, proposal.decisionKey, proposal.biometricKey,
            ByteArray(32) { 14 }, null, ByteArray(16) { 15 }, 1000u, 2000u)
        val routeBudgetMillis = 2_000L
        val challenge = ByteArray(32) { 16 }
        // The Android device test checks the platform exporter. This peer isolates the route/session deadline.
        val exporter = ByteArray(32) { 17 }
        val provider = object : PairingV2TLSProvider {
            override fun configure(engine: SSLEngine) = Unit
            override fun export(engine: SSLEngine) = exporter.copyOf()
        }
        val address = InetAddress.getByName("127.0.0.1")
        (server.sslContext().serverSocketFactory.createServerSocket(0, 1, address) as SSLServerSocket).use { listener ->
            listener.soTimeout = 8_000
            listener.needClientAuth = true
            listener.enabledProtocols = arrayOf("TLSv1.3")
            listener.sslParameters = listener.sslParameters.apply {
                applicationProtocols = arrayOf(PairingSetupPreludeV2.APPLICATION_PROTOCOL)
            }
            val peer = async(Dispatchers.IO) {
                (listener.accept() as SSLSocket).use { socket ->
                    socket.soTimeout = 8_000
                    socket.startHandshake()
                    assertEquals(PairingSetupPreludeV2.APPLICATION_PROTOCOL, socket.applicationProtocol)
                    val output = DataOutputStream(socket.outputStream)
                    fun send(body: ByteArray) { output.writeInt(body.size); output.write(body); output.flush() }
                    send(PairingSetupPreludeV2.Challenge(challenge).encode())
                    val input = DataInputStream(socket.inputStream)
                    val size = input.readInt()
                    require(size in 1..PairingSetupPreludeV2.MAXIMUM_BYTES)
                    val proof = assertIs<PairingSetupPreludeV2.Proposal>(
                        PairingSetupPreludeV2.decode(ByteArray(size).also(input::readFully)))
                    assertEquals(CborValue.Bytes(credentials.proof(proposal, challenge, exporter)), proof.tag)
                    delay(routeBudgetMillis + 250)
                    send(PairingSetupFrame.Transcript(transcript).encode())
                }
            }
            val channel = authenticatePairingV2Routes(this, flowOf(ApprovalCarrierRoute { owner ->
                DirectTCPConnector().connect(owner, InetSocketAddress(address, listener.localPort))
            }), keys, credentials, proposal, routeBudgetMillis, provider)
            try {
                val actual = withTimeout(8_000) { channel.awaitTranscriptV2(credentials) }
                assertContentEquals(transcript.encode(), actual.encode())
                peer.await()
            } finally {
                channel.closeAndJoin()
            }
        }
    }

}
