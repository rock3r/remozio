package dev.remozio.phone.audit

import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.*
import java.io.Closeable
import java.io.EOFException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlinx.serialization.json.*
import kotlin.test.*

/** Real native/JVM exchange with disposable trust and storage. No device, production channel or journal. */
class AuditFlowTest {
    private val bound = CborLimits(32768, 8, 2048)
    private val limits = AuditPageLimits(bound, bound, bound, 2, bound, bound)
    private val capacity = AuditEvidenceLimits(100, 1000000, 100, 20)
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun epoch(n: Int) = CborValue.Bytes(id(n))

    @Test fun nativePagesPersistAndReloadWithoutInventingFreshness(): Unit = Peer().use { peer ->
        val disk = Disk(); val key = aesKey()
        Phone(peer.publicKey, disk, key, budget = 2).use { phone ->
            assertEquals(1, phone.round(peer))
            val state = phone.session.state.value
            assertEquals(AuditSyncPhase.COMPLETE, state.phase)
            assertEquals(listOf(1uL, 2uL, 3uL, 4uL), state.history.epochs.single().records.map { it.sequence })
            assertTrue(state.history.epochs.single().gaps.isEmpty())
            assertEquals(AuditOutcome.UNRESOLVED, state.history.epochs.single().records.last().outcome)
            assertEquals(AuditEventKind.UNKNOWN_OUTCOME, state.history.epochs.single().records.last().kind)
            assertNotNull(state.lastCompletedAt)
            val ciphertext = assertNotNull(disk.bytes)
            val plaintext = AuditArchiveCipher(key, bound.maxBytes).decrypt(ciphertext, phone.binding)
            assertFalse(ciphertext.contentEquals(plaintext))
            assertEquals(3, state.history.proofs.size)
        }
        Phone(peer.publicKey, disk, key).use { restored ->
            val state = restored.session.state.value
            assertEquals(AuditSyncPhase.IDLE, state.phase)
            assertEquals(4, state.history.epochs.single().records.size)
            assertNull(state.lastCompletedAt); assertNull(state.currentObservation)
            assertEquals(listOf(1uL, 2uL, 3uL, 4uL), AuditHistory.timeline(state.history, id(8))
                .chains.single().epochs.single().records.map { it.sequence })
            assertEquals(0, restored.round(peer))
            assertNotNull(restored.session.state.value.lastCompletedAt)
        }
    }

    @Test fun nativeRestoreAndHistoryLossPreserveThePhonesOlderEvidence() = Peer().use { peer ->
        Phone(peer.publicKey).use { phone ->
            phone.round(peer)
            peer.control("restore", "restored")
            phone.round(peer)
            var history = phone.session.state.value.history
            assertEquals(4, history.epochs.single { it.epoch == epoch(3) }.records.size)
            assertEquals(2, history.epochs.single { it.epoch == epoch(4) }.records.size)
            assertEquals(AuditEpochCause.RESTORATION, history.epochs.single { it.epoch == epoch(4) }.descriptor?.cause)
            assertTrue(history.proofs.any { it.historyStatus?.disposition == AuditHistoryDisposition.CURSOR_AHEAD })
            assertTrue(history.proofs.all { it.conflicts.isEmpty() })
            assertEquals(listOf(epoch(4), epoch(3)), AuditHistory.list(listOf(history)).single().chains.single().epochs.map { it.epoch })
            peer.control("forgetOld", "forgotOld")
            phone.round(peer); history = phone.session.state.value.history
            assertEquals(4, history.epochs.single { it.epoch == epoch(3) }.records.size)
            assertTrue(history.proofs.any { it.historyStatus?.disposition == AuditHistoryDisposition.UNAVAILABLE })
            assertEquals(AuditSyncPhase.COMPLETE, phone.session.state.value.phase)
        }
    }

    @Test fun fullyPrunedNativeEpochProducesAnExplicitGap() = Peer().use { peer ->
        peer.control("pruneCurrent", "pruned")
        Phone(peer.publicKey).use { phone ->
            phone.round(peer)
            val history = phone.session.state.value.history.epochs.single()
            assertTrue(history.records.isEmpty())
            assertEquals(listOf(AuditHistoryGap(0u, 4u, true)), history.gaps)
            assertEquals(AuditSyncPhase.COMPLETE, phone.session.state.value.phase)
        }
    }

    @Test fun signedRepliesStillNeedThePinnedKeyNonceAndLiveQuery() = Peer().use { peer ->
        Phone(peer.publicKey).use { phone ->
            phone.session.start(); val cancelled = assertNotNull(phone.session.next())
            val late = peer.reply(cancelled); phone.session.cancel()
            phone.session.start(); val fresh = assertNotNull(phone.session.next())
            assertFailsWith<IllegalStateException> { phone.accept(cancelled, late) }
            assertEquals(AuditPageRejection.WRONG_QUERY, assertFailsWith<AuditPageException> { phone.accept(fresh, late) }.reason)
            assertTrue(phone.session.state.value.history.proofs.isEmpty())
            phone.session.start(); val tamperedQuery = assertNotNull(phone.session.next())
            val frame = peer.reply(tamperedQuery)
            val signature = frame.bytes("signature").apply { this[0] = (this[0].toInt() xor 1).toByte() }
            assertEquals(AuditPageRejection.INVALID_SIGNATURE, assertFailsWith<AuditPageException> {
                phone.session.accept(tamperedQuery, frame.bytes("body"), signature)
            }.reason)
            Peer().use { foreign ->
                phone.session.start(); val wrongKey = assertNotNull(phone.session.next())
                assertEquals(AuditPageRejection.INVALID_SIGNATURE, assertFailsWith<AuditPageException> {
                    phone.accept(wrongKey, foreign.reply(wrongKey))
                }.reason)
            }
            assertNull(phone.session.state.value.lastCompletedAt)
            assertTrue(phone.session.state.value.history.proofs.isEmpty())
            phone.round(peer)
            assertEquals(AuditSyncPhase.COMPLETE, phone.session.state.value.phase)
        }
    }

    private class Disk { var bytes: ByteArray? = null }
    private class Storage(private val disk: Disk) : AuditCiphertextStorage {
        private var closed = false
        override fun read(maximumBytes: Int): ByteArray? {
            check(!closed)
            return disk.bytes?.copyOf()?.also { check(it.size <= maximumBytes) }
        }
        override fun replace(ciphertext: ByteArray) { check(!closed); disk.bytes = ciphertext.copyOf() }
        override fun close() { closed = true }
    }
    private fun aesKey() = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private inner class Phone(publicKey: ByteArray, disk: Disk = Disk(), key: SecretKey = aesKey(), budget: Int = 20) : Closeable {
        val binding = AuditCacheBinding(id(1), id(2), publicKey)
        private var now = 100uL
        private val cache = EncryptedAuditCache.open(Storage(disk), AuditArchiveCipher(key, bound.maxBytes), binding, limits, capacity, bound)
        val session = AuditSyncSession(cache, budget, 1000u) { ElapsedInstant(1, now) }
        fun accept(query: AuditQuery, reply: JsonObject) {
            assertEquals("1", reply.text("wireVersion"))
            assertEquals(if (query is AuditHistoryQuery) "history" else "page", reply.text("kind"))
            now++
            session.accept(query, reply.bytes("body"), reply.bytes("signature"))
        }
        fun round(peer: Peer): Int {
            session.start()
            var pauses = 0
            repeat(32) {
                when (session.state.value.phase) {
                    AuditSyncPhase.PAUSED -> { pauses++; session.resume() }
                    AuditSyncPhase.SYNCING -> {
                        val query = assertNotNull(session.next())
                        accept(query, peer.reply(query))
                    }
                    AuditSyncPhase.COMPLETE -> return pauses
                    else -> error("Unexpected audit sync phase")
                }
            }
            error("Audit round exceeded test response budget")
        }
        override fun close() { session.close() }
    }

    private inner class Peer : Closeable {
        private val process = ProcessBuilder(checkNotNull(System.getProperty("remozio.test.auditPeer")))
            .redirectErrorStream(true).start()
        private val input = process.outputStream.bufferedWriter()
        private val output = process.inputStream.bufferedReader()
        private val reader = Executors.newSingleThreadExecutor()
        // The test controller provisions trust through this local child-process pipe, never a network message.
        val publicKey: ByteArray
        init {
            try { publicKey = receive().bytes("authorityKey").also { check(it.size == 65 && it[0] == 4.toByte()) } }
            catch (failure: Throwable) {
                try { cleanup() } catch (cleanupFailure: Throwable) { failure.addSuppressed(cleanupFailure) }
                throw failure
            }
        }
        fun reply(query: AuditQuery): JsonObject {
            val fields = mutableMapOf("nonce" to query.queryNonce.hex())
            when (query) {
                is AuditHistoryQuery -> {
                    fields["command"] = "history"
                    query.requestedEpoch?.let { fields["epoch"] = it.hex(); fields["after"] = checkNotNull(query.requestedAfter).toString() }
                }
                is AuditPageQuery -> {
                    fields["command"] = "page"; fields["epoch"] = query.journalEpoch.hex()
                    fields["generation"] = query.epochCreationGeneration.toString(); fields["after"] = query.requestedAfter.toString()
                }
            }
            send(fields)
            return receive()
        }
        fun control(command: String, acknowledgement: String) {
            send(mapOf("command" to command)); assertEquals(acknowledgement, receive().text("control"))
        }
        private fun send(fields: Map<String, String>) {
            input.write(buildJsonObject { fields.forEach { (key, value) -> put(key, value) } }.toString())
            input.newLine(); input.flush()
        }
        private fun readFrame(): String {
            val result = StringBuilder()
            while (true) {
                val char = output.read()
                if (char < 0) throw EOFException("Synthetic audit peer closed its output")
                if (char == 10) return result.toString()
                check(result.length < 140_000) { "Synthetic audit response exceeded its bound" }
                result.append(char.toChar())
            }
        }
        private fun receive(): JsonObject {
            val line = try { reader.submit<String> { readFrame() }.get(10, TimeUnit.SECONDS) }
                catch (failure: Throwable) { process.destroyForcibly(); throw failure }
            return Json.parseToJsonElement(line).jsonObject
        }
        private fun cleanup() {
            try { process.destroyForcibly().waitFor(3, TimeUnit.SECONDS) }
            finally {
                reader.shutdownNow()
                try { output.close() } finally { input.close() }
            }
        }
        override fun close() {
            var code: Int? = null
            try {
                input.close()
                if (process.waitFor(3, TimeUnit.SECONDS)) code = process.exitValue()
            } finally { cleanup() }
            check(code == 0) { "Synthetic audit peer did not exit cleanly" }
        }
    }
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    private fun JsonObject.bytes(key: String) = text(key).also { check(it.length % 2 == 0) }
        .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
