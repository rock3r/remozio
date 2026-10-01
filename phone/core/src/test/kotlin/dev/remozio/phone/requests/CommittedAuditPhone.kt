package dev.remozio.phone.requests

import dev.remozio.phone.audit.*
import dev.remozio.protocol.*
import java.io.Closeable
import javax.crypto.KeyGenerator
import kotlinx.serialization.json.*
import kotlin.test.*

/** Disposable encrypted storage and pinned trust for the journal-backed native test peer. */
internal class CommittedAuditDisk {
    val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    var ciphertext: ByteArray? = null
}

internal class CommittedAuditPhone(authorityKey: ByteArray, disk: CommittedAuditDisk) : Closeable {
    private val bound = CborLimits(32768, 32, 4096)
    val binding = AuditCacheBinding(ByteArray(16) { 1 }, ByteArray(16) { 2 }, authorityKey)
    private var now = 100uL
    private val cache = EncryptedAuditCache.open(object : AuditCiphertextStorage {
        private var closed = false
        override fun read(maximumBytes: Int): ByteArray? {
            check(!closed)
            return disk.ciphertext?.copyOf()?.also { check(it.size <= maximumBytes) }
        }
        override fun replace(ciphertext: ByteArray) { check(!closed); disk.ciphertext = ciphertext.copyOf() }
        override fun close() { closed = true }
    }, AuditArchiveCipher(disk.key, bound.maxBytes), binding,
        AuditPageLimits(bound, bound, bound, 2, bound, bound), AuditEvidenceLimits(100, 1000000, 100, 20), bound)
    val session = AuditSyncSession(cache, 1, 1000u) { ElapsedInstant(1, now) }

    fun sync(exchange: (Map<String, String>) -> JsonObject) {
        session.start()
        repeat(32) {
            when (session.state.value.phase) {
                AuditSyncPhase.PAUSED -> session.resume()
                AuditSyncPhase.COMPLETE -> return
                AuditSyncPhase.SYNCING -> {
                    val query = assertNotNull(session.next())
                    val fields = mutableMapOf("nonce" to query.queryNonce.hex())
                    when (query) {
                        is AuditHistoryQuery -> {
                            fields["command"] = "auditHistory"
                            query.requestedEpoch?.let { fields["epoch"] = it.hex(); fields["after"] = checkNotNull(query.requestedAfter).toString() }
                        }
                        is AuditPageQuery -> {
                            fields["command"] = "auditPage"; fields["epoch"] = query.journalEpoch.hex()
                            fields["generation"] = query.epochCreationGeneration.toString(); fields["after"] = query.requestedAfter.toString()
                        }
                    }
                    val reply = exchange(fields)
                    assertEquals("1", reply.getValue("wireVersion").jsonPrimitive.content)
                    assertEquals(if (query is AuditHistoryQuery) "history" else "page", reply.getValue("kind").jsonPrimitive.content)
                    now++
                    session.accept(query, reply.bytes("body"), reply.bytes("signature"))
                }
                else -> error("Unexpected committed audit sync state")
            }
        }
        error("Committed audit sync exceeded its response budget")
    }

    override fun close() { session.close() }
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
    private fun JsonObject.bytes(key: String) = getValue(key).jsonPrimitive.content.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
