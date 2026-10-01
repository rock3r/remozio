package dev.remozio.phone.audit

import dev.remozio.phone.requests.ElapsedInstant
import dev.remozio.protocol.*
import java.security.SecureRandom

class AuditPageLimits(val batch: CborLimits, val record: CborLimits, val signing: CborLimits, val maximumRecords: Int,
                      val history: CborLimits, val descriptor: CborLimits) {
    init { require(maximumRecords > 0) }
}

enum class AuditPageRejection { CLOSED, CAPACITY, INACTIVE_QUERY, EXPIRED_QUERY, INVALID_SIGNATURE, WRONG_QUERY }
class AuditPageException(val reason: AuditPageRejection) : IllegalArgumentException(reason.name)

/** An opaque, one-use handle owned by one receiver. */
sealed class AuditQuery protected constructor(private val owner: AuditPageReceiver, private val nonce: CborValue.Bytes) : AutoCloseable {
    val queryNonce: ByteArray get() = nonce.copyBytes()
    final override fun close() { owner.cancel(this) }
}

/** The epoch and generation must come from authenticated history state, not from an incoming page. */
class AuditPageQuery internal constructor(
    owner: AuditPageReceiver,
    private val epoch: CborValue.Bytes,
    val epochCreationGeneration: ULong,
    val requestedAfter: ULong,
    nonce: CborValue.Bytes,
) : AuditQuery(owner, nonce) {
    val journalEpoch: ByteArray get() = epoch.copyBytes()
}

/** Null epoch and cursor ask for discovery. Otherwise both identify retained phone history. */
class AuditHistoryQuery internal constructor(
    owner: AuditPageReceiver,
    private val epoch: CborValue.Bytes?,
    val requestedAfter: ULong?,
    nonce: CborValue.Bytes,
) : AuditQuery(owner, nonce) {
    val requestedEpoch: ByteArray? get() = epoch?.copyBytes()
}

/** Authenticated status evidence. It does not replace or reconcile cached records by itself. */
class ReceivedAuditHistory internal constructor(
    val status: AuditHistoryStatus, canonical: ByteArray, signature: ByteArray, val receivedAt: ElapsedInstant,
) {
    private val body = CborValue.Bytes(canonical)
    private val signed = CborValue.Bytes(signature)
    val canonicalBody: ByteArray get() = body.copyBytes()
    val signature: ByteArray get() = signed.copyBytes()
}

/** Evidence for a matched query. The cache must still check overlap, epoch continuity and retained boundaries. */
class ReceivedAuditPage internal constructor(
    val batch: AuditBatch,
    canonical: ByteArray,
    signature: ByteArray,
    val receivedAt: ElapsedInstant,
) {
    private val body = CborValue.Bytes(canonical)
    private val signed = CborValue.Bytes(signature)
    val canonicalBody: ByteArray get() = body.copyBytes()
    val signature: ByteArray get() = signed.copyBytes()
}

/**
 * Owns bounded, one-use queries for one trusted Mac/account. Close on enrollment revocation or key change.
 * This receiver does not establish an authenticated channel, persist history or authorize any action.
 */
class AuditPageReceiver(
    expectedMacID: ByteArray,
    expectedAccountID: ByteArray,
    trustedAuthorityPublicKey: ByteArray,
    private val limits: AuditPageLimits,
    private val maximumPendingQueries: Int,
    private val queryLifetimeMs: ULong,
    private val clock: () -> ElapsedInstant,
) : AutoCloseable {
    init {
        require(expectedMacID.size == 16 && expectedAccountID.size == 16)
        require(trustedAuthorityPublicKey.size == 65 && trustedAuthorityPublicKey[0] == 4.toByte())
        require(maximumPendingQueries > 0 && queryLifetimeMs > 0uL)
    }
    private val macID = CborValue.Bytes(expectedMacID)
    private val accountID = CborValue.Bytes(expectedAccountID)
    private val key = trustedAuthorityPublicKey.copyOf()
    private val random = SecureRandom()
    private class Pending(val startedAt: ElapsedInstant, var lastObserved: ULong)
    private val pending = LinkedHashMap<AuditQuery, Pending>()
    private var closed = false

    /** Uses a fresh nonce. The clock must include sleep and change epoch whenever its origin changes. */
    @Synchronized
    fun begin(journalEpoch: ByteArray, epochCreationGeneration: ULong, requestedAfter: ULong): AuditPageQuery {
        ensureOpen()
        require(journalEpoch.size == 16)
        return beginQuery { AuditPageQuery(this, CborValue.Bytes(journalEpoch), epochCreationGeneration, requestedAfter, it) }
    }

    @Synchronized
    fun beginHistory(requestedEpoch: ByteArray?, requestedAfter: ULong?): AuditHistoryQuery {
        ensureOpen()
        require((requestedEpoch == null) == (requestedAfter == null))
        require(requestedEpoch == null || requestedEpoch.size == 16)
        val epoch = requestedEpoch?.let(CborValue::Bytes)
        return beginQuery { AuditHistoryQuery(this, epoch, requestedAfter, it) }
    }

    private fun <T : AuditQuery> beginQuery(create: (CborValue.Bytes) -> T): T {
        val now = clock()
        pending.entries.removeIf { !live(it.value, now) }
        if (pending.size >= maximumPendingQueries) reject(AuditPageRejection.CAPACITY)
        val nonce = ByteArray(32).also(random::nextBytes)
        val query = create(CborValue.Bytes(nonce))
        pending[query] = Pending(now, now.milliseconds)
        return query
    }

    /** A rejected signature or binding cannot consume a still-live query. Successful receipt consumes it once. */
    @Synchronized
    fun receive(query: AuditPageQuery, canonicalBody: ByteArray, signature: ByteArray): ReceivedAuditPage {
        ensureOpen()
        val state = pending[query] ?: reject(AuditPageRejection.INACTIVE_QUERY)
        requireLive(query, state)
        if (canonicalBody.size > limits.batch.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
        if (signature.size != 64) reject(AuditPageRejection.INVALID_SIGNATURE)
        val bytes = canonicalBody.copyOf()
        val signed = signature.copyOf()
        if (!AuditBatchSignature.verify(signed, key, 1u, bytes, limits.batch, limits.signing)) {
            reject(AuditPageRejection.INVALID_SIGNATURE)
        }
        val batch = AuditBatch.decode(bytes, limits.batch, limits.record, limits.maximumRecords)
        if (CborValue.Bytes(batch.macID) != macID || CborValue.Bytes(batch.accountID) != accountID ||
            !batch.journalEpoch.contentEquals(query.journalEpoch) || batch.epochCreationGeneration != query.epochCreationGeneration ||
            batch.requestedAfter != query.requestedAfter || !batch.queryNonce.contentEquals(query.queryNonce)) {
            reject(AuditPageRejection.WRONG_QUERY)
        }
        val receivedAt = requireLive(query, state)
        pending.remove(query)
        return ReceivedAuditPage(batch, bytes, signed, receivedAt)
    }

    /** Discovery and old-cursor responses use their own signing purpose and the same one-use query budget. */
    @Synchronized
    fun receiveHistory(query: AuditHistoryQuery, canonicalBody: ByteArray, signature: ByteArray): ReceivedAuditHistory {
        ensureOpen()
        val state = pending[query] ?: reject(AuditPageRejection.INACTIVE_QUERY)
        requireLive(query, state)
        if (canonicalBody.size > limits.history.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
        if (signature.size != 64) reject(AuditPageRejection.INVALID_SIGNATURE)
        val bytes = canonicalBody.copyOf()
        val signed = signature.copyOf()
        if (!AuditHistoryStatusSignature.verify(signed, key, 1u, bytes, limits.history, limits.signing)) {
            reject(AuditPageRejection.INVALID_SIGNATURE)
        }
        val status = AuditHistoryStatus.decode(bytes, limits.history, limits.descriptor)
        if (CborValue.Bytes(status.macID) != macID || CborValue.Bytes(status.accountID) != accountID ||
            !status.requestedEpoch.contentEquals(query.requestedEpoch) || status.requestedAfter != query.requestedAfter ||
            !status.queryNonce.contentEquals(query.queryNonce)) reject(AuditPageRejection.WRONG_QUERY)
        val receivedAt = requireLive(query, state)
        pending.remove(query)
        return ReceivedAuditHistory(status, bytes, signed, receivedAt)
    }

    @Synchronized
    internal fun cancel(query: AuditQuery) { pending.remove(query) }

    @Synchronized
    override fun close() {
        closed = true
        pending.clear()
    }

    private fun requireLive(query: AuditQuery, state: Pending): ElapsedInstant {
        val now = clock()
        if (!live(state, now)) {
            pending.remove(query)
            reject(AuditPageRejection.EXPIRED_QUERY)
        }
        return now
    }

    private fun live(state: Pending, now: ElapsedInstant): Boolean {
        if (now.epoch != state.startedAt.epoch || now.milliseconds < state.lastObserved ||
            now.milliseconds - state.startedAt.milliseconds >= queryLifetimeMs) return false
        state.lastObserved = now.milliseconds
        return true
    }
    private fun ensureOpen() { if (closed) reject(AuditPageRejection.CLOSED) }
    private fun reject(reason: AuditPageRejection): Nothing = throw AuditPageException(reason)
}
