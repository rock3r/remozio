package dev.remozio.phone.requests

import dev.remozio.protocol.*
import java.util.Collections
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

/** In-memory ownership errors. These are not remote request outcomes. */
enum class InboxRejection { CLOSED, ALREADY_ENROLLED, STALE_ENROLLMENT, CAPACITY, CONFLICTING_REQUEST, UNKNOWN_REQUEST }
class InboxException(val reason: InboxRejection) : IllegalStateException(reason.name)

/**
 * Local trusted code installs enrollment handles. Request delivery cannot create or replace enrollment.
 * Limits bound this in-memory window; no entry is silently evicted. This is not durable replay protection.
 */
class CommandRequestInbox(private val maximumEnrollments: Int, private val maximumRequestsPerEnrollment: Int) : AutoCloseable {
    private data class Scope(val mac: CborValue.Bytes, val account: CborValue.Bytes)
    private val enrollments = linkedMapOf<Scope, CommandRequestEnrollment>()
    private var closed = false

    init { require(maximumEnrollments > 0 && maximumRequestsPerEnrollment > 0) }

    /** IDs/key must come from completed trusted enrollment, never an incoming request or peer advertisement. */
    @Synchronized
    fun add(macID: ByteArray, accountID: ByteArray, authorityKey: ByteArray, limits: RequestLimits): CommandRequestEnrollment {
        checkOpen()
        val scope = scope(macID, accountID)
        if (scope in enrollments) reject(InboxRejection.ALREADY_ENROLLED)
        if (enrollments.size >= maximumEnrollments) reject(InboxRejection.CAPACITY)
        val enrollment = CommandRequestEnrollment(macID, accountID, authorityKey, limits, maximumRequestsPerEnrollment)
        enrollments[scope] = enrollment
        return enrollment
    }

    /** Explicit replacement after independently authorized trust changes; old network callbacks keep a closed handle. */
    @Synchronized
    fun replace(old: CommandRequestEnrollment, authorityKey: ByteArray, limits: RequestLimits): CommandRequestEnrollment {
        checkOpen()
        val scope = Scope(old.macID, old.accountID)
        if (enrollments[scope] !== old) reject(InboxRejection.STALE_ENROLLMENT)
        val replacement = CommandRequestEnrollment(old.macID.copyBytes(), old.accountID.copyBytes(),
            authorityKey, limits, maximumRequestsPerEnrollment)
        old.close()
        enrollments[scope] = replacement
        return replacement
    }

    /** A stale handle cannot remove a replacement enrollment. Other scopes remain untouched. */
    @Synchronized
    fun remove(enrollment: CommandRequestEnrollment): Boolean {
        val scope = Scope(enrollment.macID, enrollment.accountID)
        if (enrollments[scope] !== enrollment) return false
        enrollment.close()
        enrollments.remove(scope)
        return true
    }

    @Synchronized
    override fun close() {
        closed = true
        enrollments.values.forEach { it.close() }
        enrollments.clear()
    }

    private fun checkOpen() { if (closed) reject(InboxRejection.CLOSED) }
    private fun scope(macID: ByteArray, accountID: ByteArray): Scope {
        require(macID.size == 16 && accountID.size == 16)
        return Scope(CborValue.Bytes(macID), CborValue.Bytes(accountID))
    }
}

/** Holds requests for one trusted Mac/account incarnation. A replaced handle can never reopen. */
class CommandRequestEnrollment internal constructor(
    macID: ByteArray, accountID: ByteArray, authorityKey: ByteArray,
    internal val limits: RequestLimits, private val maximumRequests: Int,
) : AutoCloseable {
    val macID = CborValue.Bytes(macID)
    val accountID = CborValue.Bytes(accountID)
    private val authorityKey = authorityKey.copyOf()
    private val requests = linkedMapOf<CommandRequestIdentity, CommandRequestSession>()
    private var receiver: AutoCloseable? = null
    private val publishedSessions = MutableStateFlow<List<CommandRequestSession>>(emptyList())
    val requestSessions = publishedSessions.asStateFlow()
    private var closed = false

    init { require(authorityKey.size == 65 && authorityKey[0] == 4.toByte()) }

    /** Even duplicates authenticate first. Reuse the existing owner instead of resetting its status or timing. */
    @Synchronized
    fun accept(body: ByteArray, signature: ByteArray): CommandRequestSession {
        if (closed) reject(InboxRejection.CLOSED)
        val candidate = CommandRequestSession.open(body, signature, macID.copyBytes(), accountID.copyBytes(), authorityKey, limits)
        val existing = requests[candidate.identity]
        if (existing != null) {
            candidate.close()
            if (existing.requestDigest != candidate.requestDigest) reject(InboxRejection.CONFLICTING_REQUEST)
            return existing
        }
        if (requests.size >= maximumRequests) {
            candidate.close()
            reject(InboxRejection.CAPACITY)
        }
        requests[candidate.identity] = candidate
        publishedSessions.value = Collections.unmodifiableList(requests.values.toList())
        return candidate
    }

    /** Local ownership handoff only. Reconnect keeps the existing request window. */
    @Synchronized
    internal fun attach(owner: AutoCloseable) {
        if (closed) reject(InboxRejection.CLOSED)
        val previous = receiver
        receiver = owner
        previous?.close()
    }

    @Synchronized
    internal fun detach(owner: AutoCloseable) { if (receiver === owner) receiver = null }

    /** The identity check and state update share the enrollment monitor with replacement and removal. */
    @Synchronized
    internal fun deliver(owner: AutoCloseable, message: ApprovalMessage, receivedAt: ElapsedInstant) {
        if (closed || receiver !== owner) reject(InboxRejection.STALE_ENROLLMENT)
        val body = message.body.copyBytes()
        val signature = message.signature.copyBytes()
        when (message.type) {
            ApprovalMessageType.REQUEST -> accept(body, signature)
            ApprovalMessageType.STATUS -> {
                val claim = RequestStatusPayload.decode(body, limits.status)
                val key = CommandRequestIdentity(CborValue.Bytes(claim.macID), CborValue.Bytes(claim.accountID),
                    CborValue.Bytes(claim.requestID))
                val session = requests[key] ?: reject(InboxRejection.UNKNOWN_REQUEST)
                session.observe(body, signature, receivedAt)
            }
            ApprovalMessageType.DECISION -> throw IllegalArgumentException("Unexpected inbound decision")
        }
    }

    /** Snapshot of owned handles, including terminal tombstones. Capture contents remain owned by each session. */
    @Synchronized
    fun sessions(): List<CommandRequestSession> = requests.values.toList()

    @Synchronized
    override fun close() {
        closed = true
        receiver?.close()
        receiver = null
        requests.values.forEach { it.close() }
        requests.clear()
        publishedSessions.value = emptyList()
    }
}

private fun reject(reason: InboxRejection): Nothing = throw InboxException(reason)
