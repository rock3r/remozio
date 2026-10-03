package dev.remozio.android.requests

import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.phone.requests.*
import dev.remozio.protocol.*
import java.io.IOException
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal enum class CommandConnectionState { DISCONNECTED, CONNECTING, CONNECTED, CLOSED }

internal interface CommandConnectionWire : AutoCloseable {
    suspend fun receive()
    suspend fun send(bytes: ByteArray)
}

/** One trusted enrollment incarnation. The setup owner must close it before changing or removing trust. */
internal class CommandConnection(
    val record: StoredPhoneEnrollment,
    val limits: RequestLimits,
    private val open: suspend (CoroutineScope, CommandRequestEnrollment) -> CommandConnectionWire,
    private val clock: () -> ElapsedInstant,
    maximumRequests: Int = 128,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) : AutoCloseable {
    private val inbox = CommandRequestInbox(1, maximumRequests)
    private val enrollment: CommandRequestEnrollment
    private val monitor = Any()
    private val running = Mutex()
    private val sending = Mutex()
    private var closed = false
    private var lifetime: Job? = null
    private var wire: CommandConnectionWire? = null
    private val state = MutableStateFlow(CommandConnectionState.DISCONNECTED)
    val connectionState = state.asStateFlow()
    val requests get() = enrollment.requestSessions

    init {
        require(record.phase == EnrollmentPhase.ACTIVE)
        val e = record.enrollment
        enrollment = inbox.add(e.macID.copyBytes(), e.accountID.copyBytes(), e.authorityPublicKey.copyBytes(), limits)
    }

    /** A foreground or wake owner runs this once per connection attempt. No automatic decision retry occurs. */
    suspend fun run() {
        check(running.tryLock())
        var candidate: CommandConnectionWire? = null
        try {
            withContext(dispatcher) {
                coroutineScope {
                    synchronized(monitor) {
                        check(!closed)
                        lifetime = coroutineContext[Job]
                        state.value = CommandConnectionState.CONNECTING
                    }
                    candidate = open(this, enrollment)
                    ensureActive()
                    synchronized(monitor) {
                        check(!closed)
                        wire = checkNotNull(candidate)
                        state.value = CommandConnectionState.CONNECTED
                    }
                    checkNotNull(candidate).receive()
                }
            }
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { throw IOException("Command connection unavailable") }
        finally {
            synchronized(monitor) {
                wire = null
                lifetime = null
                if (!closed) state.value = CommandConnectionState.DISCONNECTED
            }
            try { candidate?.close() } finally { running.unlock() }
        }
    }

    fun approval(session: CommandRequestSession) = CommandApprovalContext(record, limits) { send(session, it) }

    /** Rechecks the retained request and enrolled signing role before writing on this incarnation. */
    internal suspend fun send(session: CommandRequestSession, message: ApprovalMessage) = withContext(dispatcher) {
        sending.withLock {
            val active = synchronized(monitor) { check(!closed); checkNotNull(wire) }
            check(enrollment.sessions().any { it === session })
            val e = record.enrollment
            check(message.wireVersion == 1uL && message.type == ApprovalMessageType.DECISION)
            val body = message.body.copyBytes()
            val claim = DecisionPayload.decode(body, limits.body)
            val key = when (claim.action.choice) {
                ActionChoice.EXECUTE -> e.biometricKey.also { check(message.purpose == SigningPurpose.BIOMETRIC_AUTHORIZATION) }
                ActionChoice.DECLINE -> e.decisionKey.also { check(message.purpose == SigningPurpose.CANCELLATION) }
                else -> throw IOException("Unsupported command decision")
            }
            session.withPendingDecision(clock(), e.phoneID.copyBytes(), key.keyID.copyBytes(), claim.action) {
                check(it.encode(limits.body).contentEquals(body))
                check(ApprovalSignature.verify(message.signature.copyBytes(), key.publicKey.copyBytes(), 1u,
                    message.type, message.purpose, body, limits.body, limits.signing))
            }
            ensureActive()
            synchronized(monitor) { check(!closed && wire === active) }
            active.send(message.encode(limits.body.maxBytes))
            ensureActive()
            synchronized(monitor) { check(!closed && wire === active) }
        }
    }

    override fun close() {
        val resources = synchronized(monitor) {
            if (closed) return
            closed = true
            state.value = CommandConnectionState.CLOSED
            (wire to lifetime).also { wire = null; lifetime = null }
        }
        resources.second?.cancel()
        try { resources.first?.close() } finally { inbox.close() }
    }
}
