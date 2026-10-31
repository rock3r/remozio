package dev.remozio.phone.transport

import dev.remozio.phone.enrollment.PhoneEnrollment
import dev.remozio.phone.enrollment.EnrollmentPhase
import dev.remozio.phone.enrollment.StoredPhoneEnrollment
import dev.remozio.protocol.*
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withTimeout

/** A signed observation is not proof that a host remains online. The owner must recheck enrollment and connectivity. */
sealed interface PhoneRoutingResult {
    class Failure(val reason: PhoneRoutingFailure) : PhoneRoutingResult
    class Verified internal constructor(
        val response: RoutingStatusResponse,
        private val record: StoredPhoneEnrollment,
        private val age: RoutingElapsedAge,
    ) : PhoneRoutingResult {
        fun matchesEnrollment(current: StoredPhoneEnrollment): Boolean =
            current.phase == EnrollmentPhase.ACTIVE && record.sameConnectionAs(current)
        fun ageMilliseconds(): Long? = age.milliseconds()
        fun isFresh(maximumAgeMilliseconds: Long): Boolean {
            require(maximumAgeMilliseconds > 0)
            return ageMilliseconds()?.let { it < maximumAgeMilliseconds } == true
        }
        val challenge: PhoneRoutingChallenge? = response.canonicalChallenge?.let { PhoneRoutingChallenge(record, it.copyBytes(), age) }
        override fun toString() = "PhoneRoutingResult.Verified(redacted)"
    }
}

/** Retains the original request instant. Repeated reads cannot renew a challenge or recover from a regressing clock. */
internal class RoutingElapsedAge(private val started: Long, private val now: () -> Long) {
    private var previous = started
    private var invalid = started < 0
    @Synchronized fun milliseconds(): Long? {
        if (invalid) return null
        val sampled = try { now() } catch (_: Exception) { invalid = true; return null }
        if (sampled < previous) { invalid = true; return null }
        previous = sampled
        val elapsed = sampled - started
        return elapsed / 1_000_000 + if (elapsed % 1_000_000 == 0L) 0 else 1
    }
}

/** Only a verified Root response can create this decision-key challenge. It grants no command or credential authority. */
class PhoneRoutingChallenge internal constructor(
    private val record: StoredPhoneEnrollment,
    canonicalControl: ByteArray,
    private val age: RoutingElapsedAge,
) {
    private val canonical = CborValue.Bytes(canonicalControl)
    private val control = RoutingAwayControl.decode(canonical.copyBytes(), CONTROL_LIMITS)
    private val lifetime = control.expiresAtUnixMillis - control.issuedAtUnixMillis
    init {
        require(lifetime <= Long.MAX_VALUE.toULong())
        require(control.keyID.contentEquals(record.enrollment.decisionKey.keyID.copyBytes()))
    }
    internal fun requireUsable(current: StoredPhoneEnrollment) {
        require(current.phase == EnrollmentPhase.ACTIVE && record.sameConnectionAs(current))
        require(age.milliseconds()?.let { it.toULong() < lifetime } == true)
    }
    fun signingInput(): ByteArray {
        requireUsable(record)
        return RoutingAwaySigningInput.make(1u, canonical.copyBytes(), CONTROL_LIMITS, SIGNING_LIMITS)
    }
    /** Custody code signs only a verified challenge for its exact enrolled identity. */
    fun sign(enrollment: PhoneEnrollment, signer: (ByteArray) -> ByteArray): ByteArray {
        require(record.sameConnectionAs(StoredPhoneEnrollment(enrollment, record.phase, record.pairing)))
        val signature = signer(signingInput()).copyOf()
        requireUsable(record)
        require(RoutingAwaySignature.verify(signature, enrollment.decisionKey.publicKey.copyBytes(), 1u,
            canonical.copyBytes(), CONTROL_LIMITS, SIGNING_LIMITS))
        return signature
    }
    internal fun bytes(current: StoredPhoneEnrollment): ByteArray {
        requireUsable(current); return canonical.copyBytes()
    }
    override fun toString() = "PhoneRoutingChallenge(redacted)"
}

/** One bounded routing exchange over enrolled TLS. Application messages are never retried. */
class PhoneRoutingChannel private constructor(
    private val record: StoredPhoneEnrollment,
    private val channel: NegotiatedTLSChannel,
    private val timeoutMillis: Long,
    private val nowNanos: () -> Long,
    private val newNonce: () -> ByteArray,
) : AutoCloseable {
    private val used = AtomicBoolean(false)

    suspend fun status(): PhoneRoutingResult = operation { PhoneRoutingFrame.Status(newNonce()) }
    suspend fun challenge(expectedRevision: ULong): PhoneRoutingResult = operation { PhoneRoutingFrame.Challenge(newNonce(), expectedRevision) }
    suspend fun apply(challenge: PhoneRoutingChallenge, signature: ByteArray): PhoneRoutingResult = operation {
        val control = challenge.bytes(record)
        val retainedSignature = signature.copyOf()
        require(RoutingAwaySignature.verify(retainedSignature, record.enrollment.decisionKey.publicKey.copyBytes(), 1u,
            control, CONTROL_LIMITS, SIGNING_LIMITS))
        PhoneRoutingFrame.Apply(newNonce(), control, retainedSignature)
    }
    private suspend fun operation(request: () -> PhoneRoutingFrame): PhoneRoutingResult {
        try {
            check(used.compareAndSet(false, true))
            return withTimeout(timeoutMillis) {
                val age = RoutingElapsedAge(nowNanos(), nowNanos)
                require(age.milliseconds() != null)
                val query = request()
                channel.send(query.encode())
                val reply = PhoneRoutingFrame.decode(channel.receive() ?: throw IOException("Missing routing response"))
                require(reply.queryNonce == query.queryNonce)
                val result = when (reply) {
                    is PhoneRoutingFrame.Failure -> PhoneRoutingResult.Failure(reply.reason)
                    is PhoneRoutingFrame.Response -> {
                        val body = reply.canonicalPayload.copyBytes()
                        require(RoutingStatusSignature.verify(reply.signature.copyBytes(), record.enrollment.authorityPublicKey.copyBytes(),
                            1u, body, SIGNING_LIMITS))
                        val response = RoutingStatusResponse.decode(body)
                        validate(response, query)
                        PhoneRoutingResult.Verified(response, record, age).also { it.challenge?.requireUsable(record) }
                    }
                    else -> throw IOException("Invalid routing response role")
                }
                require(age.milliseconds()?.let { it < timeoutMillis } == true)
                result
            }
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { throw IOException("Routing unavailable") }
        finally { close() }
    }
    private fun validate(response: RoutingStatusResponse, query: PhoneRoutingFrame) {
        val e = record.enrollment
        require(response.scope == ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes()))
        require(response.queryNonce == query.queryNonce)
        when (query) {
            is PhoneRoutingFrame.Status -> require(response.outcome == RoutingStatusOutcome.STATUS)
            is PhoneRoutingFrame.Challenge -> {
                require((response.outcome == RoutingStatusOutcome.CHALLENGE && response.state.revision == query.expectedRevision) ||
                    response.outcome == RoutingStatusOutcome.CONFLICT)
                require(response.controlDigest == null)
            }
            is PhoneRoutingFrame.Apply -> {
                require(response.outcome == RoutingStatusOutcome.APPLIED || response.outcome == RoutingStatusOutcome.CONFLICT)
                require(response.controlDigest == CborValue.Bytes(MessageDigest.getInstance("SHA-256").digest(query.canonicalControl.copyBytes())))
                if (response.outcome == RoutingStatusOutcome.APPLIED) {
                    val original = RoutingAwayControl.decode(query.canonicalControl.copyBytes(), CONTROL_LIMITS)
                    require(original.expectedRevision < ULong.MAX_VALUE && response.appliedRevision == original.expectedRevision + 1u)
                }
            }
            else -> throw IOException("Invalid routing request role")
        }
    }
    override fun close() = channel.close()
    suspend fun closeAndJoin() = channel.closeAndJoin()
    override fun toString() = "PhoneRoutingChannel(redacted)"

    companion object {
        /** Android must supply elapsedRealtimeNanos, which includes device sleep. */
        fun bind(record: StoredPhoneEnrollment, channel: NegotiatedTLSChannel, elapsedRealtimeNanos: () -> Long,
                 timeoutMillis: Long = 5_000): PhoneRoutingChannel =
            bind(record, channel, elapsedRealtimeNanos, timeoutMillis) { ByteArray(32).also { SecureRandom().nextBytes(it) } }

        internal fun bind(record: StoredPhoneEnrollment, channel: NegotiatedTLSChannel, elapsedRealtimeNanos: () -> Long,
                          timeoutMillis: Long, newNonce: () -> ByteArray): PhoneRoutingChannel {
            try {
                require(record.phase == EnrollmentPhase.ACTIVE && timeoutMillis in 1..60_000)
                val e = record.enrollment
                val scope = ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes())
                val peer = channel.negotiated
                require(channel.purpose == EnrolledChannelPurpose.ROUTING && channel.localRequests.isEmpty() && channel.localAuditVersions.isEmpty())
                require(channel.maximumPayloadBytes >= PhoneRoutingFrame.MAXIMUM_BYTES)
                require(peer.peer.role == ChannelRole.MAC && peer.peer.scope == scope && peer.envelopeVersion == 1uL &&
                    peer.envelopeVersion >= (record.pairing?.minimumEnvelopeVersion ?: 1uL) && peer.peer.requests.isEmpty() && peer.peer.auditVersions.isEmpty())
                return PhoneRoutingChannel(record, channel, timeoutMillis, elapsedRealtimeNanos, newNonce)
            } catch (failure: Exception) { channel.close(); throw failure }
        }
    }
}

private val CONTROL_LIMITS = CborLimits(1024, 2, 32)
private val SIGNING_LIMITS = CborLimits(3200, 2, 16)
