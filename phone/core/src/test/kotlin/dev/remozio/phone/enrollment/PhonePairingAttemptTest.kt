package dev.remozio.phone.enrollment

import dev.remozio.protocol.*
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import org.junit.Test
import kotlin.test.*

class PhonePairingAttemptTest {
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun key() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val authority = key()
    private fun record(n: Int): PhoneEnrollment {
        fun local(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val point = key().public.encoded
            return EnrollmentKeyReference(role, id(n * 3 + role.ordinal),
                "remozio.${role.aliasPart}.v1.${"%032x".format(n * 3 + role.ordinal)}",
                if (role == EnrollmentKeyRole.TRANSPORT) point else point.takeLast(65).toByteArray())
        }
        return PhoneEnrollment(id(n), id(20), id(21), id(n + 30), id(n + 40), "Synthetic Mac",
            authority.public.encoded.takeLast(65).toByteArray(), key().public.encoded,
            local(EnrollmentKeyRole.TRANSPORT), local(EnrollmentKeyRole.DECISION), local(EnrollmentKeyRole.BIOMETRIC),
            ByteArray(32) { n.toByte() }, null)
    }
    private fun transcript(e: PhoneEnrollment, old: PhoneEnrollment? = null): PairingTranscript {
        val scope = ChannelScope(e.macID.copyBytes(), e.accountID.copyBytes(), e.phoneID.copyBytes(), e.epoch.copyBytes())
        fun offer(role: ChannelRole, nonce: Int) = ChannelOffer(role, scope, ByteArray(32) { nonce.toByte() }, setOf(1uL), emptyList(), emptySet())
        fun claim(k: EnrollmentKeyReference) = PairingKey(k.keyID.copyBytes(), k.pointBytes())
        return PairingTranscript(id(70), ByteArray(32) { 71 }, offer(ChannelRole.PHONE, 72), offer(ChannelRole.MAC, 73),
            1u, 1u, e.authorityPublicKey.copyBytes(), e.transportPublicKey.copyBytes().takeLast(65).toByteArray(),
            claim(e.transportKey), claim(e.decisionKey), claim(e.biometricKey), e.enrollmentTag.copyBytes(),
            old?.let { PairingReplacement(it.phoneID.copyBytes(), it.epoch.copyBytes()) }, id(74), 1000u, 2000u)
    }
    private fun sign(t: PairingTranscript, purpose: PairingProofPurpose = PairingProofPurpose.MAC_COMMIT) =
        Signature.getInstance("SHA256withECDSAinP1363Format").run {
            initSign(authority.private); update(t.signingInput(purpose)); sign()
        }
    private fun store(): EncryptedEnrollmentStore {
        val storage = object : EnrollmentStorage {
            var bytes: ByteArray? = null
            override fun read(maximumBytes: Int) = bytes?.copyOf()
            override fun replace(ciphertext: ByteArray) { bytes = ciphertext.copyOf() }
            override fun close() { }
        }
        return EncryptedEnrollmentStore.create(storage,
            EnrollmentCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey(), 65_536), 10)
    }

    @Test fun onlyTheExactMacReceiptActivatesAndReplayCannotReviveRemoval() {
        val store = store(); val e = record(1); val t = transcript(e)
        val prepared = store.prepare(e, 0u).entries.single()
        val attempt = PhonePairingAttempt(t, prepared, null, 1u)
        assertFailsWith<IllegalArgumentException> { attempt.activate(store, ByteArray(64)) }
        assertFailsWith<IllegalArgumentException> { attempt.activate(store, sign(t, PairingProofPurpose.PHONE_BIOMETRIC)) }
        assertEquals(EnrollmentPhase.PREPARED, store.snapshot().entries.single().phase)
        assertEquals(EnrollmentPhase.ACTIVE, attempt.activate(store, sign(t)).entries.single().phase)
        assertFailsWith<IllegalArgumentException> { attempt.activate(store, sign(t)) }
        store.remove(e.recordID.copyBytes(), 2u)
        assertFailsWith<IllegalArgumentException> { attempt.activate(store, sign(t)) }
        assertEquals(EnrollmentPhase.REMOVED, store.snapshot().entries.single().phase)
    }

    @Test fun receiptCannotAuthorizeDifferentLocallyPreparedMaterial() {
        val e = record(1); val other = record(2); val t = transcript(e)
        val encoded = (EnrollmentEncoding.encode(StoredPhoneEnrollment(e, EnrollmentPhase.PREPARED)) as CborValue.Fields).values
        val different = (EnrollmentEncoding.encode(StoredPhoneEnrollment(other, EnrollmentPhase.PREPARED)) as CborValue.Fields).values
        for (field in listOf(3uL, 4uL, 7uL, 8uL, 9uL, 10uL, 11uL)) {
            val changed = EnrollmentEncoding.decode(CborValue.Fields(encoded + (field to different.getValue(field))))
            assertFailsWith<IllegalArgumentException> { PhonePairingAttempt(t, changed, null, 1u) }
        }
        assertFailsWith<IllegalArgumentException> {
            PhonePairingAttempt(t, StoredPhoneEnrollment(e, EnrollmentPhase.PREPARED), null, 2u)
        }
        val store = store(); store.prepare(e, 0u)
        val attempt = PhonePairingAttempt(t, store.snapshot().entries.single(), null, 1u)
        assertFailsWith<IllegalArgumentException> { attempt.activate(store, sign(transcript(other))) }
    }

    @Test fun replacementRequiresTheExactActiveLocalSelection() {
        val store = store(); val old = record(1); val next = record(2)
        store.prepare(old, 0u); val active = store.activate(old.recordID.copyBytes(), 1u).entries.single()
        val prepared = store.prepare(next, 2u).entries.last(); val t = transcript(next, old)
        assertFailsWith<IllegalArgumentException> { PhonePairingAttempt(t, prepared, null, 1u) }
        assertFailsWith<IllegalArgumentException> { PhonePairingAttempt(transcript(next), prepared, active, 1u) }
        assertFailsWith<IllegalArgumentException> {
            PhonePairingAttempt(t, prepared, StoredPhoneEnrollment(record(3), EnrollmentPhase.ACTIVE), 1u)
        }
        val result = PhonePairingAttempt(t, prepared, active, 1u).activate(store, sign(t))
        assertEquals(listOf(EnrollmentPhase.REMOVED, EnrollmentPhase.ACTIVE), result.entries.map { it.phase })
    }
}
