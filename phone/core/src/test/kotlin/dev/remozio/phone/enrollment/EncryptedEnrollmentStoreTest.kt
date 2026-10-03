package dev.remozio.phone.enrollment

import dev.remozio.phone.transport.RelayAccessCredential
import dev.remozio.phone.transport.RelayEndpoint
import dev.remozio.protocol.*
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import org.junit.Test
import kotlin.test.*

class EncryptedEnrollmentStoreTest {
    private class Storage : EnrollmentStorage {
        var bytes: ByteArray? = null
        var failBefore = false
        var failAfter = false
        var writes = 0
        override fun read(maximumBytes: Int): ByteArray? = bytes?.copyOf()?.also { require(it.size <= maximumBytes) }
        override fun replace(ciphertext: ByteArray) {
            writes++
            if (failBefore) error("synthetic before")
            bytes = ciphertext.copyOf()
            if (failAfter) error("synthetic after")
        }
        override fun close() { }
    }
    private fun cipher() = EnrollmentCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey(), 65_536)
    private fun identity(n: Int) = ByteArray(16) { n.toByte() }
    private fun spki() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded
    private fun record(n: Int, scope: Int = n, reuse: PhoneEnrollment? = null, tag: ByteArray? = null): PhoneEnrollment {
        fun key(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val publicKey = spki()
            return EnrollmentKeyReference(role, identity(n * 3 + role.ordinal),
                "remozio.${role.aliasPart}.v1.${"%032x".format(n * 3 + role.ordinal)}",
                if (role == EnrollmentKeyRole.TRANSPORT) publicKey else publicKey.takeLast(65).toByteArray())
        }
        val endpoint = RelayEndpoint("synthetic.example")
        return PhoneEnrollment(identity(n), identity(scope), identity(100), identity(n + 40), identity(n + 80),
            "Synthetic Mac $scope", spki().takeLast(65).toByteArray(), spki(),
            reuse?.transportKey ?: key(EnrollmentKeyRole.TRANSPORT), reuse?.decisionKey ?: key(EnrollmentKeyRole.DECISION),
            reuse?.biometricKey ?: key(EnrollmentKeyRole.BIOMETRIC), tag ?: ByteArray(32) { n.toByte() },
            RelayAccessCredential(endpoint, "synthetic-access-id", "synthetic-access-secret"))
    }

    @Test fun preparationActivationAndRemovalSurviveRestartWithoutAffectingAnotherMac() {
        val storage = Storage(); val cipher = cipher()
        val store = EncryptedEnrollmentStore.create(storage, cipher, 10)
        val a = record(1); val b = record(2)
        store.prepare(a, 0u); store.activate(a.recordID.copyBytes(), 1u)
        store.prepare(b, 2u); store.activate(b.recordID.copyBytes(), 3u)
        store.remove(a.recordID.copyBytes(), 4u)
        store.close()
        val restored = EncryptedEnrollmentStore.open(storage, cipher, 10).snapshot()
        assertEquals(5uL, restored.revision)
        assertEquals(listOf(EnrollmentPhase.REMOVED, EnrollmentPhase.ACTIVE), restored.entries.map { it.phase })
        assertContentEquals(b.transportPublicKey.copyBytes(), restored.entries[1].enrollment.transportPublicKey.copyBytes())
        assertFalse(String(requireNotNull(storage.bytes), Charsets.ISO_8859_1).contains("synthetic-access-secret"))
    }

    @Test fun explicitReplacementIsAtomicAndLateCallbacksCannotReviveRemovedEntries() {
        val storage = Storage(); val cipher = cipher()
        val store = EncryptedEnrollmentStore.create(storage, cipher, 10)
        val old = record(1); val replacement = record(2, scope = 1)
        store.prepare(old, 0u); store.activate(old.recordID.copyBytes(), 1u); store.prepare(replacement, 2u)
        assertFailsWith<IllegalArgumentException> { store.activate(replacement.recordID.copyBytes(), 3u) }
        assertFailsWith<IllegalArgumentException> { store.activate(replacement.recordID.copyBytes(), 3u, identity(99)) }
        val snapshot = store.activate(replacement.recordID.copyBytes(), 3u, old.recordID.copyBytes())
        assertEquals(listOf(EnrollmentPhase.REMOVED, EnrollmentPhase.ACTIVE), snapshot.entries.map { it.phase })
        assertFailsWith<IllegalArgumentException> { store.activate(old.recordID.copyBytes(), 4u) }
        assertFailsWith<IllegalArgumentException> { store.prepare(old, 4u) }
        assertFailsWith<IllegalArgumentException> { store.remove(replacement.recordID.copyBytes(), 3u) }
    }

    @Test fun ambiguousWriteRetiresTheOwnerAndReopenReconcilesTheActualDurableResult() {
        for (after in listOf(false, true)) {
            val storage = Storage(); val cipher = cipher()
            val store = EncryptedEnrollmentStore.create(storage, cipher, 10)
            val a = record(1); store.prepare(a, 0u)
            storage.failBefore = !after; storage.failAfter = after
            assertFailsWith<EnrollmentStoreUnavailable> { store.activate(a.recordID.copyBytes(), 1u) }
            assertFailsWith<EnrollmentStoreUnavailable> { store.snapshot() }
            assertFailsWith<EnrollmentStoreUnavailable> { store.remove(a.recordID.copyBytes(), 1u) }
            store.close(); storage.failBefore = false; storage.failAfter = false
            val restored = EncryptedEnrollmentStore.open(storage, cipher, 10).snapshot()
            assertEquals(if (after) EnrollmentPhase.ACTIVE else EnrollmentPhase.PREPARED, restored.entries.single().phase)
        }
    }

    @Test fun refusesMissingCorruptWrongKeyAndUnknownSchemaWithoutReset() {
        val storage = Storage(); val cipher = cipher()
        assertFailsWith<EnrollmentStoreUnavailable> { EncryptedEnrollmentStore.open(storage, cipher, 10) }
        EncryptedEnrollmentStore.create(storage, cipher, 10).close()
        assertFailsWith<EnrollmentStoreUnavailable> { EncryptedEnrollmentStore.create(storage, cipher, 10) }
        assertFailsWith<EnrollmentStoreUnavailable> { EncryptedEnrollmentStore.open(storage, cipher(), 10) }
        storage.bytes = storage.bytes!!.also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertFailsWith<EnrollmentStoreUnavailable> { EncryptedEnrollmentStore.open(storage, cipher, 10) }
        storage.bytes = cipher.encrypt(DeterministicCbor.encode(CborValue.Fields(mapOf(0uL to CborValue.Unsigned(2u),
            1uL to CborValue.Unsigned(0u), 2uL to CborValue.ArrayValue(emptyList()))), CborLimits(100, 3, 10)))
        assertFailsWith<EnrollmentStoreUnavailable> { EncryptedEnrollmentStore.open(storage, cipher, 10) }
        assertEquals(1, storage.writes)
    }

    @Test fun boundsRecordsAndForbidsCrossMacKeyReuseWhileAllowingSamePairContinuity() {
        val storage = Storage(); val store = EncryptedEnrollmentStore.create(storage, cipher(), 2)
        val a = record(1); store.prepare(a, 0u); store.activate(a.recordID.copyBytes(), 1u)
        assertFailsWith<IllegalArgumentException> { store.prepare(record(2, reuse = a), 2u) }
        store.prepare(record(3, scope = 1, reuse = a), 2u)
        assertFailsWith<IllegalArgumentException> { store.prepare(record(4), 3u) }
        assertEquals(3uL, store.snapshot().revision)
    }

    @Test fun rejectsDuplicateAndAmbiguousRowsOnLoad() {
        val cipher = cipher(); val storage = Storage(); val a = record(1)
        val row = EnrollmentEncoding.encode(StoredPhoneEnrollment(a, EnrollmentPhase.ACTIVE))
        storage.bytes = cipher.encrypt(DeterministicCbor.encode(CborValue.Fields(mapOf(0uL to CborValue.Unsigned(1u),
            1uL to CborValue.Unsigned(5u), 2uL to CborValue.ArrayValue(listOf(row, row)))), CborLimits(65_536, 8, 1_000)))
        assertFailsWith<EnrollmentStoreUnavailable> { EncryptedEnrollmentStore.open(storage, cipher, 10) }
        assertEquals(0, storage.writes)
    }

    @Test fun cancellingPreparedReplacementKeepsTheCurrentEnrollmentActive() {
        val store = EncryptedEnrollmentStore.create(Storage(), cipher(), 10)
        val a = record(1); val b = record(2, scope = 1)
        store.prepare(a, 0u); store.activate(a.recordID.copyBytes(), 1u); store.prepare(b, 2u)
        val snapshot = store.remove(b.recordID.copyBytes(), 3u)
        assertEquals(listOf(EnrollmentPhase.ACTIVE, EnrollmentPhase.REMOVED), snapshot.entries.map { it.phase })
        assertFailsWith<IllegalArgumentException> { store.activate(b.recordID.copyBytes(), 4u, a.recordID.copyBytes()) }
    }

    @Test fun rejectsUnknownFieldsPhasesAndReusedApprovalMaterialOnLoad() {
        val cipher = cipher(); val a = record(1)
        val valid = (EnrollmentEncoding.encode(StoredPhoneEnrollment(a, EnrollmentPhase.PREPARED)) as CborValue.Fields).values
        val changedBiometric = (valid.getValue(10u) as CborValue.Fields).values.toMutableMap().apply { this[2u] = a.decisionKey.publicKey }
        for (changed in listOf(valid + (14uL to CborValue.Null), valid + (13uL to CborValue.Unsigned(99u)), valid + (10uL to CborValue.Fields(changedBiometric)))) {
            val storage = Storage()
            storage.bytes = cipher.encrypt(DeterministicCbor.encode(CborValue.Fields(mapOf(0uL to CborValue.Unsigned(1u),
                1uL to CborValue.Unsigned(1u), 2uL to CborValue.ArrayValue(listOf(CborValue.Fields(changed))))), CborLimits(65_536, 8, 1_000)))
            assertFailsWith<EnrollmentStoreUnavailable> { EncryptedEnrollmentStore.open(storage, cipher, 10) }
            assertEquals(0, storage.writes)
        }
    }

    @Test fun enrollmentTagsCannotBeReusedAcrossMacsOrAfterRemoval() {
        val storage = Storage(); val cipher = cipher(); val store = EncryptedEnrollmentStore.create(storage, cipher, 10)
        val a = record(1); val duplicate = record(2, tag = a.enrollmentTag.copyBytes())
        store.prepare(a, 0u); store.activate(a.recordID.copyBytes(), 1u)
        assertFailsWith<IllegalArgumentException> { store.prepare(duplicate, 2u) }
        assertFailsWith<IllegalArgumentException> { store.prepare(record(3, scope = 1, tag = a.enrollmentTag.copyBytes()), 2u) }
        store.remove(a.recordID.copyBytes(), 2u)
        assertFailsWith<IllegalArgumentException> { store.prepare(duplicate, 3u) }
        storage.bytes = cipher.encrypt(DeterministicCbor.encode(CborValue.Fields(mapOf(0uL to CborValue.Unsigned(1u),
            1uL to CborValue.Unsigned(4u), 2uL to CborValue.ArrayValue(listOf(
                EnrollmentEncoding.encode(StoredPhoneEnrollment(a, EnrollmentPhase.REMOVED)),
                EnrollmentEncoding.encode(StoredPhoneEnrollment(duplicate, EnrollmentPhase.PREPARED)))))), CborLimits(65_536, 8, 1_000)))
        assertFailsWith<EnrollmentStoreUnavailable> { EncryptedEnrollmentStore.open(storage, cipher, 10) }
    }

    @Test fun configurationPreflightRejectsLimitsThatCannotInitializeTheArchive() {
        for (size in 1..6) assertFailsWith<CborException> { EncryptedEnrollmentStore.validateConfiguration(10, size) }
        EncryptedEnrollmentStore.validateConfiguration(10, 7)
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val storage = Storage()
        val store = EncryptedEnrollmentStore.create(storage, EnrollmentCipher(key, 7), 10)
        assertEquals(0uL, store.snapshot().revision)
        assertEquals(43, storage.bytes!!.size)
    }

    @Test fun snapshotsAndPublicKeyReferencesAreImmutableAndDescriptionsAreRedacted() {
        val store = EncryptedEnrollmentStore.create(Storage(), cipher(), 10)
        val a = record(1); val snapshot = store.prepare(a, 0u)
        val key = a.transportKey.publicKey.copyBytes(); key.fill(0)
        assertNotEquals(0.toByte(), a.transportKey.publicKey.copyBytes()[0])
        assertFailsWith<UnsupportedOperationException> { (snapshot.entries as MutableList).clear() }
        assertEquals("PhoneEnrollment(redacted)", a.toString())
        assertEquals("EnrollmentKeyReference(redacted)", a.transportKey.toString())
        assertEquals("EnrollmentSnapshot(redacted)", snapshot.toString())
    }
}
