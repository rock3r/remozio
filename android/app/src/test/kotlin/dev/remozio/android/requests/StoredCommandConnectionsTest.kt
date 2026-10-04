package dev.remozio.android.requests

import dev.remozio.phone.enrollment.*
import dev.remozio.phone.requests.*
import dev.remozio.protocol.CborLimits
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import org.junit.Test
import kotlin.test.*

class StoredCommandConnectionsTest {
    private class Storage : EnrollmentStorage {
        var bytes: ByteArray? = null
        var fail = false
        override fun read(maximumBytes: Int): ByteArray? { check(!fail); return bytes?.copyOf() }
        override fun replace(ciphertext: ByteArray) { bytes = ciphertext.copyOf() }
        override fun close() = Unit
    }
    private val storage = Storage()
    private val cipher = EnrollmentCipher(KeyGenerator.getInstance("AES").apply { init(256) }.generateKey(), 65536)
    private val bounds = CborLimits(32768, 32, 4096)
    private val limits = RequestLimits(bounds, bounds, bounds, bounds)
    private fun id(n: Int) = ByteArray(16) { n.toByte() }
    private fun publicKey() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded
    private fun enrollment(n: Int, scope: Int = n): PhoneEnrollment {
        fun key(role: EnrollmentKeyRole): EnrollmentKeyReference {
            val public = publicKey()
            return EnrollmentKeyReference(role, id(3 * n + role.ordinal),
                "remozio.${role.aliasPart}.v1.${"%032x".format(3 * n + role.ordinal)}",
                if (role == EnrollmentKeyRole.TRANSPORT) public else public.takeLast(65).toByteArray())
        }
        return PhoneEnrollment(id(n), id(scope), id(100), id(110 + n), id(120 + n), "Synthetic Mac",
            publicKey().takeLast(65).toByteArray(), publicKey(), key(EnrollmentKeyRole.TRANSPORT),
            key(EnrollmentKeyRole.DECISION), key(EnrollmentKeyRole.BIOMETRIC), ByteArray(32) { n.toByte() }, null)
    }
    private fun open() = EncryptedEnrollmentStore.open(storage, cipher, 10)
    private fun activate(enrollment: PhoneEnrollment, replacement: PhoneEnrollment? = null) = open().use {
        val prepared = it.prepare(enrollment, it.snapshot().revision)
        it.activateSyntheticEnrollment(enrollment.recordID.copyBytes(), prepared.revision, replacement?.recordID?.copyBytes())
    }
    private fun connection(record: StoredPhoneEnrollment) = CommandConnection(record, limits,
        open = { _, _ -> error("No network in registry test") }, clock = { ElapsedInstant(0, 0u) }, dispatcher = Dispatchers.Unconfined)
    private fun registry(create: (StoredPhoneEnrollment) -> CommandConnection = ::connection) =
        StoredCommandConnections(::open, create, Mutex(), Dispatchers.Unconfined)
    init { EncryptedEnrollmentStore.create(storage, cipher, 10).close() }

    @Test fun repeatedAndConcurrentAcquisitionsShareOneOwnerPerMac() = runBlocking {
        val a = enrollment(1); val b = enrollment(2); activate(a); activate(b)
        var created = 0
        val registry = registry { created++; connection(it) }
        val owners = List(20) { async { registry.acquire(a.recordID) } }.awaitAll()
        owners.forEach { assertSame(owners.first(), it) }
        val other = registry.acquire(b.recordID)
        assertNotSame(owners.first(), other); assertEquals(2, created)
        registry.invalidate()
        assertEquals(CommandConnectionState.CLOSED, owners.first().connectionState.value)
        assertEquals(CommandConnectionState.CLOSED, other.connectionState.value)
    }

    @Test fun replacementClosesOldOwnerBeforeOpeningNewWithoutClosingAnotherMac() = runBlocking {
        val a = enrollment(1); val b = enrollment(2); val replacement = enrollment(3, 1)
        activate(a); activate(b)
        var old: CommandConnection? = null
        val registry = registry {
            if (it.enrollment.recordID == replacement.recordID) assertEquals(CommandConnectionState.CLOSED, old!!.connectionState.value)
            connection(it)
        }
        old = registry.acquire(a.recordID)
        val other = registry.acquire(b.recordID)
        activate(replacement, a)
        val fresh = registry.acquire(replacement.recordID)
        assertNotSame(old, fresh); assertSame(other, registry.acquire(b.recordID))
        assertFailsWith<CommandEnrollmentUnavailable> { registry.acquire(a.recordID) }
        registry.invalidate()
    }

    @Test fun unreadableArchiveInvalidatesEveryOwnerAndRecoveryCreatesFreshOnes() = runBlocking {
        val a = enrollment(1); val b = enrollment(2); activate(a); activate(b)
        val registry = registry(); val first = registry.acquire(a.recordID); val second = registry.acquire(b.recordID)
        storage.fail = true
        assertFailsWith<CommandRegistryUnavailable> { registry.acquire(a.recordID) }
        assertEquals(CommandConnectionState.CLOSED, first.connectionState.value)
        assertEquals(CommandConnectionState.CLOSED, second.connectionState.value)
        storage.fail = false
        assertNotSame(first, registry.acquire(a.recordID)); registry.invalidate()
    }

    @Test fun preparedRemovedAndFailedConstructionNeverPublishAnOwner() = runBlocking {
        val a = enrollment(1)
        open().use { it.prepare(a, it.snapshot().revision) }
        var attempts = 0
        val registry = registry { attempts++; if (attempts == 1) error("Synthetic storage failure"); connection(it) }
        assertFailsWith<CommandEnrollmentUnavailable> { registry.acquire(a.recordID) }; assertEquals(0, attempts)
        open().use { it.activateSyntheticEnrollment(a.recordID.copyBytes(), it.snapshot().revision) }
        assertFailsWith<CommandRegistryUnavailable> { registry.acquire(a.recordID) }
        val owner = registry.acquire(a.recordID); assertEquals(2, attempts)
        open().use { it.remove(a.recordID.copyBytes(), it.snapshot().revision) }
        assertFailsWith<CommandEnrollmentUnavailable> { registry.acquire(a.recordID) }
        assertEquals(CommandConnectionState.CLOSED, owner.connectionState.value)
    }
}
