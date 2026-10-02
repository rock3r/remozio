package dev.remozio.phone.crypto

import java.io.Closeable
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.*
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.hpke.HPKE
import org.junit.Test
import kotlin.test.*

/** Software-key experiment only. The private controller is not a network protocol or trust store. */
class HPKEInteropTest {
    private fun hpke(mode: Byte = HPKE.mode_auth) = HPKE(
        mode, HPKE.kem_P256_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM256)
    private val info = "remozio-experiment-only/v1/mac-1/account-2/phone-3/epoch-4/mac-to-phone".toByteArray()
    private val aad = "request-5/message-6".toByteArray()
    private val plaintext = "synthetic approval details".toByteArray()
    private fun changed(bytes: ByteArray) = bytes.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
    private fun publicKey(key: AsymmetricCipherKeyPair) = hpke().serializePublicKey(key.public)

    @Test fun swiftSenderOpensInKotlinWithPinnedSender() = Peer().use { peer ->
        val recipient = hpke().generatePrivateKey()
        val sealed = peer.seal(publicKey(recipient), info, aad, plaintext)
        assertContentEquals(plaintext, open(sealed, recipient, peer.publicKey))
        assertEquals(65, sealed.encapsulation.size)
        assertEquals(plaintext.size + 16, sealed.ciphertext.size)
    }

    @Test fun kotlinSenderOpensInSwiftWithPinnedSender() = Peer().use { peer ->
        val sender = hpke().generatePrivateKey()
        val sealed = seal(sender, peer.publicKey)
        assertContentEquals(plaintext, peer.open(sealed, publicKey(sender), info, aad).bytes("plaintext"))
    }

    @Test fun kotlinRejectsChangedSenderRecipientScopeMetadataAndCiphertext() = Peer().use { peer ->
        val recipient = hpke().generatePrivateKey()
        val other = hpke().generatePrivateKey()
        val sealed = peer.seal(publicKey(recipient), info, aad, plaintext)
        val attempts = listOf<() -> ByteArray>(
            { open(sealed, recipient, publicKey(other)) },
            { open(sealed, other, peer.publicKey) },
            { open(sealed, recipient, peer.publicKey, changed(info)) },
            { open(sealed, recipient, peer.publicKey, associated = changed(aad)) },
            { open(sealed.copy(ciphertext = changed(sealed.ciphertext)), recipient, peer.publicKey) },
            { open(sealed.copy(ciphertext = sealed.ciphertext.dropLast(1).toByteArray()), recipient, peer.publicKey) },
        )
        attempts.forEach { assertFailsWith<InvalidCipherTextException> { it() } }
        assertContentEquals(plaintext, open(sealed, recipient, peer.publicKey))
    }

    @Test fun swiftRejectsChangedSenderRecipientScopeMetadataAndCiphertext() = Peer().use { peer ->
        val sender = hpke().generatePrivateKey()
        val other = hpke().generatePrivateKey()
        val sealed = seal(sender, peer.publicKey)
        val attempts = listOf(
            peer.open(sealed, publicKey(other), info, aad),
            peer.open(seal(sender, publicKey(other)), publicKey(sender), info, aad),
            peer.open(sealed, publicKey(sender), changed(info), aad),
            peer.open(sealed, publicKey(sender), info, changed(aad)),
            peer.open(sealed.copy(ciphertext = changed(sealed.ciphertext)), publicKey(sender), info, aad),
            peer.open(sealed.copy(ciphertext = sealed.ciphertext.dropLast(1).toByteArray()), publicKey(sender), info, aad),
        )
        attempts.forEach { assertEquals("true", it["rejected"]?.jsonPrimitive?.content) }
        assertContentEquals(plaintext, peer.open(sealed, publicKey(sender), info, aad).bytes("plaintext"))
    }

    @Test fun swiftRejectsBaseModeAndInvalidEncapsulatedKeys() = Peer().use { peer ->
        val sender = hpke().generatePrivateKey()
        val base = hpke(HPKE.mode_base).setupBaseS(hpke().deserializePublicKey(peer.publicKey), info)
        val baseEnvelope = Envelope(base.encapsulation, base.seal(aad, plaintext))
        assertEquals("true", peer.open(baseEnvelope, publicKey(sender), info, aad)["rejected"]?.jsonPrimitive?.content)
        val sealed = seal(sender, peer.publicKey)
        for (invalid in listOf(byteArrayOf(), ByteArray(65), sealed.encapsulation.copyOf(64), ByteArray(65) { 0xff.toByte() })) {
            assertEquals("true", peer.open(sealed.copy(encapsulation = invalid), publicKey(sender), info, aad)["rejected"]?.jsonPrimitive?.content)
        }
    }

    @Test fun emptyAndMaximumFixturePayloadsWorkInBothDirections() = Peer().use { peer ->
        val key = hpke().generatePrivateKey()
        for (payload in listOf(byteArrayOf(), ByteArray(65_536) { it.toByte() })) {
            assertContentEquals(payload, open(peer.seal(publicKey(key), info, aad, payload), key, peer.publicKey))
            assertContentEquals(payload, peer.open(seal(key, peer.publicKey, payload), publicKey(key), info, aad).bytes("plaintext"))
        }
    }

    @Test fun freshEncapsulationChangesCiphertextForIdenticalInput() = Peer().use { peer ->
        val key = hpke().generatePrivateKey()
        val swiftA = peer.seal(publicKey(key), info, aad, plaintext)
        val swiftB = peer.seal(publicKey(key), info, aad, plaintext)
        val kotlinA = seal(key, peer.publicKey)
        val kotlinB = seal(key, peer.publicKey)
        for ((a, b) in listOf(swiftA to swiftB, kotlinA to kotlinB)) {
            assertFalse(a.encapsulation.contentEquals(b.encapsulation))
            assertFalse(a.ciphertext.contentEquals(b.ciphertext))
        }
    }

    @Test fun newRecipientContextCanDecryptReplaySoApplicationMustRejectIt() = Peer().use { peer ->
        val key = hpke().generatePrivateKey()
        val swift = peer.seal(publicKey(key), info, aad, plaintext)
        val kotlin = seal(key, peer.publicKey)
        repeat(2) {
            assertContentEquals(plaintext, open(swift, key, peer.publicKey))
            assertContentEquals(plaintext, peer.open(kotlin, publicKey(key), info, aad).bytes("plaintext"))
        }
    }

    private data class Envelope(val encapsulation: ByteArray, val ciphertext: ByteArray)
    private fun seal(sender: AsymmetricCipherKeyPair, recipient: ByteArray, payload: ByteArray = plaintext): Envelope {
        val context = hpke().setupAuthS(hpke().deserializePublicKey(recipient), info, sender)
        return Envelope(context.encapsulation, context.seal(aad, payload))
    }
    private fun open(envelope: Envelope, recipient: AsymmetricCipherKeyPair, sender: ByteArray,
                     context: ByteArray = info, associated: ByteArray = aad): ByteArray =
        hpke().setupAuthR(envelope.encapsulation, recipient, context, hpke().deserializePublicKey(sender))
            .open(associated, envelope.ciphertext)

    private class Peer : Closeable {
        private val process = ProcessBuilder(requireNotNull(System.getProperty("remozio.test.hpkePeer")))
            .redirectError(ProcessBuilder.Redirect.INHERIT).start()
        private val input = process.inputStream.bufferedReader()
        private val output = process.outputStream.bufferedWriter()
        private val reader = Executors.newSingleThreadExecutor()
        val publicKey: ByteArray
        init {
            try { publicKey = receive().bytes("publicKey") }
            catch (failure: Throwable) { close(); throw failure }
        }
        fun seal(recipient: ByteArray, info: ByteArray, aad: ByteArray, plaintext: ByteArray): Envelope {
            val response = exchange("seal", recipient, info, aad, plaintext)
            return Envelope(response.bytes("encapsulation"), response.bytes("ciphertext"))
        }
        fun open(envelope: Envelope, sender: ByteArray, info: ByteArray, aad: ByteArray) =
            exchange("open", sender, info, aad, envelope.ciphertext, envelope.encapsulation)
        private fun exchange(command: String, peer: ByteArray, info: ByteArray, aad: ByteArray,
                             payload: ByteArray, encapsulation: ByteArray? = null): JsonObject {
            val value = buildJsonObject {
                put("command", command)
                put("peer", encode(peer)); put("info", encode(info)); put("aad", encode(aad)); put("payload", encode(payload))
                encapsulation?.let { put("encapsulation", encode(it)) }
            }
            output.write(value.toString()); output.newLine(); output.flush()
            return receive()
        }
        private fun receive(): JsonObject = reader.submit<JsonObject> {
            Json.parseToJsonElement(requireNotNull(input.readLine()) { "HPKE peer closed stdout" }).jsonObject
        }.get(15, TimeUnit.SECONDS)
        override fun close() {
            process.destroyForcibly()
            process.waitFor(5, TimeUnit.SECONDS)
            reader.shutdownNow()
            input.close(); output.close()
        }
        private fun encode(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)
    }
}

private fun JsonObject.bytes(name: String): ByteArray =
    Base64.getDecoder().decode(getValue(name).jsonPrimitive.content)
