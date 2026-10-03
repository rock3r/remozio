package dev.remozio.android.audit

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.AtomicFile
import dev.remozio.android.storage.ExclusiveFileOwner
import dev.remozio.phone.audit.*
import dev.remozio.protocol.CborLimits
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/** Blocking I/O. The enrollment owner calls this off the main thread and closes the cache when it is retired. */
internal object AndroidAuditCache {
    fun open(context: Context, binding: AuditCacheBinding, protocol: AuditPageLimits,
             capacity: AuditEvidenceLimits, archiveLimits: CborLimits): EncryptedAuditCache {
        val identity = MessageDigest.getInstance("SHA-256").digest(binding.macID + binding.accountID)
            .joinToString("") { "%02x".format(it) }
        val directory = File(context.noBackupFilesDir, "audit")
        if (!directory.isDirectory && !directory.mkdirs()) throw IOException("Audit directory unavailable")
        val storage = AndroidAuditStorage(File(directory, "$identity.cache"))
        try {
            val key = AuditCacheKey.load("remozio.audit-cache.v1.$identity", allowCreation = !storage.hasArchive())
            return EncryptedAuditCache.open(storage, AuditArchiveCipher(key, archiveLimits.maxBytes), binding,
                protocol, capacity, archiveLimits)
        } catch (failure: Throwable) {
            storage.close()
            throw failure
        }
    }
}

/** One process-wide key operation at a time. Existing aliases are never overwritten or silently repaired. */
private object AuditCacheKey {
    @Synchronized
    fun load(alias: String, allowCreation: Boolean): SecretKey {
        fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!store().containsAlias(alias)) {
            check(allowCreation) { "Audit encryption key unavailable" }
            try { generate(alias, strongBox = true) }
            catch (_: StrongBoxUnavailableException) {
                if (!store().containsAlias(alias)) generate(alias, strongBox = false)
            }
        }
        val key = checkNotNull(store().getKey(alias, null) as? SecretKey) { "Audit encryption key unavailable" }
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
        check(key.algorithm == KeyProperties.KEY_ALGORITHM_AES && key.encoded == null && info.keySize == 256)
        check(info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX || info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT)
        check(info.purposes == (KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT))
        check(info.blockModes.toSet() == setOf(KeyProperties.BLOCK_MODE_GCM))
        check(info.encryptionPaddings.toSet() == setOf(KeyProperties.ENCRYPTION_PADDING_NONE))
        check(!info.isUserAuthenticationRequired && !info.isUnlockedDeviceRequired)
        return key
    }

    private fun generate(alias: String, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(false)
            .setUnlockedDeviceRequired(false)
            .setIsStrongBoxBacked(strongBox)
            .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }.generateKey()
    }
}

/** Holds an OS file lock for the whole cache lifetime. AtomicFile itself provides no mutual exclusion. */
private class AndroidAuditStorage(private val base: File) : AuditCiphertextStorage {
    private val owner = ExclusiveFileOwner.acquire(File(base.path + ".lock"))
    private val atomic = AtomicFile(base)
    private var closed = false

    @Synchronized
    fun hasArchive(): Boolean = listOf(base, File(base.path + ".bak"), File(base.path + ".new")).any { it.exists() }

    @Synchronized
    override fun read(maximumBytes: Int): ByteArray? {
        check(!closed)
        require(maximumBytes > 0)
        val input = try { atomic.openRead() } catch (failure: FileNotFoundException) {
            if (!base.exists() && !File(base.path + ".bak").exists()) return null
            throw failure
        }
        return input.use {
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val count = it.read(buffer)
                if (count < 0) break
                if (count > maximumBytes - output.size()) throw IOException("Audit cache exceeds configured size")
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
    }

    @Synchronized
    override fun replace(ciphertext: ByteArray) {
        check(!closed)
        val output = atomic.startWrite()
        try {
            output.write(ciphertext)
            output.fd.sync()
            atomic.finishWrite(output)
        } catch (failure: Throwable) {
            atomic.failWrite(output)
            throw failure
        }
        if (read(ciphertext.size)?.contentEquals(ciphertext) != true) throw IOException("Audit cache replacement was not verified")
    }

    @Synchronized
    override fun close() {
        if (!closed) {
            closed = true
            owner.close()
        }
    }
}
