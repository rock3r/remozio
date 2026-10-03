package dev.remozio.android.enrollment

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.system.Os
import android.system.OsConstants
import android.util.AtomicFile
import androidx.annotation.WorkerThread
import dev.remozio.phone.enrollment.*
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.io.RandomAccessFile
import java.nio.channels.FileLock
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/** One exclusive owner. Invoke off the main thread and close when the enrollment host stops. */
internal object AndroidEnrollmentStore {
    private const val KEY_ALIAS = "remozio.enrollment-storage.v1"

    @WorkerThread
    fun open(context: Context, maximumRecords: Int, maximumPlaintextBytes: Int): EncryptedEnrollmentStore {
        EncryptedEnrollmentStore.validateConfiguration(maximumRecords, maximumPlaintextBytes)
        val app = context.applicationContext
        check(!app.isDeviceProtectedStorage)
        val directory = File(app.noBackupFilesDir, "enrollments")
        if (!directory.isDirectory) {
            check(directory.mkdirs())
            syncDirectory(app.noBackupFilesDir)
        }
        val storage = EnrollmentFile(File(directory, "state"))
        try {
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val existingKey = store.containsAlias(KEY_ALIAS)
            val existingArchive = storage.hasArchive()
            if (!existingKey && existingArchive) throw EnrollmentStoreUnavailable()
            if (!existingKey) {
                try { generate(strongBox = true) }
                catch (_: StrongBoxUnavailableException) {
                    check(!store.containsAlias(KEY_ALIAS))
                    generate(strongBox = false)
                }
            }
            val key = store.getKey(KEY_ALIAS, null) as? SecretKey ?: throw EnrollmentStoreUnavailable()
            val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
            check(key.algorithm == KeyProperties.KEY_ALGORITHM_AES && key.encoded == null && key.format == null)
            check(info.keystoreAlias == KEY_ALIAS && info.origin == KeyProperties.ORIGIN_GENERATED && info.keySize == 256)
            check(info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX || info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT)
            check(info.purposes == (KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT))
            check(info.blockModes.toSet() == setOf(KeyProperties.BLOCK_MODE_GCM))
            check(info.encryptionPaddings.toSet() == setOf(KeyProperties.ENCRYPTION_PADDING_NONE))
            check(!info.isUserAuthenticationRequired && !info.isUnlockedDeviceRequired)
            val cipher = EnrollmentCipher(key, maximumPlaintextBytes)
            return if (existingKey) EncryptedEnrollmentStore.open(storage, cipher, maximumRecords)
                else EncryptedEnrollmentStore.create(storage, cipher, maximumRecords)
        } catch (_: Exception) { storage.close(); throw EnrollmentStoreUnavailable() }
    }

    private fun generate(strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true).setIsStrongBoxBacked(strongBox)
            .setUserAuthenticationRequired(false).setUnlockedDeviceRequired(false).build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }.generateKey()
    }
}

private class EnrollmentFile(private val file: File) : EnrollmentStorage {
    private val processLease = EnrollmentFileOwners.acquire(file.canonicalPath)
    private val lockFile: RandomAccessFile
    private val lock: FileLock
    private val atomic = AtomicFile(file)
    private var closed = false
    init {
        var opened: RandomAccessFile? = null
        try {
            val channelOwner = RandomAccessFile(File(file.path + ".lock"), "rw")
            opened = channelOwner
            lock = channelOwner.channel.tryLock() ?: throw EnrollmentStoreUnavailable()
            lockFile = channelOwner
        } catch (failure: Exception) {
            try { opened?.close() } finally { processLease.close() }
            throw failure
        }
    }
    fun hasArchive() = listOf(file, File(file.path + ".bak"), File(file.path + ".new")).any { it.exists() }
    @Synchronized override fun read(maximumBytes: Int): ByteArray? {
        check(!closed && maximumBytes > 0)
        val input = try { atomic.openRead() } catch (failure: FileNotFoundException) {
            if (!file.exists() && !File(file.path + ".bak").exists()) return null
            throw failure
        }
        return input.use {
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val count = it.read(buffer)
                if (count < 0) break
                check(count <= maximumBytes - output.size())
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
    }
    @Synchronized override fun replace(ciphertext: ByteArray) {
        check(!closed)
        val output = atomic.startWrite()
        try { output.write(ciphertext); output.fd.sync(); atomic.finishWrite(output) }
        catch (failure: Exception) { atomic.failWrite(output); throw failure }
        syncDirectory(requireNotNull(file.parentFile))
        check(read(ciphertext.size)?.contentEquals(ciphertext) == true)
    }
    @Synchronized override fun close() {
        if (!closed) {
            closed = true
            try { lock.release() } finally { try { lockFile.close() } finally { processLease.close() } }
        }
    }
}

private fun syncDirectory(directory: File) {
    val descriptor = Os.open(directory.path, OsConstants.O_RDONLY or OsConstants.O_CLOEXEC, 0)
    try { check(OsConstants.S_ISDIR(Os.fstat(descriptor).st_mode)); Os.fsync(descriptor) } finally { Os.close(descriptor) }
}
