package dev.remozio.android.biometrics

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.WorkerThread
import dev.remozio.android.decisions.decisionPublicPoint
import dev.remozio.android.storage.ExclusiveFileOwner
import dev.remozio.phone.enrollment.EnrollmentKeyReference
import dev.remozio.phone.enrollment.EnrollmentKeyRole
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/** Fresh local keys only. The authorized enrollment flow must persist and register the returned reference. */
object AndroidBiometricKeyCreation {
    @WorkerThread
    fun create(context: Context): EnrollmentKeyReference {
        try {
            val directory = File(context.noBackupFilesDir, "biometrics")
            check(directory.isDirectory || directory.mkdirs())
            ExclusiveFileOwner.acquire(File(directory, "creation.lock")).use {
                val id = ByteArray(16).also(SecureRandom()::nextBytes)
                val alias = "remozio.biometric.v1." + id.joinToString("") { "%02x".format(it) }
                val point = createBiometricKey(PlatformBiometricKeys, alias)
                val reference = EnrollmentKeyReference(EnrollmentKeyRole.BIOMETRIC, id, alias, point)
                loadBiometricKey(reference)
                return reference
            }
        } catch (_: Exception) { throw BiometricIdentityUnavailable() }
    }
}

internal class BiometricStrongBoxUnavailable : Exception()
internal interface BiometricKeyCreationBackend {
    fun contains(alias: String): Boolean
    fun generate(alias: String, strongBox: Boolean): ByteArray
}

/** The caller holds the creation lock through generation and the subsequent custody check. */
internal fun createBiometricKey(backend: BiometricKeyCreationBackend, alias: String): ByteArray {
    require(Regex("remozio\\.biometric\\.v1\\.[0-9a-f]{32}").matches(alias))
    check(!backend.contains(alias))
    return try { backend.generate(alias, true) }
    catch (_: BiometricStrongBoxUnavailable) {
        check(!backend.contains(alias))
        backend.generate(alias, false)
    }
}

private object PlatformBiometricKeys : BiometricKeyCreationBackend {
    override fun contains(alias: String) = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(alias)
    override fun generate(alias: String, strongBox: Boolean): ByteArray {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(false)
            .setUserConfirmationRequired(false)
            .setUserPresenceRequired(false)
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()
        try {
            val pair = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                .apply { initialize(spec) }.generateKeyPair()
            return decisionPublicPoint(pair.public as ECPublicKey)
        } catch (_: StrongBoxUnavailableException) { throw BiometricStrongBoxUnavailable() }
    }
}
