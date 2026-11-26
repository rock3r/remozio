package dev.sebastiano.remozio.android.transport

import android.content.Context
import android.util.AtomicFile
import androidx.annotation.WorkerThread
import dev.sebastiano.remozio.android.storage.ExclusiveFileOwner
import java.io.File
import java.io.FileNotFoundException
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Date

/** Stores a public certificate only. The original certificate and private key stay in Android Keystore. */
internal object AndroidTransportLeaves {
    private val transportAlias = Regex("remozio\\.transport\\.v1\\.[0-9a-f]{32}")

    @WorkerThread
    @Synchronized
    fun load(context: Context, alias: String, key: PrivateKey, chain: Array<X509Certificate>): Array<X509Certificate> {
        require(transportAlias.matches(alias))
        val now = Instant.now()
        val original = chain.first()
        return try {
            val directory = directory(context)
            check(directory.isDirectory || directory.mkdirs() || directory.isDirectory)
            ExclusiveFileOwner.acquire(File(directory, "renewal.lock")).use {
                val file = AtomicFile(File(directory, "$alias.der"))
                selectTransportLeaf(chain, original.publicKey, now,
                    read = {
                        try { file.openRead().use { it.readNBytes(TRANSPORT_LEAF_MAX_BYTES + 1) } }
                        catch (_: FileNotFoundException) { null }
                    },
                    issue = { issueTransportLeaf(key, original.publicKey, now) },
                    write = { bytes ->
                        val output = file.startWrite()
                        try {
                            output.write(bytes)
                            output.fd.sync()
                            file.finishWrite(output)
                        } catch (failure: Exception) {
                            file.failWrite(output)
                            throw failure
                        }
                    })
            }
        } catch (_: Exception) {
            original.checkValidity(Date.from(now))
            chain
        }
    }

    @WorkerThread
    @Synchronized
    fun hasArtifacts(context: Context, alias: String): Boolean {
        if (!transportAlias.matches(alias)) return false
        val base = File(directory(context), "$alias.der")
        return base.exists() || File("${base.path}.new").exists() || File("${base.path}.bak").exists()
    }

    @WorkerThread
    @Synchronized
    fun retire(context: Context, alias: String) {
        if (!transportAlias.matches(alias)) return
        val directory = directory(context)
        if (!directory.isDirectory) return
        ExclusiveFileOwner.acquire(File(directory, "renewal.lock")).use {
            AtomicFile(File(directory, "$alias.der")).delete()
        }
    }

    private fun directory(context: Context) = File(context.noBackupFilesDir, "transport-leaves")
}
