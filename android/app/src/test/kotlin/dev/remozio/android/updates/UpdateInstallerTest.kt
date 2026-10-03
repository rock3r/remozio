package dev.remozio.android.updates

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.OutputStream
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking

class UpdateInstallerTest {
    private fun identity(version: Long) = ApkIdentity("dev.remozio.android", version, "test",
        setOf("key"), listOf("key"), 37, 37)

    private class Session(private val events: MutableList<String>) : UpdateInstallSession {
        override val id = 42
        val bytes = ByteArrayOutputStream()
        var failAt: String? = null
        var onWrite: () -> Unit = {}
        private fun event(name: String) {
            events += name
            if (failAt == name) throw IOException("injected failure")
        }
        override fun openWrite(size: Long): OutputStream {
            event("open:$size")
            return object : OutputStream() {
                override fun write(value: Int) { event("write"); onWrite(); bytes.write(value) }
                override fun write(value: ByteArray, offset: Int, length: Int) {
                    event("write"); onWrite(); bytes.write(value, offset, length)
                }
                override fun close() = event("streamClose")
            }
        }
        override fun fsync(output: OutputStream) = event("fsync")
        override fun commit() = event("commit")
        override fun abandon() = event("abandon")
        override fun close() = event("sessionClose")
    }

    private inner class Fixture(val cache: File) {
        val events = mutableListOf<String>()
        val session = Session(events)
        var file: File? = null
        var allowed = true
        var installedVersion = 1L
        var beforeInstalledRead: () -> Unit = {}
        val commits = mutableListOf<InstallAttempt>()
        var record: (InstallAttempt) -> Unit = { events += "record"; commits += it }
        val verifier = StagedApkVerifier(cache, object : ApkInspector {
            override fun installed() = identity(1)
            override fun verify(file: File): ApkIdentity { this@Fixture.file = file; return identity(2) }
        }, 37, 64L * 1024)
        val backend = object : UpdateInstallBackend {
            override fun canRequestInstallation() = allowed
            override fun installed(): ApkIdentity { beforeInstalledRead(); return identity(installedVersion) }
            override fun create(identity: ApkIdentity, size: Long): UpdateInstallSession {
                events += "create"
                return session
            }
        }
        val installer = UpdateInstaller(backend, 37) { record(it) }
        suspend fun apk(bytes: ByteArray = byteArrayOf(1, 2, 3)) = verifier.stage(ByteArrayInputStream(bytes))
    }

    private fun fixture(block: suspend Fixture.() -> Unit) {
        val cache = Files.createTempDirectory("remozio-installer-test-").toFile()
        try { runBlocking { Fixture(cache).block() } } finally { cache.deleteRecursively() }
    }

    @Test fun writesVerifiesFlushesClosesAndRecordsBeforeCommit() = fixture {
        val result = installer.submit(apk())
        assertEquals(InstallSubmissionState.REQUESTED, result.state)
        assertEquals(InstallAttempt(42, "dev.remozio.android", 2), result.attempt)
        assertEquals(listOf("create", "open:3", "write", "fsync", "streamClose", "record", "commit", "sessionClose"), events)
        assertEquals(listOf(result.attempt), commits)
        assertContentEquals(byteArrayOf(1, 2, 3), session.bytes.toByteArray())
        assertTrue(cache.listFiles()!!.isEmpty())
    }

    @Test fun permissionFailureRetainsTheVerifiedFileForSettingsRoundTrip() = fixture {
        val staged = apk()
        allowed = false
        assertFailsWith<InstallPermissionRequired> { installer.submit(staged) }
        assertTrue(file!!.exists())
        assertTrue(events.isEmpty())
        allowed = true
        assertEquals(InstallSubmissionState.REQUESTED, installer.submit(staged).state)
    }

    @Test fun staleVersionBeforePreparationCreatesNoSession() = fixture {
        val staged = apk()
        installedVersion = 2
        assertFailsWith<UpdateRejected> { installer.submit(staged) }
        assertTrue(events.isEmpty())
        assertTrue(commits.isEmpty())
        assertTrue(cache.listFiles()!!.isEmpty())
    }

    @Test fun changedInstalledVersionDuringCopyPreventsCommit() = fixture {
        session.onWrite = { installedVersion = 2 }
        assertFailsWith<UpdateRejected> { installer.submit(apk()) }
        assertTrue("abandon" in events)
        assertFalse("commit" in events)
        assertTrue(commits.isEmpty())
    }

    @Test fun changedApkBytesAbandonThePartialInstallerSession() = fixture {
        val staged = apk()
        file!!.apply { setWritable(true); writeBytes(byteArrayOf(9, 9, 9)) }
        assertFailsWith<UpdateRejected> { installer.submit(staged) }
        assertTrue("abandon" in events)
        assertFalse("fsync" in events)
        assertFalse("commit" in events)
        assertTrue(commits.isEmpty())
        assertTrue(cache.listFiles()!!.isEmpty())
    }

    @Test fun writeFlushAndStreamCloseFailuresCannotReachCommit() {
        for (failure in listOf("open:3", "write", "fsync", "streamClose")) fixture {
            session.failAt = failure
            assertFailsWith<UpdateRejected> { installer.submit(apk()) }
            assertTrue("abandon" in events, failure)
            assertTrue("sessionClose" in events, failure)
            assertFalse("commit" in events, failure)
            assertTrue(commits.isEmpty(), failure)
            assertTrue(cache.listFiles()!!.isEmpty(), failure)
        }
    }

    @Test fun failedDurableRecordPreventsCommitAndAbandonsSession() = fixture {
        record = { throw IOException("disk full") }
        assertFailsWith<UpdateRejected> { installer.submit(apk()) }
        assertTrue("abandon" in events)
        assertFalse("commit" in events)
    }

    @Test fun lostCommitReplyReturnsUnknownAndDoesNotAbandonOrRetry() = fixture {
        session.failAt = "commit"
        val result = installer.submit(apk())
        assertEquals(InstallSubmissionState.UNKNOWN, result.state)
        assertEquals(1, commits.size)
        assertEquals(1, events.count { it == "commit" })
        assertFalse("abandon" in events)
        assertTrue("sessionClose" in events)
        assertTrue(cache.listFiles()!!.isEmpty())
    }

    @Test fun closeFailureAfterCommitDoesNotInventInstallFailure() = fixture {
        session.failAt = "sessionClose"
        assertEquals(InstallSubmissionState.REQUESTED, installer.submit(apk()).state)
        assertFalse("abandon" in events)
        assertEquals(1, commits.size)
    }

    @Test fun cancellationDuringCopyAbandonsWithoutACommitIntent() = fixture {
        val staged = apk(ByteArray(40_000))
        assertFailsWith<CancellationException> {
            coroutineScope {
                session.onWrite = { cancel() }
                installer.submit(staged)
            }
        }
        assertTrue("abandon" in events)
        assertFalse("commit" in events)
        assertTrue(commits.isEmpty())
        assertTrue(cache.listFiles()!!.isEmpty())
    }

    @Test fun cancellationBeforeSubmissionRetainsTheHandle() = fixture {
        val staged = apk()
        assertFailsWith<CancellationException> { coroutineScope { cancel(); installer.submit(staged) } }
        assertTrue(file!!.exists())
        assertTrue(events.isEmpty())
        staged.close()
    }
    @Test fun cancellationAfterRecordingStillPreventsCommit() = fixture {
        val staged = apk()
        assertFailsWith<CancellationException> {
            coroutineScope {
                record = { commits += it; cancel() }
                installer.submit(staged)
            }
        }
        assertEquals(1, commits.size)
        assertFalse("commit" in events)
        assertTrue("abandon" in events)
    }

    @Test fun concurrentSubmissionRetainsTheRejectedHandle() = fixture {
        val first = apk()
        val otherVerifier = StagedApkVerifier(cache, object : ApkInspector {
            override fun installed() = identity(1)
            override fun verify(file: File) = identity(2)
        }, 37, 8)
        val second = otherVerifier.stage(ByteArrayInputStream(byteArrayOf(4)))
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        beforeInstalledRead = { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)) }
        coroutineScope {
            val running = async(kotlinx.coroutines.Dispatchers.Default) { installer.submit(first) }
            try {
                assertTrue(entered.await(5, TimeUnit.SECONDS))
                assertFailsWith<UpdateRejected> { installer.submit(second) }
                val retained = ByteArrayOutputStream()
                second.copyToUncommittedSession(retained)
                assertContentEquals(byteArrayOf(4), retained.toByteArray())
            } finally {
                release.countDown()
                second.close()
            }
            assertEquals(InstallSubmissionState.REQUESTED, running.await().state)
        }
    }

}
