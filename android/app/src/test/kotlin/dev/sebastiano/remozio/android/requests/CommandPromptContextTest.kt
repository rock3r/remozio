package dev.sebastiano.remozio.android.requests

import dev.remozio.protocol.CborValue
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import org.junit.Test

class CommandPromptContextTest {
    private val digest = CborValue.Bytes(ByteArray(32) { it.toByte() })

    @Test fun usesTheAuthenticatedLabelsAndOnlyTheExecutableBasename() {
        val context = context(path = "/private/user/tools/rsync")
        val labels = assertNotNull(context.labels)
        assertEquals("\"Mac mini\"", labels.host)
        assertEquals("\"Account 12345678\"", labels.account)
        assertEquals("\"rsync\"", labels.executable)
        assertEquals("000102030405", context.reference)
    }

    @Test fun escapesBidiControlsConfusablesAndQuotes() {
        val labels = assertNotNull(context(host = "Mac\u202E\n", path = "/usr/bin/\u0441at\"\\").labels)
        assertEquals("\"Mac\\u{202e}\\u{a}\"", labels.host)
        assertEquals("\"\\u{441}at\\\"\\\\\"", labels.executable)
    }

    @Test fun escapesSupplementaryCodePointsWithoutSplittingThem() {
        val labels = assertNotNull(context(host = "Mac \uD83D\uDD12").labels)
        assertEquals("\"Mac \\u{1f512}\"", labels.host)
    }

    @Test fun keepsTheReferenceWhenALabelWouldNeedTruncation() {
        assertNotNull(context(host = "x".repeat(34)).labels)
        for (host in listOf("x".repeat(35), "x".repeat(33) + "\u202E")) {
            val context = context(host = host)
            assertNull(context.labels)
            assertEquals("000102030405", context.reference)
        }
    }

    @Test fun usesOnlyTheReferenceForMissingOrUndecodableNames() {
        val invalidPath = byteArrayOf('/'.code.toByte(), 0xff.toByte())
        assertNull(context(path = "/usr/bin/").labels)
        assertNull(context(host = "   ").labels)
        assertNull(CommandPromptContext.create(digest, "Mac", "Account", invalidPath).labels)
    }

    @Test fun identicalVisibleLabelsRetainDistinctRequestReferences() {
        val first = context()
        val next = CommandPromptContext.create(CborValue.Bytes(ByteArray(32) { 0x11 }), "Mac mini",
            "Account 12345678", "/usr/bin/true".encodeToByteArray())
        assertEquals(first.labels?.executable, next.labels?.executable)
        assertNotEquals(first.reference, next.reference)
    }

    private fun context(host: String = "Mac mini", path: String = "/usr/bin/true") =
        CommandPromptContext.create(digest, host, "Account 12345678", path.encodeToByteArray())
}
