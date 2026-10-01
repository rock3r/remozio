package dev.remozio.protocol

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class CommandCaptureTest {
    private val limits = CborLimits(8192, 16, 1024)
    private fun vectors() = Json.parseToJsonElement(File(checkNotNull(System.getProperty("remozio.commandVectors"))).readText()).jsonObject
    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun first() = hex(vectors().getValue("valid").jsonArray[0].jsonObject.getValue("hex").jsonPrimitive.content)
    @Test fun sharedCapturesPreserveExactBytesAndProvenance() {
        val rows = vectors().getValue("valid").jsonArray
        assertEquals(9, rows.size)
        for (row in rows) {
            val fields = row.jsonObject
            val bytes = hex(fields.getValue("hex").jsonPrimitive.content)
            val capture = CommandCapture(bytes, limits)
            assertContentEquals(bytes, capture.canonicalBytes)
            assertEquals(fields.getValue("arguments").jsonArray.map { CborValue.Bytes(hex(it.jsonPrimitive.content)) }, capture.arguments)
            assertEquals(fields.getValue("environmentNames").jsonArray.map { CborValue.Bytes(hex(it.jsonPrimitive.content)) }, capture.environment.map { it.name })
            assertEquals(fields.getValue("inputKind").jsonPrimitive.content.toULong(), capture.input.kind.wireValue)
            assertEquals(fields.getValue("signingStatus").jsonPrimitive.content.toULong(), capture.requester.signing.status.wireValue)
            assertEquals(fields.getValue("ancestry").jsonPrimitive.content.toULong(), capture.ancestry.completeness.wireValue)
            assertEquals(fields.getValue("rationale").jsonPrimitive.contentOrNull, capture.unverifiedRationale)
        }
        val capture = CommandCapture(first(), limits)
        assertContentEquals("/usr/bin/printf".encodeToByteArray(), capture.executable.path.copyBytes())
        assertEquals(100uL, capture.executable.identity.inode)
        assertContentEquals(ByteArray(32) { it.toByte() }, capture.executable.sha256.copyBytes())
        assertEquals(101uL, capture.directory.identity.inode)
        assertEquals(listOf(0u, 80u), capture.target.supplementaryGroups)
        assertEquals("root", capture.target.observedName)
        assertEquals(EnvironmentSource.REQUESTED, capture.environment.last().source)
        assertContentEquals(byteArrayOf(0xff.toByte(), 0x0a), capture.environment.last().value.copyBytes())
        assertEquals(4321u, capture.requester.pid)
        assertEquals(7u, capture.requester.pidVersion)
        assertEquals(501u, capture.requester.realUID)
        assertEquals("EXAMPLE", capture.requester.signing.team)
        assertEquals(AncestryReason.EXITED, capture.ancestry.reason)
        assertContentEquals("/bin/zsh".encodeToByteArray(), capture.ancestry.entries[0].executablePath!!.copyBytes())
        assertContentEquals(ByteArray(32) { 2 }, capture.submission.nonce.copyBytes())
        assertContentEquals(ByteArray(16) { 3 }, capture.submission.callerBinding.copyBytes())
    }
    @Test fun sharedInvalidCapturesFail() {
        val rows = vectors().getValue("invalid").jsonArray
        assertEquals(86, rows.size)
        for (row in rows) {
            val fields = row.jsonObject
            assertFailsWith<IllegalArgumentException>(fields.getValue("name").jsonPrimitive.content) {
                CommandCapture(hex(fields.getValue("hex").jsonPrimitive.content), limits)
            }
        }
    }
    @Test fun boundsAndImmutableSnapshots() {
        val bytes = first()
        val original = bytes.copyOf()
        val capture = CommandCapture(bytes, limits)
        bytes[0] = 0
        capture.canonicalBytes[0] = 0
        capture.arguments[0].copyBytes()[0] = 0
        assertContentEquals(original, capture.canonicalBytes)
        assertContentEquals("printf".encodeToByteArray(), capture.arguments[0].copyBytes())
        assertFailsWith<UnsupportedOperationException> { (capture.arguments as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (capture.environment as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (capture.target.supplementaryGroups as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (capture.ancestry.entries as MutableList).clear() }
        for (bound in listOf(CborLimits(original.size - 1, 16, 1024), CborLimits(8192, 1, 1024), CborLimits(8192, 16, 2))) {
            assertFailsWith<CborException> { CommandCapture(original, bound) }
        }
    }
    @Test fun issuedRequestPreservesCompleteCapture() {
        val bytes = first()
        val contract = RequestContract(RequestKind.COMMAND, 1u, 1u)
        val issued = IssuedRequestPayload(contract, ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 },
            ByteArray(32) { 4 }, emptySet(), 10u, 20u, bytes,
            listOf(CapturedAction(ActionChoice.EXECUTE, ActionScope.CurrentRequest)), limits, limits)
        val decoded = IssuedRequestPayload.decode(issued.encode(limits), limits, limits, ContractCapabilities(mapOf(contract to emptySet())))
        assertContentEquals(bytes, CommandCapture(decoded.canonicalCapture, limits).canonicalBytes)
        assertContentEquals(issued.requestDigest(limits, limits), decoded.requestDigest(limits, limits))
    }
}
