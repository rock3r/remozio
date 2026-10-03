package dev.remozio.protocol

import java.util.Collections

enum class CommandCaptureFailure { FIELDS, TYPE, VERSION, BYTES, PATH, ENVIRONMENT, ENUMERATION, ANCESTRY }
class CommandCaptureException(val reason: CommandCaptureFailure) : IllegalArgumentException(reason.name)

interface CommandWireTag { val wireValue: ULong }
data class CapturedFileIdentity(val device: ULong, val inode: ULong)
data class CapturedExecutable(val path: CborValue.Bytes, val identity: CapturedFileIdentity, val sha256: CborValue.Bytes)
data class CapturedDirectory(val path: CborValue.Bytes, val identity: CapturedFileIdentity)
data class CommandTarget(val uid: UInt, val gid: UInt, val supplementaryGroups: List<UInt>, val observedName: String?)
enum class EnvironmentSource(override val wireValue: ULong) : CommandWireTag { MINIMAL(0u), REQUESTED(1u) }
data class CapturedEnvironmentEntry(val name: CborValue.Bytes, val value: CborValue.Bytes, val source: EnvironmentSource)
enum class CommandInputKind(override val wireValue: ULong) : CommandWireTag { NULL(0u), PIPE(1u), FILE(2u), TTY(3u), PTY(4u) }
data class CapturedCommandInput(val kind: CommandInputKind, val streamBinding: CborValue.Bytes?, val observedPath: CborValue.Bytes?, val identity: CapturedFileIdentity?)
enum class CommandIOMode(override val wireValue: ULong) : CommandWireTag { PIPES(0u), PTY(1u) }
enum class StartedCommandDisconnect(override val wireValue: ULong) : CommandWireTag { TERMINATE(0u), CONTINUE_RUNNING(1u) }
enum class CapturedSigningStatus(override val wireValue: ULong) : CommandWireTag { UNSIGNED(0u), AD_HOC(1u), VALIDATED(2u), INVALID(3u), UNAVAILABLE(4u) }
data class CapturedSigningIdentity(val status: CapturedSigningStatus, val identifier: String?, val team: String?, val cdHash: CborValue.Bytes?)
data class CapturedRequester(val executablePath: CborValue.Bytes, val realUID: UInt, val effectiveUID: UInt, val pid: UInt,
    val pidVersion: UInt, val signing: CapturedSigningIdentity, val sessionID: UInt?, val ttyPath: CborValue.Bytes?)
enum class AncestryCompleteness(override val wireValue: ULong) : CommandWireTag { COMPLETE(0u), PARTIAL(1u), UNAVAILABLE(2u) }
enum class AncestryReason(override val wireValue: ULong) : CommandWireTag { NONE(0u), EXITED(1u), PERMISSION(2u), TRUNCATED(3u), UNSUPPORTED(4u) }
data class CapturedAncestor(val pid: UInt, val pidVersion: UInt, val executablePath: CborValue.Bytes?, val uid: UInt)
data class CapturedAncestry(val completeness: AncestryCompleteness, val entries: List<CapturedAncestor>, val reason: AncestryReason)
data class CapturedSubmission(val id: CborValue.Bytes, val nonce: CborValue.Bytes, val callerBinding: CborValue.Bytes)

/** Parses claims only. OS capture, authenticated issuance, and execution are separate responsibilities. */
class CommandCapture(canonicalBytes: ByteArray, limits: CborLimits) {
    private val original: CborValue.Bytes
    val canonicalBytes: ByteArray get() = original.copyBytes()
    val canonicalByteCount: Int get() = original.size
    val executable: CapturedExecutable
    val arguments: List<CborValue.Bytes>
    val directory: CapturedDirectory
    val target: CommandTarget
    val environment: List<CapturedEnvironmentEntry>
    val input: CapturedCommandInput
    val ioMode: CommandIOMode
    val disconnectBehavior: StartedCommandDisconnect
    val requester: CapturedRequester
    val ancestry: CapturedAncestry
    val unverifiedRationale: String?
    val submission: CapturedSubmission

    init {
        // Bound input before retaining another copy.
        if (canonicalBytes.size > limits.maxBytes) throw CborException(CborFailure.BYTE_LIMIT)
        original = CborValue.Bytes(canonicalBytes)
        val root = CaptureFields(DeterministicCbor.decode(original.copyBytes(), limits), 13)
        ensure(root.uint(0u) == 1uL, CommandCaptureFailure.VERSION)
        val executable = CaptureFields(root[1u], 3)
        this.executable = CapturedExecutable(executable.path(0u), executable.identity(1u), executable.bytes(2u, 32))
        arguments = immutable(root.array(2u).map { CaptureFields.cString(it) })
        ensure(arguments.isNotEmpty(), CommandCaptureFailure.BYTES)
        val directory = CaptureFields(root[3u], 2)
        this.directory = CapturedDirectory(directory.path(0u), directory.identity(1u))
        val target = CaptureFields(root[4u], 4)
        this.target = CommandTarget(target.uint32(0u), target.uint32(1u),
            immutable(target.array(2u).map { CaptureFields.uint32(it) }), target.optionalText(3u))
        var previous: ByteArray? = null
        environment = immutable(root.array(5u).map { value ->
            val entry = CaptureFields(value, 3)
            val name = CaptureFields.cString(entry[0u])
            val bytes = name.copyBytes()
            ensure(bytes.isNotEmpty() && bytes.none { it == 0x3d.toByte() } &&
                (previous == null || lexicographicallyBefore(previous, bytes)), CommandCaptureFailure.ENVIRONMENT)
            previous = bytes
            CapturedEnvironmentEntry(name, CaptureFields.cString(entry[1u]), entry.tag(2u, EnvironmentSource.entries))
        })
        val input = CaptureFields(root[6u], 4)
        val kind = input.tag(0u, CommandInputKind.entries)
        val binding = input.optionalBytes(1u, 16)
        val path = input.optionalPath(2u)
        val identity = input.optionalIdentity(3u)
        if (kind == CommandInputKind.NULL) ensure(binding == null && path == null && identity == null, CommandCaptureFailure.FIELDS)
        else ensure(binding != null, CommandCaptureFailure.BYTES)
        this.input = CapturedCommandInput(kind, binding, path, identity)
        ioMode = root.tag(7u, CommandIOMode.entries)
        disconnectBehavior = root.tag(8u, StartedCommandDisconnect.entries)
        val requester = CaptureFields(root[9u], 8)
        val signing = CaptureFields(requester[5u], 4)
        this.requester = CapturedRequester(requester.path(0u), requester.uint32(1u), requester.uint32(2u), requester.pid(3u), requester.uint32(4u),
            CapturedSigningIdentity(signing.tag(0u, CapturedSigningStatus.entries), signing.optionalText(1u), signing.optionalText(2u), signing.optionalBytes(3u, 20)),
            requester.optionalUInt32(6u), requester.optionalPath(7u))
        val ancestry = CaptureFields(root[10u], 3)
        val completeness = ancestry.tag(0u, AncestryCompleteness.entries)
        val reason = ancestry.tag(2u, AncestryReason.entries)
        val entries = immutable(ancestry.array(1u).map { value ->
            val entry = CaptureFields(value, 4)
            CapturedAncestor(entry.pid(0u), entry.uint32(1u), entry.optionalPath(2u), entry.uint32(3u))
        })
        ensure((completeness == AncestryCompleteness.COMPLETE) == (reason == AncestryReason.NONE) &&
            (completeness != AncestryCompleteness.UNAVAILABLE || entries.isEmpty()), CommandCaptureFailure.ANCESTRY)
        this.ancestry = CapturedAncestry(completeness, entries, reason)
        unverifiedRationale = root.optionalText(11u)
        val submission = CaptureFields(root[12u], 3)
        this.submission = CapturedSubmission(submission.bytes(0u, 16), submission.bytes(1u, 32), submission.bytes(2u, 16))
    }
}

private fun <T> immutable(values: List<T>): List<T> = Collections.unmodifiableList(ArrayList(values))
private fun ensure(condition: Boolean, reason: CommandCaptureFailure) { if (!condition) throw CommandCaptureException(reason) }
private fun fail(reason: CommandCaptureFailure): Nothing = throw CommandCaptureException(reason)
private fun lexicographicallyBefore(left: ByteArray, right: ByteArray): Boolean {
    for (i in 0 until minOf(left.size, right.size)) {
        val a = left[i].toInt() and 255
        val b = right[i].toInt() and 255
        if (a != b) return a < b
    }
    return left.size < right.size
}
private class CaptureFields(value: CborValue, count: Int) {
    private val values = (value as? CborValue.Fields)?.values ?: fail(CommandCaptureFailure.FIELDS)
    init { ensure(values.keys == (0 until count).map { it.toULong() }.toSet(), CommandCaptureFailure.FIELDS) }
    operator fun get(field: ULong): CborValue = values.getValue(field)
    fun uint(field: ULong): ULong = (get(field) as? CborValue.Unsigned)?.value ?: fail(CommandCaptureFailure.TYPE)
    fun uint32(field: ULong): UInt = uint32(get(field))
    fun pid(field: ULong): UInt = uint32(field).also { ensure(it > 0u && it <= Int.MAX_VALUE.toUInt(), CommandCaptureFailure.TYPE) }
    fun optionalUInt32(field: ULong): UInt? = if (get(field) == CborValue.Null) null else uint32(field)
    fun <T: CommandWireTag> tag(field: ULong, values: List<T>): T = values.firstOrNull { it.wireValue == uint(field) } ?: fail(CommandCaptureFailure.ENUMERATION)
    fun array(field: ULong): List<CborValue> = (get(field) as? CborValue.ArrayValue)?.values ?: fail(CommandCaptureFailure.TYPE)
    fun bytes(field: ULong, count: Int): CborValue.Bytes = ((get(field) as? CborValue.Bytes)?.takeIf { it.size == count }) ?: fail(CommandCaptureFailure.BYTES)
    fun optionalBytes(field: ULong, count: Int): CborValue.Bytes? = if (get(field) == CborValue.Null) null else bytes(field, count)
    fun path(field: ULong): CborValue.Bytes = cString(get(field)).also { ensure(it.copyBytes().firstOrNull() == 0x2f.toByte(), CommandCaptureFailure.PATH) }
    fun optionalPath(field: ULong): CborValue.Bytes? = if (get(field) == CborValue.Null) null else path(field)
    fun optionalText(field: ULong): String? = if (get(field) == CborValue.Null) null else (get(field) as? CborValue.Text)?.value ?: fail(CommandCaptureFailure.TYPE)
    fun identity(field: ULong): CapturedFileIdentity = CaptureFields(get(field), 2).let { CapturedFileIdentity(it.uint(0u), it.uint(1u)) }
    fun optionalIdentity(field: ULong): CapturedFileIdentity? = if (get(field) == CborValue.Null) null else identity(field)
    companion object {
        fun uint32(value: CborValue): UInt {
            val number = (value as? CborValue.Unsigned)?.value ?: fail(CommandCaptureFailure.TYPE)
            ensure(number <= UInt.MAX_VALUE.toULong(), CommandCaptureFailure.TYPE)
            return number.toUInt()
        }
        fun cString(value: CborValue): CborValue.Bytes {
            val bytes = value as? CborValue.Bytes ?: fail(CommandCaptureFailure.BYTES)
            ensure(bytes.copyBytes().none { it == 0.toByte() }, CommandCaptureFailure.BYTES)
            return bytes
        }
    }
}
