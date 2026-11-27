package dev.sebastiano.remozio.android.requests

import dev.remozio.protocol.CborValue
import java.nio.charset.CharacterCodingException

/** Presentation for one authenticated request. The reference also appears in the inspector. */
internal class CommandPromptContext private constructor(
    val reference: String,
    val labels: Labels?,
) {
    class Labels(val host: String, val account: String, val executable: String)

    companion object {
        private const val LABEL_LIMIT = 36

        fun create(requestDigest: CborValue.Bytes, host: String, account: String, executablePath: ByteArray): CommandPromptContext {
            val reference = commandIdentityText(requestDigest).take(12)
            val nameStart = executablePath.lastIndexOf('/'.code.toByte()) + 1
            val executable = try {
                executablePath.decodeToString(startIndex = nameStart, throwOnInvalidSequence = true)
            } catch (_: CharacterCodingException) {
                ""
            }
            val hostLabel = promptLabel(host)
            val accountLabel = promptLabel(account)
            val executableLabel = promptLabel(executable)
            val labels = if (hostLabel != null && accountLabel != null && executableLabel != null) {
                Labels(hostLabel, accountLabel, executableLabel)
            } else null
            return CommandPromptContext(reference, labels)
        }

        private fun promptLabel(value: String): String? {
            if (value.length > LABEL_LIMIT - 2 || value.isBlank()) return null
            val result = StringBuilder().append('"')
            var offset = 0
            while (offset < value.length) {
                val codePoint = value.codePointAt(offset)
                when (codePoint) {
                    '"'.code, '\\'.code -> result.append('\\').appendCodePoint(codePoint)
                    in 0x20..0x7e -> result.appendCodePoint(codePoint)
                    else -> result.append("\\u{").append(codePoint.toString(16)).append('}')
                }
                if (result.length >= LABEL_LIMIT) return null
                offset += Character.charCount(codePoint)
            }
            return result.append('"').toString()
        }
    }
}
