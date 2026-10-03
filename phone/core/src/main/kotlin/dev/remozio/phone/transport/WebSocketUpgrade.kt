package dev.remozio.phone.transport

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.Locale

/** Bounded HTTP/1.1 upgrade only. No redirects, response bodies, extensions, cookies, or general HTTP API. */
internal object WebSocketUpgrade {
    const val PROTOCOL = "remozio.ciphertext.v1"
    private const val MAX_HEADERS = 16_384
    private const val GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    private val random = SecureRandom()

    fun exchange(input: InputStream, output: OutputStream, endpoint: RelayEndpoint, credential: RelayAccessCredential) {
        require(credential.endpoint == endpoint)
        val nonce = ByteArray(16).also(random::nextBytes)
        val key = Base64.getEncoder().encodeToString(nonce)
        val request = buildString {
            append("GET ${endpoint.path} HTTP/1.1\r\nHost: ${endpoint.authority}\r\n")
            append("Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n")
            append("Sec-WebSocket-Key: $key\r\nSec-WebSocket-Protocol: $PROTOCOL\r\n")
            append("CF-Access-Client-Id: ${credential.clientId}\r\n")
            append("CF-Access-Client-Secret: ${credential.clientSecret}\r\n\r\n")
        }.toByteArray(Charsets.US_ASCII)
        try { output.write(request); output.flush() } finally { request.fill(0) }
        validate(input, key)
    }

    internal fun validate(input: InputStream, key: String) {
        var remaining = MAX_HEADERS
        fun read(): Int {
            if (remaining-- <= 0) throw rejected()
            return input.read().also { if (it < 0) throw rejected() }
        }
        fun line(): String {
            val result = StringBuilder()
            while (true) {
                val next = read()
                if (next == 13) { if (read() != 10) throw rejected(); return result.toString() }
                if ((next !in 0x20..0x7e && next != 9) || result.length >= 4_096) throw rejected()
                result.append(next.toChar())
            }
        }
        val status = line()
        if (!Regex("HTTP/1\\.1 101(?: [ -~]*)?").matches(status)) throw rejected()
        val headers = mutableMapOf<String, MutableList<String>>()
        var count = 0
        while (true) {
            val header = line()
            if (header.isEmpty()) break
            if (++count > 64 || header.first() == ' ' || header.first() == '\t') throw rejected()
            val colon = header.indexOf(':')
            if (colon < 1) throw rejected()
            val name = header.substring(0, colon)
            if (!Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+").matches(name)) throw rejected()
            headers.getOrPut(name.lowercase(Locale.ROOT)) { mutableListOf() }.add(header.substring(colon + 1).trim(' ', '\t'))
        }
        fun single(name: String): String = headers[name]?.singleOrNull() ?: throw rejected()
        if (!single("upgrade").equals("websocket", ignoreCase = true)) throw rejected()
        val connections = headers["connection"] ?: throw rejected()
        if (connections.flatMap { it.split(',') }.none { it.trim().equals("upgrade", ignoreCase = true) }) throw rejected()
        val expected = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((key + GUID).toByteArray(Charsets.US_ASCII)))
        if (!MessageDigest.isEqual(single("sec-websocket-accept").toByteArray(Charsets.US_ASCII), expected.toByteArray(Charsets.US_ASCII))) throw rejected()
        if (single("sec-websocket-protocol") != PROTOCOL) throw rejected()
        if (headers.containsKey("sec-websocket-extensions") || headers.containsKey("transfer-encoding")) throw rejected()
        headers["content-length"]?.let { if (it.size != 1 || it.single() != "0") throw rejected() }
    }

    private fun rejected() = IOException("Relay upgrade rejected")
}
