package dev.remozio.phone.transport

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import org.junit.Test
import kotlin.test.*

class WebSocketUpgradeTest {
    private val key = "dGhlIHNhbXBsZSBub25jZQ=="
    private val accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    private fun response(extra: String = "") = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: $accept\r\nSec-WebSocket-Protocol: ${WebSocketUpgrade.PROTOCOL}\r\n$extra\r\n"
    private fun validate(text: String) = WebSocketUpgrade.validate(text.byteInputStream(Charsets.US_ASCII), key)

    @Test fun validatesTheUpgradeWithoutConsumingTheFirstFrame() {
        val bytes = response().toByteArray(Charsets.US_ASCII) + byteArrayOf(0x82.toByte(), 1, 7)
        val input = ByteArrayInputStream(bytes)
        WebSocketUpgrade.validate(input, key)
        assertContentEquals(byteArrayOf(0x82.toByte(), 1, 7), input.readBytes())
    }

    @Test fun rejectsStatusNonceProtocolExtensionsAndEntityBodies() {
        for (text in listOf(
            response().replace("101", "302"), response().replace("101", "403"), response().replace("HTTP/1.1", "HTTP/1.0"),
            response().replace(accept, "wrong"), response().replace(WebSocketUpgrade.PROTOCOL, "other.v1"),
            response("Sec-WebSocket-Extensions: permessage-deflate\r\n"),
            response("Transfer-Encoding: chunked\r\n"), response("Content-Length: 1\r\n"),
            response("Sec-WebSocket-Accept: $accept\r\n"), response("Sec-WebSocket-Protocol: ${WebSocketUpgrade.PROTOCOL}\r\n"),
            response().replace("Connection: keep-alive, Upgrade", "Connection: keep-alive"),
            response().replace("Upgrade: websocket", "Upgrade: something-else"),
        )) assertFailsWith<IOException> { validate(text) }
    }

    @Test fun boundsHeadersAndRejectsAmbiguousLines() {
        for (text in listOf(
            response("X-Long: ${"a".repeat(4_097)}\r\n"),
            response((1..60).joinToString("") { "X-$it: ${"a".repeat(300)}\r\n" }),
            response((1..65).joinToString("") { "X-$it: a\r\n" }),
            response(" folded\r\n"), response("Bad Name: a\r\n"),
            response().replace("\r\n", "\n"), response().dropLast(1),
        )) assertFailsWith<IOException> { validate(text) }
        validate(response("Content-Length: 0\r\nSet-Cookie: a\r\nSet-Cookie: b\r\n"))
    }

    @Test fun scopesCredentialsAndRejectsHeaderInjection() {
        val endpoint = RelayEndpoint("relay.example")
        val credential = RelayAccessCredential(endpoint, "synthetic-id", "synthetic-secret")
        assertEquals("RelayAccessCredential(redacted)", credential.toString())
        assertEquals("RelayEndpoint(redacted)", endpoint.toString())
        assertFailsWith<IllegalArgumentException> { RelayAccessCredential(endpoint, "bad\r\nX: value", "secret") }
        for (host in listOf("https://relay.example", "relay.example\r\n", "user@relay.example", "a..example", "-bad.example")) {
            assertFailsWith<IllegalArgumentException> { RelayEndpoint(host) }
        }
        for (path in listOf("/../a", "/a?token=x", "/a#b", "/%2e%2e/a", "/a\r\n")) {
            assertFailsWith<IllegalArgumentException> { RelayEndpoint("relay.example", path = path) }
        }
        val output = ByteArrayOutputStream()
        assertFailsWith<IllegalArgumentException> {
            WebSocketUpgrade.exchange(ByteArrayInputStream(byteArrayOf()), output, RelayEndpoint("other.example"), credential)
        }
        assertEquals(0, output.size())
    }
}
