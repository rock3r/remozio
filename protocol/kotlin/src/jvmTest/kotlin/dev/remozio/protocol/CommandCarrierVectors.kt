package dev.remozio.protocol

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

internal object CommandCarrierVectors {
    internal data class Row(val name: String, private val hex: String) {
        fun bytes(): ByteArray {
            require(hex.length % 2 == 0) { "Odd hex length for $name" }
            return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        }
    }

    private val fixture by lazy {
        val file = File(checkNotNull(System.getProperty("remozio.commandCarrierVectors")))
        Json.parseToJsonElement(file.readText()).jsonObject
    }

    fun rows(carrier: String, group: String): List<Row> =
        fixture.getValue(carrier).jsonObject.getValue(group).jsonArray.map { entry ->
            val fields = entry.jsonObject
            Row(fields.getValue("name").jsonPrimitive.content, fields.getValue("hex").jsonPrimitive.content)
        }
}
