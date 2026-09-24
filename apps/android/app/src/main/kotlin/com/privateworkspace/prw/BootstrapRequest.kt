package com.privateworkspace.prw

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

internal data class BootstrapRequest(
    val workspaceId: String,
    val userId: String,
    val deviceId: String,
    val sessionId: String,
    val publicSpki: ByteArray,
    val nonce: ByteArray,
) {
    fun encode(): ByteArray {
        require(nonce.size == NONCE_BYTES)
        val output = ByteArrayOutputStream()
        output.write(MAGIC)
        output.write(shortBytes(VERSION))
        writeUtf8(output, workspaceId)
        writeUtf8(output, userId)
        writeUtf8(output, deviceId)
        writeUtf8(output, sessionId)
        writeBytes(output, publicSpki, MAX_PUBLIC_SPKI_BYTES)
        output.write(nonce)
        return output.toByteArray().also { require(it.size <= MAX_BYTES) }
    }

    companion object {
        private val MAGIC = byteArrayOf('P'.code.toByte(), '1'.code.toByte(), '4'.code.toByte(), '5'.code.toByte())
        private const val VERSION = 1
        private const val NONCE_BYTES = 32
        private const val MAX_FIELD_BYTES = 1024
        private const val MAX_PUBLIC_SPKI_BYTES = 256
        private const val MAX_BYTES = 4096

        private fun shortBytes(value: Int): ByteArray = ByteBuffer
            .allocate(2)
            .order(ByteOrder.BIG_ENDIAN)
            .putShort(value.toShort())
            .array()

        private fun writeUtf8(output: ByteArrayOutputStream, value: String) {
            val bytes = value.toByteArray(Charsets.UTF_8)
            require(bytes.isNotEmpty() && bytes.size <= MAX_FIELD_BYTES)
            writeBytes(output, bytes, MAX_FIELD_BYTES)
        }

        private fun writeBytes(output: ByteArrayOutputStream, bytes: ByteArray, maximum: Int) {
            require(bytes.isNotEmpty() && bytes.size <= maximum)
            require(bytes.size <= UShort.MAX_VALUE.toInt())
            output.write(shortBytes(bytes.size))
            output.write(bytes)
        }
    }
}
