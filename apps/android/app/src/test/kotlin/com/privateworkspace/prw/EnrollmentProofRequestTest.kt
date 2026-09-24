package com.privateworkspace.prw

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class EnrollmentProofRequestTest {
    @Test fun exact_nonce_and_bounded_fields_encode() {
        val nonce = ByteArray(32) { 7 }
        val encoded = EnrollmentProofRequest(
            enrollmentId = "enrollment-146",
            workspaceId = "workspace-146",
            userId = "user-146",
            deviceId = "device-146",
            publicSpki = byteArrayOf(1, 2, 3),
            nonce = nonce,
        ).encode()
        assertArrayEquals(byteArrayOf('P'.code.toByte(), '1'.code.toByte(), '4'.code.toByte(), '6'.code.toByte()), encoded.copyOfRange(0, 4))
        assertTrue(encoded.size <= 4400)
    }

    @Test fun wrong_nonce_length_fails_closed() {
        assertThrows(IllegalArgumentException::class.java) {
            EnrollmentProofRequest(
                enrollmentId = "enrollment-146",
                workspaceId = "workspace-146",
                userId = "user-146",
                deviceId = "device-146",
                publicSpki = byteArrayOf(1),
                nonce = ByteArray(31),
            ).encode()
        }
    }
}
