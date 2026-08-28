package com.ahlyxlabs.conveyance.storage.identity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/** Host-JVM: the identity.enc byte layout, no Keystore involved. */
class IdentityContainerTest {

    private fun sample() =
        IdentityContainer(
            wrappedContentKey = ByteArray(60) { it.toByte() },
            sealedBlob = ByteArray(120) { (it * 2).toByte() },
        )

    @Test
    fun encodeDecodeRoundTrips() {
        val c = sample()
        assertEquals(c, IdentityContainer.decode(c.encode()))
    }

    @Test
    fun decodeRejectsTruncatedInput() {
        assertThrows(IdentityCorruptException::class.java) {
            IdentityContainer.decode(ByteArray(5))
        }
    }

    @Test
    fun decodeRejectsBadMagic() {
        val bytes = sample().encode()
        bytes[0] = 'X'.code.toByte()
        assertThrows(IdentityCorruptException::class.java) {
            IdentityContainer.decode(bytes)
        }
    }

    @Test
    fun decodeRejectsUnknownVersion() {
        val bytes = sample().encode()
        bytes[4] = 9
        assertThrows(IdentityCorruptException::class.java) {
            IdentityContainer.decode(bytes)
        }
    }

    @Test
    fun decodeRejectsInconsistentLengthFields() {
        val bytes = sample().encode()
        // wrapped-key-length claims 0xFFFF, far more than the buffer holds.
        bytes[5] = 0xFF.toByte()
        bytes[6] = 0xFF.toByte()
        assertThrows(IdentityCorruptException::class.java) {
            IdentityContainer.decode(bytes)
        }
    }

    @Test
    fun encodeRejectsEmptyBlob() {
        assertThrows(IllegalArgumentException::class.java) {
            IdentityContainer(ByteArray(10) { 1 }, ByteArray(0)).encode()
        }
    }
}
