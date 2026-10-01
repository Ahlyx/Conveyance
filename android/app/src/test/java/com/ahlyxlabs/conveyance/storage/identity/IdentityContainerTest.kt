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

    private fun biometricV2() =
        IdentityContainer(
            wrappedContentKey = ByteArray(60) { it.toByte() },
            sealedBlob = ByteArray(120) { (it * 2).toByte() },
            authMethod = Tier1AuthMethod.BIOMETRIC,
            generation = ByteArray(16) { (it + 1).toByte() },
            version = IdentityContainer.VERSION,
        )

    private fun passphraseV2() =
        IdentityContainer(
            wrappedContentKey = ByteArray(48) { it.toByte() },
            sealedBlob = ByteArray(120) { (it * 2).toByte() },
            authMethod = Tier1AuthMethod.PASSPHRASE,
            salt = ByteArray(16) { (it + 1).toByte() },
            nonce = ByteArray(12) { (it + 2).toByte() },
            generation = ByteArray(16) { (it + 3).toByte() },
            version = IdentityContainer.VERSION,
        )

    @Test
    fun encodeDecodeRoundTrips() {
        val c = sample()
        assertEquals(c, IdentityContainer.decode(c.encode()))
    }

    @Test
    fun biometricV2RoundTrips() {
        val c = biometricV2()
        assertEquals(c, IdentityContainer.decode(c.encode()))
    }

    @Test
    fun passphraseV2RoundTripsWithoutChangingSaltOrNonce() {
        val c = passphraseV2()
        assertEquals(c, IdentityContainer.decode(c.encode()))
    }

    @Test
    fun v2RejectsUnknownMethodAndInconsistentPayloadLength() {
        val bytes = biometricV2().encode()
        bytes[5] = 99
        assertThrows(IdentityCorruptException::class.java) {
            IdentityContainer.decode(bytes)
        }

        val badLength = biometricV2().encode()
        badLength[23] = 1
        assertThrows(IdentityCorruptException::class.java) {
            IdentityContainer.decode(badLength)
        }
    }

    @Test
    fun v2EncodingRejectsMethodEnvelopeMismatch() {
        assertThrows(IllegalArgumentException::class.java) {
            biometricV2().copy(salt = ByteArray(16)).encode()
        }
        assertThrows(IllegalArgumentException::class.java) {
            passphraseV2().copy(nonce = null).encode()
        }
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
