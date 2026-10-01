package com.ahlyxlabs.conveyance.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Contract of the value wrappers, host JVM — no native library needed.
 * The redaction and `destroy()` behaviour is security-relevant, so it is
 * pinned here rather than left to the instrumented suite.
 */
class CryptoTypesTest {

    @Test
    fun secretDestroyZeroesTheBackingArrayAndBlocksFurtherAccess() {
        val key = Ed25519SecretKey(ByteArray(32) { 0x5a })
        val exposed = key.bytes()
        assertArrayEquals(ByteArray(32) { 0x5a }, exposed)

        key.destroy()
        assertThrows(IllegalStateException::class.java) { key.bytes() }
        // The copy already handed out is untouched — this is why the
        // guarantee is "best effort": callers holding a reference keep it.
        assertArrayEquals(ByteArray(32) { 0x5a }, exposed)
    }

    @Test
    fun destroyIsIdempotent() {
        val key = AeadKey(ByteArray(32))
        key.destroy()
        key.destroy()
    }

    @Test
    fun bytesReturnsACopyNotTheBacking() {
        val key = DerivedKey(ByteArray(32) { it.toByte() })
        val a = key.bytes()
        a[0] = 99
        assertNotEquals(99.toByte(), key.bytes()[0])
    }

    @Test
    fun secretToStringNeverShowsBytes() {
        val rendered = Ed25519SecretKey(ByteArray(32) { 0xab.toByte() }).toString()
        assertEquals("Ed25519SecretKey(<redacted>)", rendered)
        assertFalse(rendered.contains("ab"))
    }

    @Test
    fun recoveryPhraseIsRedactedAndSplitsToWords() {
        val phrase = RecoveryPhrase("abandon abandon art")
        assertEquals(listOf("abandon", "abandon", "art"), phrase.words)
        assertEquals("RecoveryPhrase(<redacted>)", phrase.toString())
        assertFalse(phrase.toString().contains("abandon"))
    }

    @Test
    fun wrongLengthsAreRejectedAtConstruction() {
        assertThrows(IllegalArgumentException::class.java) { Ed25519SecretKey(ByteArray(31)) }
        assertThrows(IllegalArgumentException::class.java) { Ed25519PublicKey(ByteArray(33)) }
        assertThrows(IllegalArgumentException::class.java) { Ed25519Signature(ByteArray(63)) }
        assertThrows(IllegalArgumentException::class.java) { AeadNonce(ByteArray(16)) }
        assertThrows(IllegalArgumentException::class.java) { LogEvent(ByteArray(15), "e", "{}", 0) }
        assertThrows(IllegalArgumentException::class.java) {
            ChainRow(LogEvent(ByteArray(16), "e", "{}", 0), ByteArray(31), ByteArray(32))
        }
    }

    @Test
    fun secretKeyWrappersCanBeDestroyed() {
        val ed25519 = Ed25519SecretKey(ByteArray(32) { 1 })
        val x25519 = X25519SecretKey(ByteArray(32) { 3 })
        ed25519.destroy()
        x25519.destroy()
        assertThrows(IllegalStateException::class.java) { ed25519.bytes() }
        assertThrows(IllegalStateException::class.java) { x25519.bytes() }
    }

    @Test
    fun signingContextConstantsAreTheSpecStrings() {
        assertArrayEquals(
            "conveyance-approve-v1".toByteArray(Charsets.US_ASCII),
            SigningContext.APPROVE.bytes,
        )
        assertArrayEquals(
            "conveyance-execute-v1".toByteArray(Charsets.US_ASCII),
            SigningContext.EXECUTE.bytes,
        )
    }

    @Test
    fun logEventAndChainRowHaveContentEquality() {
        val a = LogEvent(ByteArray(16) { 7 }, "approval_granted", "{\"n\":1}", 1_700_000_000)
        val b = LogEvent(ByteArray(16) { 7 }, "approval_granted", "{\"n\":1}", 1_700_000_000)
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())

        val r1 = ChainRow(a, ByteArray(32), ByteArray(32) { 9 })
        val r2 = ChainRow(b, ByteArray(32), ByteArray(32) { 9 })
        assertEquals(r1, r2)
        assertEquals(r1.hashCode(), r2.hashCode())
        assertNotEquals(r1, r1.copy(hash = ByteArray(32) { 8 }))
    }
}
