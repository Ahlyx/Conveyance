package com.ahlyxlabs.conveyance.storage.identity

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class Tier1PassphrasePolicyTest {
    @Test
    fun requiresTwelveUnicodeScalarValues() {
        assertEquals(
            Tier1PassphrasePolicy.Violation.TOO_SHORT,
            Tier1PassphrasePolicy.violation("a".repeat(11)),
        )
        assertNull(Tier1PassphrasePolicy.violation("a".repeat(12)))
        assertNull(Tier1PassphrasePolicy.violation("😀".repeat(12)))
    }

    @Test
    fun rejectsEmptyInputAndOversizedUtf8BeforeEncoding() {
        assertEquals(Tier1PassphrasePolicy.Violation.EMPTY, Tier1PassphrasePolicy.violation(""))
        assertNull(Tier1PassphrasePolicy.violation("é".repeat(128))) // exactly 256 UTF-8 bytes
        Tier1PassphrasePolicy.requireValidUtf8("é".repeat(128).toByteArray(Charsets.UTF_8))
        assertEquals(
            Tier1PassphrasePolicy.Violation.TOO_LONG,
            Tier1PassphrasePolicy.violation("é".repeat(129)),
        )
    }

    @Test
    fun preservesWhitespaceAndUnicodeNormalizationExactly() {
        val decomposed = "\n  e\u0301 sample phrase  \n"
        val encoded = Tier1PassphrasePolicy.encode(decomposed)
        try {
            assertArrayEquals(decomposed.toByteArray(Charsets.UTF_8), encoded)
            assertNull(Tier1PassphrasePolicy.violation("  é sample phrase  "))
            assertTrue(!encoded.contentEquals("  é sample phrase  ".toByteArray(Charsets.UTF_8)))
        } finally {
            encoded.fill(0)
        }
    }

    @Test
    fun rejectsMalformedUtf16AndMalformedUtf8() {
        assertEquals(
            Tier1PassphrasePolicy.Violation.INVALID_UNICODE,
            Tier1PassphrasePolicy.violation("abcdefghijkl\uD800"),
        )
        assertTrue(runCatching {
            Tier1PassphrasePolicy.requireValidUtf8(ByteArray(257))
        }.isFailure)
        assertTrue(runCatching {
            Tier1PassphrasePolicy.requireValidUtf8(byteArrayOf(0xc0.toByte(), 0xaf.toByte()))
        }.isFailure)
        assertTrue(runCatching {
            Tier1PassphrasePolicy.requireValidUtf8(
                "abcdefghijkl".toByteArray() +
                    byteArrayOf(0xed.toByte(), 0xa0.toByte(), 0x80.toByte()),
            )
        }.isFailure)
        assertTrue(runCatching {
            Tier1PassphrasePolicy.requireValidUtf8("short".toByteArray(Charsets.UTF_8))
        }.isFailure)
    }
}
