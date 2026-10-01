package com.ahlyxlabs.conveyance.storage.identity

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class Tier1AuthInputTest {
    @Test
    fun passphraseCopiesAndPreservesExactUtf8Bytes() {
        val expected = "  e\u0301exact phrase  ".toByteArray(Charsets.UTF_8)
        val source = expected.copyOf()
        val input = Tier1AuthInput.Passphrase(source)
        source.fill(0)

        val actual = input.useBytes { it.copyOf() }
        assertArrayEquals(expected, actual)
        actual.fill(0)
        assertTrue("passphrase must not appear in diagnostics", input.toString().contains("<redacted>"))
        input.close()
        assertTrue(runCatching { input.useBytes { it.size } }.isFailure)
    }

    @Test
    fun emptyInputIsRejected() {
        assertTrue(runCatching { Tier1AuthInput.Passphrase(ByteArray(0)) }.isFailure)
    }

    @Test
    fun invalidUtf8IsRejectedBeforeInputIsCreated() {
        assertTrue(runCatching {
            Tier1AuthInput.Passphrase(byteArrayOf(0xc0.toByte(), 0xaf.toByte()))
        }.isFailure)
    }

    @Test
    fun validInputCannotBeReadAfterClose() {
        val input = Tier1AuthInput.Passphrase("valid passphrase".toByteArray(Charsets.UTF_8))
        assertTrue(input.useBytes { it.isNotEmpty() })
        input.close()
        val result = runCatching { input.useBytes { it.size } }
        assertTrue(result.isFailure)
    }
}
