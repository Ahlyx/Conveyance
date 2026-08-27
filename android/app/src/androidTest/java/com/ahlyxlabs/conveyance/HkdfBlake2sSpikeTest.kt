package com.ahlyxlabs.conveyance

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.conveyance_crypto_ffi.CryptoFfiException
import uniffi.conveyance_crypto_ffi.hkdfBlake2s

/**
 * Phase 10.1 UniFFI viability spike — the whole point of the sub-phase.
 *
 * This runs on a real emulator (`connectedDebugAndroidTest`). It loads
 * the cross-compiled `libconveyance_crypto_ffi.so`, calls through the
 * UniFFI-generated Kotlin, and checks the result byte-for-byte against a
 * value computed by the Rust reference (`conveyance-crypto`). If it
 * passes on x86_64, the toolchain — Rust -> cargo-ndk -> UniFFI bindgen
 * -> JNA -> Kotlin -> emulator — works end to end and the full 10.1
 * crypto surface can follow.
 *
 * The vector is shared verbatim with the Rust test
 * `conveyance_crypto_ffi::tests::hkdf_blake2s_matches_known_answer`.
 * BLAKE2s has no official HKDF vectors, so the anchor is the Rust
 * implementation itself: matching it proves the FFI path is faithful.
 */
@RunWith(AndroidJUnit4::class)
class HkdfBlake2sSpikeTest {

    private val ikm = "conveyance hkdf-blake2s spike".toByteArray(Charsets.US_ASCII)
    private val info = "spike-vector-v1".toByteArray(Charsets.US_ASCII)

    private val expectedOkm32 =
        "3b0d11d95126c099d16717960a07423b60ac5705b7d0615aa9d7ab7065badcca".hexToByteArray()

    @Test
    fun hkdfBlake2sMatchesRustKnownAnswer() {
        val okm = hkdfBlake2s(ikm, info, 32u)
        assertArrayEquals(expectedOkm32, okm)
    }

    @Test
    fun outputIsLengthPrefixStable() {
        val short = hkdfBlake2s(ikm, info, 32u)
        val long = hkdfBlake2s(ikm, info, 40u)
        assertArrayEquals(short, long.copyOfRange(0, 32))
    }

    @Test
    fun zeroLengthIsATypedError() {
        assertThrows(CryptoFfiException.ZeroLength::class.java) {
            hkdfBlake2s(ikm, info, 0u)
        }
    }

    private fun String.hexToByteArray(): ByteArray =
        chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
