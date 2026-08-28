package com.ahlyxlabs.conveyance.crypto

import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.conveyance_crypto_ffi.CryptoFfiException

/**
 * Every bridge error variant maps to the intended [CryptoException].
 * Runs on the host JVM: constructing a `CryptoFfiException` needs no
 * native library, and [mapCryptoFfiException] is pure Kotlin.
 *
 * If a new `CryptoFfiException` variant is added, `mapCryptoFfiException`'s
 * exhaustive `when` stops compiling — but this test also has to gain a
 * case, so the mapping decision is made deliberately, not defaulted.
 */
class ErrorMappingTest {

    @Test
    fun eachVariantMapsToItsAdapterType() {
        assertTrue(
            mapCryptoFfiException(CryptoFfiException.BadRecoveryPhrase())
                is CryptoException.BadRecoveryPhrase,
        )
        assertTrue(
            mapCryptoFfiException(CryptoFfiException.OutsideCanonicalDomain())
                is CryptoException.CanonicalDomainViolation,
        )
        assertTrue(
            mapCryptoFfiException(CryptoFfiException.InvalidJson()) is CryptoException.InvalidJson,
        )
        assertTrue(
            mapCryptoFfiException(CryptoFfiException.BadKeyBytes())
                is CryptoException.InvalidKeyEncoding,
        )
        assertTrue(
            mapCryptoFfiException(CryptoFfiException.KdfFailure()) is CryptoException.KdfFailure,
        )
        assertTrue(
            mapCryptoFfiException(CryptoFfiException.EntropyFailure())
                is CryptoException.EntropyFailure,
        )
        assertTrue(
            mapCryptoFfiException(CryptoFfiException.BadLength()) is CryptoException.InvalidLength,
        )
        assertTrue(
            mapCryptoFfiException(CryptoFfiException.ZeroLength()) is CryptoException.InvalidLength,
        )
        assertTrue(
            mapCryptoFfiException(CryptoFfiException.OutputTooLong())
                is CryptoException.InvalidLength,
        )
        assertTrue(
            mapCryptoFfiException(CryptoFfiException.SignatureInvalid())
                is CryptoException.SignatureInvalid,
        )
        assertTrue(
            mapCryptoFfiException(CryptoFfiException.DecryptionFailed())
                is CryptoException.DecryptionFailed,
        )
    }
}
