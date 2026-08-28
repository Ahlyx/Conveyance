package com.ahlyxlabs.conveyance.crypto

import uniffi.conveyance_crypto_ffi.CryptoFfiException

/**
 * Translate a UniFFI-generated [CryptoFfiException] to the adapter's
 * [CryptoException]. Split out from [UniffiConveyanceCrypto] so it can be
 * exercised exhaustively in a host JVM unit test — constructing a
 * `CryptoFfiException` needs no native library, only the mapping does the
 * interesting work.
 *
 * The `when` is exhaustive over the sealed hierarchy with no `else`: a
 * new bridge error variant fails to compile here rather than silently
 * falling through to a wrong [CryptoException].
 */
internal fun mapCryptoFfiException(e: CryptoFfiException): CryptoException =
    when (e) {
        is CryptoFfiException.BadRecoveryPhrase -> CryptoException.BadRecoveryPhrase()
        is CryptoFfiException.OutsideCanonicalDomain -> CryptoException.CanonicalDomainViolation()
        is CryptoFfiException.InvalidJson -> CryptoException.InvalidJson()
        is CryptoFfiException.BadKeyBytes -> CryptoException.InvalidKeyEncoding()
        is CryptoFfiException.KdfFailure -> CryptoException.KdfFailure()
        is CryptoFfiException.EntropyFailure -> CryptoException.EntropyFailure()
        is CryptoFfiException.BadLength ->
            CryptoException.InvalidLength("bridge rejected a byte-string length")
        is CryptoFfiException.ZeroLength ->
            CryptoException.InvalidLength("HKDF output length must be >= 1")
        is CryptoFfiException.OutputTooLong ->
            CryptoException.InvalidLength("HKDF output length exceeds 255*HashLen")
        is CryptoFfiException.SignatureInvalid -> CryptoException.SignatureInvalid()
        is CryptoFfiException.DecryptionFailed -> CryptoException.DecryptionFailed()
    }
