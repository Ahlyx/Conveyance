package com.ahlyxlabs.conveyance.crypto

import javax.inject.Inject
import uniffi.conveyance_crypto_ffi.CryptoFfiException
import uniffi.conveyance_crypto_ffi.UnlockedIdentity as FfiUnlockedIdentity
import uniffi.conveyance_crypto_ffi.createSealedIdentity as ffiCreateSealedIdentity
import uniffi.conveyance_crypto_ffi.openCredential as ffiOpenCredential
import uniffi.conveyance_crypto_ffi.openSealedIdentity as ffiOpenSealedIdentity
import uniffi.conveyance_crypto_ffi.sealCredential as ffiSealCredential

/** [SealedIdentityCrypto] over the UniFFI bridge. Thin: convert, call, map. */
class UniffiSealedIdentityCrypto @Inject constructor() : SealedIdentityCrypto {

    override fun createSealedIdentity(
        phrase: RecoveryPhrase,
        contentKey: ByteArray,
    ): SealedIdentityBlob {
        val s = try {
            ffiCreateSealedIdentity(phrase.raw(), contentKey)
        } catch (e: CryptoFfiException) {
            throw mapCryptoFfiException(e)
        }
        return SealedIdentityBlob(
            blob = s.blob,
            ed25519Public = Ed25519PublicKey(s.ed25519Public),
            x25519Public = X25519PublicKey(s.x25519Public),
        )
    }

    override fun openSealedIdentity(
        blob: ByteArray,
        contentKey: ByteArray,
    ): Result<UnlockedIdentity> =
        try {
            Result.success(RustUnlockedIdentity(ffiOpenSealedIdentity(blob, contentKey)))
        } catch (e: CryptoFfiException.DecryptionFailed) {
            Result.failure(CryptoException.DecryptionFailed())
        } catch (e: CryptoFfiException) {
            throw mapCryptoFfiException(e)
        }

    override fun sealCredential(secret: ByteArray, dek: ByteArray): ByteArray =
        try {
            ffiSealCredential(secret, dek)
        } catch (e: CryptoFfiException) {
            throw mapCryptoFfiException(e)
        }

    override fun openCredential(blob: ByteArray, dek: ByteArray): Result<ByteArray> =
        try {
            Result.success(ffiOpenCredential(blob, dek))
        } catch (e: CryptoFfiException.DecryptionFailed) {
            Result.failure(CryptoException.DecryptionFailed())
        } catch (e: CryptoFfiException) {
            throw mapCryptoFfiException(e)
        }
}

/** Wraps the generated UniFFI object so callers never see `uniffi.*`. */
private class RustUnlockedIdentity(
    private val inner: FfiUnlockedIdentity,
) : UnlockedIdentity {

    override fun ed25519PublicKey(): Ed25519PublicKey = Ed25519PublicKey(inner.ed25519Public())

    override fun x25519PublicKey(): X25519PublicKey = X25519PublicKey(inner.x25519Public())

    override fun sign(message: ByteArray): Ed25519Signature = Ed25519Signature(inner.sign(message))

    /** Drops the Rust object; its `Zeroizing` secret buffer is wiped. */
    override fun close() = inner.close()
}
