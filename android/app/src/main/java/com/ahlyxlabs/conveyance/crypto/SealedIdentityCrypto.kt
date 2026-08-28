package com.ahlyxlabs.conveyance.crypto

/**
 * Storage-layer crypto whose defining property is what it does *not* do:
 * the phone's identity secret scalars never cross the FFI boundary as
 * plaintext.
 *
 * [createSealedIdentity] derives and seals in one Rust call — only the
 * `identity.enc` blob and the public keys come back. [openSealedIdentity]
 * returns an opaque [UnlockedIdentity] handle backed by a Rust-owned
 * object; the scalars live in native `Zeroizing` memory and are wiped
 * when the handle is closed. This is the Phase 10.2 upgrade over the
 * stateless [ConveyanceCrypto], whose `deriveIdentity` (retained only for
 * cross-implementation verification) returns raw key bytes.
 *
 * `openSealedIdentity` and `openCredential` return `Result`: a wrong
 * content key or a tampered blob is [CryptoException.DecryptionFailed],
 * an expected outcome that drives the recovery flow, not an exception.
 */
interface SealedIdentityCrypto {

    /** Derive both identity keypairs from `phrase` and seal them under `contentKey` (32 bytes). */
    fun createSealedIdentity(phrase: RecoveryPhrase, contentKey: ByteArray): SealedIdentityBlob

    /**
     * Open an `identity.enc` blob into a Rust-owned handle.
     *
     * @return `success(handle)`, or `failure(`[CryptoException.DecryptionFailed]`)`
     *   for a wrong `contentKey` or a tampered / truncated blob.
     */
    fun openSealedIdentity(blob: ByteArray, contentKey: ByteArray): Result<UnlockedIdentity>

    /** Seal one credential secret under a per-service DEK (32 bytes). */
    fun sealCredential(secret: ByteArray, dek: ByteArray): ByteArray

    /**
     * Open one credential blob. The plaintext returns to the caller (the
     * request executor needs it); rows are opened one at a time.
     *
     * @return `success(plaintext)`, or `failure(`[CryptoException.DecryptionFailed]`)`.
     */
    fun openCredential(blob: ByteArray, dek: ByteArray): Result<ByteArray>
}

/** The on-disk `identity.enc` bytes plus the two public keys (safe in the clear). */
class SealedIdentityBlob(
    val blob: ByteArray,
    val ed25519Public: Ed25519PublicKey,
    val x25519Public: X25519PublicKey,
)

/**
 * A handle to an unlocked phone identity. The secret scalars are held in
 * native memory; this object exposes operations over them, never the
 * bytes. [close] (or `use { }`) drops the Rust object and wipes them.
 */
interface UnlockedIdentity : java.io.Closeable {
    fun ed25519PublicKey(): Ed25519PublicKey
    fun x25519PublicKey(): X25519PublicKey

    /** Sign `message` with the Ed25519 identity key. The caller builds the message. */
    fun sign(message: ByteArray): Ed25519Signature
}
