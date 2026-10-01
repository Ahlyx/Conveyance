package com.ahlyxlabs.conveyance.crypto

/**
 * The crypto layer's error surface, in Kotlin terms.
 *
 * Consumers catch these, never the UniFFI-generated `CryptoFfiException`.
 * Variants are deliberately coarse — the same reason the Rust
 * `conveyance_crypto::CryptoError` is coarse: a security product must not
 * tell a caller *which* internal check failed. [`SignatureInvalid`] and
 * [`DecryptionFailed`] do not distinguish a wrong key from a wrong nonce
 * from a flipped byte, and the API returns them as `Result` values rather
 * than throwing, because they are outcomes a caller branches on (an
 * attack signal), not exceptions.
 *
 * ---
 *
 * ## Secret material and memory
 *
 * Low-level primitive wrappers that accept caller-supplied secret bytes
 * hold those values as JVM `ByteArray`s. The JVM neither pins nor zeroes
 * that memory: the garbage collector may copy an array during a
 * compaction, leaving the old bytes behind in freed space until they are
 * overwritten. Production phone identity creation and signing instead
 * use [SealedIdentityCrypto] and a Rust-owned [UnlockedIdentity] handle;
 * private identity scalars do not cross that boundary. Raw phrase-derived
 * scalars are exposed only by the debug `test-vectors` fixture bridge.
 *
 * The secret-bearing types here ([Ed25519SecretKey], [X25519SecretKey],
 * [DerivedKey], [AeadKey]) expose `destroy()`, which fills the *currently
 * referenced* backing array with zeros. That is **best effort, not
 * erasure**: any copy the GC made before `destroy()` was called is out of
 * reach. [RecoveryPhrase] cannot even do that much — a Kotlin `String` is
 * immutable, so its characters cannot be wiped at all; this is one reason
 * the spec says the phrase is never stored, only shown once.
 *
 * [Secret.destroy] is best-effort for these low-level wrappers. It does
 * not affect the production identity path, whose scalars remain inside
 * Rust-owned zeroizing memory and are wiped when [UnlockedIdentity.close]
 * is called.
 */
sealed class CryptoException(message: String, cause: Throwable? = null) :
    Exception(message, cause) {

    /** An Ed25519 signature did not verify. Returned via `Result`, not thrown. */
    class SignatureInvalid : CryptoException("signature verification failed")

    /** AEAD open failed — wrong key, nonce, AAD, or corrupted bytes. Returned via `Result`. */
    class DecryptionFailed : CryptoException("decryption failed")

    /** Wrong word count, unknown word, or bad BIP-39 checksum. No parsing oracle. */
    class BadRecoveryPhrase : CryptoException("invalid recovery phrase")

    /** A value handed to [ConveyanceCrypto.canonicalize] carried a float or an out-of-range integer. */
    class CanonicalDomainViolation : CryptoException("value outside the canonical-JSON domain")

    /** The string handed to [ConveyanceCrypto.canonicalize] is not valid JSON. */
    class InvalidJson : CryptoException("input is not valid JSON")

    /** A key was not a valid curve point. */
    class InvalidKeyEncoding : CryptoException("invalid key encoding")

    /** Argon2id rejected the derivation (only reachable via invalid parameters). */
    class KdfFailure : CryptoException("key derivation failed")

    /** The OS CSPRNG failed. Effectively unreachable on Android; the API is fallible anyway. */
    class EntropyFailure : CryptoException("entropy source failed")

    /**
     * A byte-string argument had the wrong length for its field. This is
     * caller misuse (the typed wrappers make it hard to hit); it is
     * thrown, never returned via `Result`.
     */
    class InvalidLength(detail: String) : CryptoException("invalid length: $detail")

    /** An unexpected error from the bridge with no more specific mapping. */
    class Internal(cause: Throwable) : CryptoException("internal crypto error", cause)
}
