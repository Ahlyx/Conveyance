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
 * ## Secret material and memory, in Phase 10.1
 *
 * This adapter is a thin wrapper over a **stateless** Rust bridge. Key
 * bytes — the Ed25519 identity scalar, the Argon2id DEK, the derived
 * identity keys — cross the FFI boundary as `ByteArray` and therefore
 * live on the JVM heap. The JVM neither pins nor zeroes that memory: the
 * garbage collector may copy an array during a compaction, leaving the
 * old bytes behind in freed space until they are overwritten by
 * something else.
 *
 * The secret-bearing types here ([Ed25519SecretKey], [X25519SecretKey],
 * [DerivedKey], [AeadKey]) expose `destroy()`, which fills the *currently
 * referenced* backing array with zeros. That is **best effort, not
 * erasure**: any copy the GC made before `destroy()` was called is out of
 * reach. [RecoveryPhrase] cannot even do that much — a Kotlin `String` is
 * immutable, so its characters cannot be wiped at all; this is one reason
 * the spec says the phrase is never stored, only shown once.
 *
 * This is an accepted limitation of the 10.1 primitives surface, recorded
 * here, on [ConveyanceCrypto], and in the phase report. Because
 * [ConveyanceCrypto] is an interface, Phase 10.2 can move secret handling
 * into Rust-owned, Android-Keystore-backed handle objects — where the
 * plaintext never enters the JVM heap — without changing a single call
 * site. The honesty posture matches auditmcp's about the limits of
 * zeroization.
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
