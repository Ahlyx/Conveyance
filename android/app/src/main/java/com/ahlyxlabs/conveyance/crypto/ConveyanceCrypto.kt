package com.ahlyxlabs.conveyance.crypto

/**
 * The phone side's cryptographic primitives, as a stable Kotlin API.
 *
 * Every operation is a pure function of its inputs. The Phase 10.1
 * implementation ([UniffiConveyanceCrypto]) delegates to
 * `conveyance-crypto` through a stateless UniFFI bridge, so the same
 * bytes come out here as on the PC daemon — that cross-implementation
 * agreement is the whole point of sharing the Rust crate, and it is
 * pinned by the fixture parity suite in CI.
 *
 * Consumers (Phase 10.2 storage, 10.5 pairing, 10.6 approvals, …) depend
 * only on this interface. They do not see UniFFI, and — see
 * [CryptoException] on the JVM-heap limitation — they will not need to
 * change when Phase 10.2 swaps in a Keystore-backed implementation whose
 * secrets never leave native memory.
 *
 * ## Error convention
 *
 * - [verify] and [open] return `Result`: signature-invalid and
 *   decryption-failed are *expected outcomes a caller branches on* (an
 *   attack signal), not exceptions.
 * - Everything else throws a [CryptoException] subtype. Malformed-input
 *   cases ([CryptoException.InvalidLength], [CryptoException.InvalidKeyEncoding])
 *   always throw — they are caller bugs the typed wrappers make hard to hit.
 */
interface ConveyanceCrypto {

    // -- Recovery / identity ------------------------------------------------

    /** Generate a fresh 24-word BIP-39 phrase from 256 bits of OS entropy. */
    fun generateRecoveryPhrase(): RecoveryPhrase

    /**
     * Validate a phrase's checksum and derive both long-term identity
     * keypairs (BIP-39 seed with an empty passphrase, then HKDF-BLAKE2s).
     *
     * **Not the production unlock path.** Production goes through
     * [SealedIdentityCrypto], where identity secrets never enter the JVM
     * heap. This returns raw key bytes and is retained only as the
     * cross-implementation verification path for the fixture parity suite
     * — hence `@RestrictTo(TESTS)`.
     *
     * @throws CryptoException.BadRecoveryPhrase if the phrase is invalid.
     */
    @androidx.annotation.RestrictTo(androidx.annotation.RestrictTo.Scope.TESTS)
    fun deriveIdentity(phrase: RecoveryPhrase): IdentityKeys

    // -- Signing ----------------------------------------------------------

    /**
     * `context || canonicalBody`, the exact preimage the peer verifies
     * over. The caller is responsible for building `canonicalBody` (its
     * message serialized, `signature` removed, then [canonicalize]) and,
     * per spec, for *omitting* absent optional fields rather than
     * emitting `null`.
     */
    fun signingPayload(context: SigningContext, canonicalBody: String): ByteArray

    /** Derive the Ed25519 public key from a secret key. */
    fun ed25519PublicKey(secret: Ed25519SecretKey): Ed25519PublicKey

    /** Sign a message with an Ed25519 secret key. */
    fun sign(key: Ed25519SecretKey, message: ByteArray): Ed25519Signature

    /**
     * Verify an Ed25519 signature.
     *
     * @return `success(Unit)` if it verifies; `failure(`[CryptoException.SignatureInvalid]`)`
     *   if it does not.
     * @throws CryptoException.InvalidKeyEncoding if `key` is not a valid curve point.
     */
    fun verify(key: Ed25519PublicKey, message: ByteArray, signature: Ed25519Signature): Result<Unit>

    // -- Canonical JSON --------------------------------------------------

    /**
     * Canonicalize a JSON document (RFC 8785, Conveyance domain: ints,
     * strings, bools, null, arrays, objects).
     *
     * @throws CryptoException.InvalidJson if `json` does not parse.
     * @throws CryptoException.CanonicalDomainViolation on a float or an
     *   integer outside the i64/u64 range.
     */
    fun canonicalize(json: String): String

    // -- Argon2id -------------------------------------------------------

    /**
     * Derive a 32-byte DEK from a passphrase with the spec's fixed
     * Argon2id parameters (m=64 MiB, t=3, p=1). `salt` must be 16 bytes.
     */
    fun deriveDek(passphrase: ByteArray, salt: ByteArray): DerivedKey

    // -- AEAD (ChaCha20-Poly1305) --------------------------------------

    /** Encrypt `plaintext` with associated data `aad`; returns `ciphertext || tag`. */
    fun seal(key: AeadKey, nonce: AeadNonce, plaintext: ByteArray, aad: ByteArray): ByteArray

    /**
     * Decrypt bytes produced by [seal].
     *
     * @return `success(plaintext)`, or `failure(`[CryptoException.DecryptionFailed]`)`
     *   for any failure (wrong key/nonce/aad, corrupted bytes).
     */
    fun open(key: AeadKey, nonce: AeadNonce, ciphertext: ByteArray, aad: ByteArray): Result<ByteArray>

    // -- HKDF-BLAKE2s -------------------------------------------------

    /** HKDF-BLAKE2s (RFC 5869), salt omitted. `length` in bytes, 1..255*32. */
    fun hkdfBlake2s(ikm: ByteArray, info: ByteArray, length: Int): ByteArray

    // -- Hash chain -------------------------------------------------

    /** `prev_hash` for the first row in any chain: 32 zero bytes. */
    fun genesisPrevHash(): ByteArray

    /** The canonical JSON bytes (as text) that [rowHash] is taken over. */
    fun eventContentJson(event: LogEvent): String

    /** `SHA256(prevHash || event_content_json(event))`. */
    fun rowHash(prevHash: ByteArray, event: LogEvent): ByteArray

    /** Walk `rows` in order, verifying every link and content hash. */
    fun verifyChain(rows: List<ChainRow>): ChainVerification
}
