package com.ahlyxlabs.conveyance.crypto

import javax.inject.Inject
import uniffi.conveyance_crypto_ffi.ChainBreakKind as FfiChainBreakKind
import uniffi.conveyance_crypto_ffi.ChainRow as FfiChainRow
import uniffi.conveyance_crypto_ffi.ChainVerification as FfiChainVerification
import uniffi.conveyance_crypto_ffi.CryptoFfiException
import uniffi.conveyance_crypto_ffi.LogEvent as FfiLogEvent
import uniffi.conveyance_crypto_ffi.argon2idDeriveDek
import uniffi.conveyance_crypto_ffi.canonicalJson as ffiCanonicalJson
import uniffi.conveyance_crypto_ffi.chacha20poly1305Open
import uniffi.conveyance_crypto_ffi.chacha20poly1305Seal
import uniffi.conveyance_crypto_ffi.ed25519PublicFromSecret
import uniffi.conveyance_crypto_ffi.ed25519Sign
import uniffi.conveyance_crypto_ffi.ed25519Verify
import uniffi.conveyance_crypto_ffi.generateRecoveryPhrase as ffiGenerateRecoveryPhrase
import uniffi.conveyance_crypto_ffi.hashChainEventContentJson
import uniffi.conveyance_crypto_ffi.hashChainGenesisPrevHash
import uniffi.conveyance_crypto_ffi.hashChainRowHash
import uniffi.conveyance_crypto_ffi.hashChainVerify
import uniffi.conveyance_crypto_ffi.hkdfBlake2s as ffiHkdfBlake2s
import uniffi.conveyance_crypto_ffi.recoveryPhraseToIdentity
import uniffi.conveyance_crypto_ffi.signingPayload as ffiSigningPayload

/**
 * [ConveyanceCrypto] backed by `conveyance-crypto` through the UniFFI
 * bridge. Thin by construction: convert types, call the generated
 * function, map the error. No cryptographic logic — that would be the
 * second implementation the whole UniFFI decision exists to avoid.
 *
 * The generated `uniffi.conveyance_crypto_ffi.*` symbols are confined to
 * this file; every one is aliased or wrapped so nothing UniFFI-shaped
 * escapes into [ConveyanceCrypto]'s surface.
 */
class UniffiConveyanceCrypto @Inject constructor() : ConveyanceCrypto {

    override fun generateRecoveryPhrase(): RecoveryPhrase =
        RecoveryPhrase(guard { ffiGenerateRecoveryPhrase() })

    // The interface method is @RestrictTo(TESTS); implementing it is not
    // "calling" it, but lint's RestrictedApi check flags the override too.
    @Suppress("RestrictedApi")
    override fun deriveIdentity(phrase: RecoveryPhrase): IdentityKeys {
        val k = guard { recoveryPhraseToIdentity(phrase.raw()) }
        return IdentityKeys(
            ed25519Secret = Ed25519SecretKey(k.ed25519Secret),
            ed25519Public = Ed25519PublicKey(k.ed25519Public),
            x25519Secret = X25519SecretKey(k.x25519Secret),
            x25519Public = X25519PublicKey(k.x25519Public),
        )
    }

    override fun signingPayload(context: SigningContext, canonicalBody: String): ByteArray =
        guard { ffiSigningPayload(context.bytes, canonicalBody) }

    override fun ed25519PublicKey(secret: Ed25519SecretKey): Ed25519PublicKey =
        Ed25519PublicKey(guard { ed25519PublicFromSecret(secret.bytes()) })

    override fun sign(key: Ed25519SecretKey, message: ByteArray): Ed25519Signature =
        Ed25519Signature(guard { ed25519Sign(key.bytes(), message) })

    override fun verify(
        key: Ed25519PublicKey,
        message: ByteArray,
        signature: Ed25519Signature,
    ): Result<Unit> =
        try {
            ed25519Verify(key.bytes, message, signature.bytes)
            Result.success(Unit)
        } catch (e: CryptoFfiException.SignatureInvalid) {
            Result.failure(CryptoException.SignatureInvalid())
        } catch (e: CryptoFfiException) {
            throw mapCryptoFfiException(e)
        }

    override fun canonicalize(json: String): String = guard { ffiCanonicalJson(json) }

    override fun deriveDek(passphrase: ByteArray, salt: ByteArray): DerivedKey =
        DerivedKey(guard { argon2idDeriveDek(passphrase, salt) })

    override fun seal(
        key: AeadKey,
        nonce: AeadNonce,
        plaintext: ByteArray,
        aad: ByteArray,
    ): ByteArray = guard { chacha20poly1305Seal(key.bytes(), nonce.bytes, plaintext, aad) }

    override fun open(
        key: AeadKey,
        nonce: AeadNonce,
        ciphertext: ByteArray,
        aad: ByteArray,
    ): Result<ByteArray> =
        try {
            Result.success(chacha20poly1305Open(key.bytes(), nonce.bytes, ciphertext, aad))
        } catch (e: CryptoFfiException.DecryptionFailed) {
            Result.failure(CryptoException.DecryptionFailed())
        } catch (e: CryptoFfiException) {
            throw mapCryptoFfiException(e)
        }

    override fun hkdfBlake2s(ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length > 0) { "HKDF length must be positive" }
        return guard { ffiHkdfBlake2s(ikm, info, length.toUInt()) }
    }

    override fun genesisPrevHash(): ByteArray = hashChainGenesisPrevHash()

    override fun eventContentJson(event: LogEvent): String =
        guard { hashChainEventContentJson(event.toFfi()) }

    override fun rowHash(prevHash: ByteArray, event: LogEvent): ByteArray =
        guard { hashChainRowHash(prevHash, event.toFfi()) }

    override fun verifyChain(rows: List<ChainRow>): ChainVerification {
        val v = guard { hashChainVerify(rows.map { it.toFfi() }) }
        return when (v) {
            is FfiChainVerification.Intact -> ChainVerification.Intact(v.verifiedRows.toLong())
            is FfiChainVerification.Broken ->
                ChainVerification.Broken(v.index.toLong(), v.kind.toAdapter())
        }
    }

    // -- conversions -----------------------------------------------------

    private fun LogEvent.toFfi() = FfiLogEvent(reqId, eventType, payloadJson, timestamp)

    private fun ChainRow.toFfi() = FfiChainRow(event.toFfi(), prevHash, hash)

    private fun FfiChainBreakKind.toAdapter(): ChainBreak =
        when (this) {
            is FfiChainBreakKind.ContentTampered ->
                ChainBreak.ContentTampered(expectedHash, storedHash)
            is FfiChainBreakKind.LinkBroken ->
                ChainBreak.LinkBroken(expectedPrev, storedPrev)
        }

    // -- error mapping -------------------------------------------------

    /** Run [block], translating any [CryptoFfiException] to its [CryptoException]. */
    private inline fun <T> guard(block: () -> T): T =
        try {
            block()
        } catch (e: CryptoFfiException) {
            throw mapCryptoFfiException(e)
        }
}
