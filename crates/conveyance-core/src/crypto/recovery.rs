//! Recovery: BIP-39 phrase → seed → identity keypairs, exactly as the
//! spec's "Recovery" section defines.
//!
//! The pipeline is the security-critical spine of the phone side and the
//! reference for any reimplementation (the Android app must produce
//! byte-identical keys from the same phrase). Every step is therefore
//! pinned:
//!
//! * phrase → seed: BIP-39 PBKDF2-HMAC-SHA512, 2048 rounds, empty
//!   passphrase — tested against TREZOR's published vectors.
//! * seed → keys: [`hkdf_blake2s`](super::hkdf) with **zero salt**
//!   (RFC 5869 §2.2 omission semantics, per the spec amendment) and the
//!   two exact info strings below. The HKDF wiring itself is proven by
//!   RFC 5869 SHA-256 vectors in super::hkdf; see that module for why it
//!   is hand-written at all.
//!
//! The phrase itself is held in a zeroizing string and never `Debug`
//! printed; it is the one artifact whose disclosure defeats everything.

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use super::hkdf::hkdf_blake2s;
use super::{CryptoError, EntropySource};

pub const IDENTITY_ED25519_INFO: &[u8] = b"conveyance-v1-identity-ed25519";
pub const IDENTITY_X25519_INFO: &[u8] = b"conveyance-v1-identity-x25519";

/// A validated English recovery phrase (24 words on generation; restore
/// accepts any valid BIP-39 length).
#[derive(Clone)]
pub struct RecoveryPhrase(Zeroizing<String>);

impl RecoveryPhrase {
    /// Generate a fresh 24-word phrase from 32 bytes drawn from
    /// `entropy`.
    pub fn generate<E: EntropySource>(entropy: &E) -> Result<Self, CryptoError> {
        let mut bytes = [0u8; 32];
        entropy.fill(&mut bytes)?;
        // Any 32 bytes are a valid 256-bit entropy input: the checksum
        // is derived from the entropy, not checked against it, so this
        // cannot fail for freshly generated material.
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &bytes)
            .expect("fresh entropy is always a valid input");
        Ok(Self(Zeroizing::new(mnemonic.to_string())))
    }

    /// Parse user-entered words. Rejects wrong word count, unknown
    /// words, and bad checksum -- all collapsed into one error so a
    /// mistyped phrase gives an attacker no parsing oracle either.
    pub fn from_words(words: &str) -> Result<Self, CryptoError> {
        let normalized = Zeroizing::new(normalize_words(words));
        normalized
            .parse::<Mnemonic>()
            .map(|_| Self(normalized))
            .map_err(|_| CryptoError::BadRecoveryPhrase)
    }

    pub fn as_words(&self) -> impl Iterator<Item = &str> {
        self.0.split_whitespace()
    }

    /// BIP-39 seed (64 bytes). Conveyance derives with an EMPTY
    /// passphrase per spec; the parameter is explicit so call sites show
    /// what was used and tests can exercise official vectors that use
    /// "TREZOR".
    pub fn to_seed(&self, passphrase: &str) -> Seed {
        let mnemonic = self
            .0
            .parse::<Mnemonic>()
            .expect("phrase was validated at construction");
        Seed(Zeroizing::new(mnemonic.to_seed(passphrase)))
    }
}

impl std::fmt::Debug for RecoveryPhrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecoveryPhrase(<redacted>)")
    }
}

fn normalize_words(words: &str) -> String {
    words.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A BIP-39 seed: 64 bytes of high-entropy key material.
#[derive(Clone)]
pub struct Seed(Zeroizing<[u8; 64]>);

impl Seed {
    #[cfg(test)]
    pub(crate) fn expose(&self) -> &[u8; 64] {
        &self.0
    }

    /// Derive both long-term identity secrets from this seed, per spec:
    /// HKDF-BLAKE2s, zero salt, L=32 each, distinct info strings.
    pub fn derive_identity_keys(&self) -> IdentityKeyset {
        let mut ed = [0u8; 32];
        let mut x = [0u8; 32];
        hkdf_blake2s(self.expose_pub(), IDENTITY_ED25519_INFO, &mut ed);
        hkdf_blake2s(self.expose_pub(), IDENTITY_X25519_INFO, &mut x);

        IdentityKeyset {
            ed25519_secret: super::Secret::from_bytes(ed),
            x25519_secret: super::Secret::from_bytes(x),
        }
    }

    fn expose_pub(&self) -> &[u8] {
        &self.0[..]
    }
}

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Seed(<redacted>)")
    }
}

/// Both long-term identity secrets derived from one phrase.
#[derive(Clone)]
pub struct IdentityKeyset {
    /// Feed to [`super::sign::IdentitySecretKey::from_bytes`].
    pub ed25519_secret: super::Secret<32>,
    /// Feed to [`super::dh::DhSecret::from_bytes`].
    pub x25519_secret: super::Secret<32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_support::{CounterEntropy, FailingEntropy};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const ZEROS_24WORD: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    const ONES_12WORD: &str =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";

    /// TREZOR official vector (vectors.json, english): 256-bit zero
    /// entropy, passphrase "TREZOR". Constants transcribed from the
    /// upstream file after two in-memory attempts got them wrong -- these
    /// strings are exactly the kind of thing memory fabricates.
    #[test]
    fn trezor_vector_zeros_256bit() {
        let phrase = RecoveryPhrase::from_words(ZEROS_24WORD).unwrap();
        let seed = phrase.to_seed("TREZOR");
        assert_eq!(
            seed.expose().to_vec(),
            hex(
                "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
            )
        );
    }

    /// Second official vector (8080…80 entropy), proving word-count
    /// flexibility on restore input.
    #[test]
    fn trezor_vector_letter_advice_128bit() {
        let phrase = RecoveryPhrase::from_words(ONES_12WORD).unwrap();
        let seed = phrase.to_seed("TREZOR");
        assert_eq!(
            seed.expose().to_vec(),
            hex(
                "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8"
            )
        );
    }

    /// Third official vector: the classic "abandon … about" 12-word
    /// phrase. Kept because its seed (c55257…) is widely quoted online --
    /// including, previously, in this file attached to the WRONG phrase.
    #[test]
    fn trezor_vector_abandon_about_128bit() {
        let phrase = RecoveryPhrase::from_words(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let seed = phrase.to_seed("TREZOR");
        assert_eq!(
            seed.expose().to_vec(),
            hex(
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
            )
        );
    }

    /// Conveyance's actual derivation uses an EMPTY passphrase (spec).
    /// No official vector publishes those bytes, so what is pinned here:
    /// determinism, and that the passphrase parameter genuinely changes
    /// the output (i.e., we are not accidentally ignoring it).
    #[test]
    fn empty_passphrase_is_deterministic_and_distinct() {
        let phrase = RecoveryPhrase::from_words(ZEROS_24WORD).unwrap();
        let a = phrase.to_seed("");
        let b = phrase.to_seed("");
        assert_eq!(a.expose(), b.expose());
        assert_ne!(a.expose(), phrase.to_seed("TREZOR").expose());

        // The spec's pipeline: to_seed("") feeds HKDF downstream.
        let keys = a.derive_identity_keys();
        let keys_again = b.derive_identity_keys();
        assert_eq!(
            keys.ed25519_secret.expose(),
            keys_again.ed25519_secret.expose()
        );
    }

    #[test]
    fn bad_checksum_and_unknown_words_are_rejected() {
        // Swap the final word (checksum word) of a valid phrase.
        let tampered = ZEROS_24WORD.replace(" art", " zoo");
        assert!(matches!(
            RecoveryPhrase::from_words(&tampered),
            Err(CryptoError::BadRecoveryPhrase)
        ));

        assert!(matches!(
            RecoveryPhrase::from_words("not even close to a real phrase"),
            Err(CryptoError::BadRecoveryPhrase)
        ));
    }

    #[test]
    fn normalization_tolerates_extra_whitespace() {
        let sloppy = "  abandon   abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon  art  ";
        let seed_a = RecoveryPhrase::from_words(ZEROS_24WORD)
            .unwrap()
            .to_seed("");
        let seed_b = RecoveryPhrase::from_words(sloppy).unwrap().to_seed("");
        assert_eq!(seed_a.expose(), seed_b.expose());
    }

    #[test]
    fn generation_is_entropy_driven() {
        assert!(matches!(
            RecoveryPhrase::generate(&FailingEntropy),
            Err(CryptoError::EntropyFailure)
        ));

        let phrase = RecoveryPhrase::generate(&CounterEntropy).unwrap();
        assert_eq!(phrase.as_words().count(), 24);
    }

    #[test]
    fn info_strings_produce_distinct_keys_and_pipeline_is_deterministic() {
        let phrase = RecoveryPhrase::from_words(ZEROS_24WORD).unwrap();
        let seed = phrase.to_seed("");

        let keys_a = seed.derive_identity_keys();
        let keys_b = phrase.to_seed("").derive_identity_keys();
        assert_eq!(
            keys_a.ed25519_secret.expose(),
            keys_b.ed25519_secret.expose()
        );
        assert_eq!(keys_a.x25519_secret.expose(), keys_b.x25519_secret.expose());
        assert_ne!(
            keys_a.ed25519_secret.expose(),
            keys_a.x25519_secret.expose()
        );
    }

    #[test]
    fn derived_secrets_are_usable_by_their_modules() {
        // Proves the handoff between modules is real, end to end:
        // phrase -> seed -> Ed25519 key that signs and verifies.
        let phrase = RecoveryPhrase::from_words(ZEROS_24WORD).unwrap();
        let keys = phrase.to_seed("").derive_identity_keys();

        let sk = crate::crypto::sign::IdentitySecretKey::from_bytes(*keys.ed25519_secret.expose());
        let sig = sk.sign(b"pipeline check");
        sk.public_key().verify(b"pipeline check", &sig).unwrap();

        let dh = crate::crypto::dh::DhSecret::from_bytes(*keys.x25519_secret.expose());
        let _shared = dh.dh(&crate::crypto::dh::DhPublic::from_bytes([7u8; 32]));
    }

    #[test]
    fn debug_never_renders_phrase_or_seed() {
        let phrase = RecoveryPhrase::from_words(ZEROS_24WORD).unwrap();
        let rendered = format!("{:?} {:?}", phrase, phrase.to_seed(""));
        assert!(!rendered.contains("abandon"));
        assert!(!rendered.contains("c55257c3"));
    }
}
