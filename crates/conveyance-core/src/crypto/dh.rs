//! X25519 Diffie-Hellman (`x25519-dalek`).
//!
//! X25519 appears twice in Conveyance: as the long-term static key each
//! side learns during pairing (the `*_dh_pub` fields), and as the DH
//! inside the Noise_KK handshake in phase 3. This module covers the
//! standalone primitive; Noise composition is snow's job and is not
//! reimplemented here.
//!
//! Vectors are RFC 7748's own: §5.2 for the raw scalar multiplication
//! and §6.1 for the full Alice/Bob exchange. The `static_secrets`
//! feature is required to construct secrets from raw bytes -- which is
//! exactly what identity persistence needs -- and it also brings
//! zeroize-on-drop for `StaticSecret`.

use x25519_dalek::{PublicKey, StaticSecret};

use super::{CryptoError, EntropySource};

/// An X25519 secret key. Clamping happens on use, per RFC 7748; callers
/// cannot forget it because dalek does it internally.
#[derive(Clone)]
pub struct DhSecret(StaticSecret);

impl DhSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    pub fn generate<E: EntropySource>(entropy: &E) -> Result<Self, CryptoError> {
        let mut bytes = [0u8; 32];
        entropy.fill(&mut bytes)?;
        Ok(Self::from_bytes(bytes))
    }

    /// Raw scalar bytes for encrypted-at-rest persistence.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> DhPublic {
        DhPublic(PublicKey::from(&self.0))
    }

    /// Raw X25519: compute the shared secret with a peer public key.
    pub fn dh(&self, peer: &DhPublic) -> [u8; 32] {
        self.0.diffie_hellman(&peer.0).to_bytes()
    }
}

impl std::fmt::Debug for DhSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DhSecret(<redacted>)")
    }
}

/// An X25519 public key.
#[derive(Clone, Debug)]
pub struct DhPublic(PublicKey);

impl DhPublic {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(PublicKey::from(bytes))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_support::{CounterEntropy, FailingEntropy};

    fn hex32(s: &str) -> [u8; 32] {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    /// RFC 7748 §5.2, both X25519 vectors. Constants transcribed from
    /// the RFC text itself after an in-memory transcription produced a
    /// u-coordinate that matched the real one for only ten hex digits --
    /// exactly the class of error this suite exists to catch. Do not
    /// "fix" these from memory; re-fetch the RFC if they look wrong.
    #[test]
    fn rfc7748_scalar_mult_vectors() {
        // Vector 1.
        let scalar = DhSecret::from_bytes(hex32(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        ));
        let u = DhPublic::from_bytes(hex32(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        ));
        assert_eq!(
            scalar.dh(&u),
            hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        );

        // Vector 2.
        let scalar2 = DhSecret::from_bytes(hex32(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        ));
        let u2 = DhPublic::from_bytes(hex32(
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        ));
        assert_eq!(
            scalar2.dh(&u2),
            hex32("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
        );
    }

    /// RFC 7748 §6.1: full Alice/Bob exchange, including public key
    /// derivation from private keys.
    #[test]
    fn rfc7748_diffie_hellman_alice_bob() {
        let alice_sk = DhSecret::from_bytes(hex32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let bob_sk = DhSecret::from_bytes(hex32(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));

        assert_eq!(
            alice_sk.public_key().to_bytes(),
            hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            bob_sk.public_key().to_bytes(),
            hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );

        let shared_ab = alice_sk.dh(&bob_sk.public_key());
        let shared_ba = bob_sk.dh(&alice_sk.public_key());
        assert_eq!(shared_ab, shared_ba);
        assert_eq!(
            shared_ab,
            hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
    }

    #[test]
    fn generate_propagates_entropy_failure_and_round_trips() {
        assert!(matches!(
            DhSecret::generate(&FailingEntropy),
            Err(CryptoError::EntropyFailure)
        ));

        let sk = DhSecret::generate(&CounterEntropy).unwrap();
        let rebuilt = DhSecret::from_bytes(sk.to_bytes());
        let other = DhSecret::generate(&CounterEntropy).unwrap();
        assert_eq!(sk.public_key().to_bytes(), rebuilt.public_key().to_bytes());
        assert_eq!(sk.dh(&other.public_key()), rebuilt.dh(&other.public_key()));
    }

    #[test]
    fn secret_debug_is_redacted() {
        let sk = DhSecret::from_bytes([0x42; 32]);
        assert!(!format!("{sk:?}").contains("424242"));
    }
}
