//! PairingConfirm and PairingAck, with the spec's raw-concatenation
//! signatures.
//!
//! SECURITY NOTE: Confirm and Ack use the SAME context string
//! ("conveyance-pair-v1"); they are distinguished by signer identity
//! (phone_id vs pc_id), not by context. A verifier that used the wrong
//! pubkey fails signature verification regardless. This is a deliberate
//! spec choice; do not add role-specific context strings without a spec
//! amendment.
//!
//! Unlike the phase-4 response signatures, these payloads are RAW BYTE
//! CONCATENATION -- context || 32-byte fields in the exact sequence the
//! pairing ceremony section lists -- not canonical JSON. Both facts are
//! pinned by tests; Android must concatenate identically.

use serde::{Deserialize, Serialize};

use crate::crypto::sign::{IdentityPublicKey, IdentitySecretKey};
use crate::wire::ProtocolError;

pub const PAIR_CONTEXT: &[u8] = b"conveyance-pair-v1";

/// Phone -> PC, over the (plaintext) framing layer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PairingConfirm {
    /// The phone's long-term Ed25519 identity public key.
    pub phone_id_pub: [u8; 32],
    /// The phone's long-term X25519 static public key.
    pub phone_dh_pub: [u8; 32],
    /// Ed25519 by phone_id_priv over PAIR_CONTEXT || pc_id_pub || nonce
    /// || phone_id_pub || phone_dh_pub.
    #[serde(with = "crate::wire::message::signature_serde")]
    pub signature: [u8; 64],
}

/// PC -> phone, same field set signed by the PC's identity key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PairingAck {
    pub nonce: [u8; 32],
    pub pc_id_pub: [u8; 32],
    pub phone_id_pub: [u8; 32],
    pub phone_dh_pub: [u8; 32],
    #[serde(with = "crate::wire::message::signature_serde")]
    pub signature: [u8; 64],
}

/// `"conveyance-pair-v1" || pc_id_pub || nonce || phone_id_pub ||
/// phone_dh_pub` -- raw concatenation, exactly the byte sequence the
/// spec prescribes.
fn pairing_payload(
    pc_id_pub: &[u8; 32],
    nonce: &[u8; 32],
    phone_id_pub: &[u8; 32],
    phone_dh_pub: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(PAIR_CONTEXT.len() + 128);
    out.extend_from_slice(PAIR_CONTEXT);
    out.extend_from_slice(pc_id_pub);
    out.extend_from_slice(nonce);
    out.extend_from_slice(phone_id_pub);
    out.extend_from_slice(phone_dh_pub);
    out
}

impl PairingConfirm {
    /// Sign on the phone side (and in the mock harness).
    pub fn sign(
        phone_id_secret: &IdentitySecretKey,
        pc_id_pub: &[u8; 32],
        nonce: &[u8; 32],
        phone_id_pub: &[u8; 32],
        phone_dh_pub: &[u8; 32],
    ) -> Self {
        let payload = pairing_payload(pc_id_pub, nonce, phone_id_pub, phone_dh_pub);
        let signature = phone_id_secret.sign(&payload);
        Self {
            phone_id_pub: *phone_id_pub,
            phone_dh_pub: *phone_dh_pub,
            signature,
        }
    }

    /// Verify on the PC side against values the PC itself chose or
    /// expects. `pc_id_pub` and `nonce` come from the QR the PC just
    /// displayed; the phone keys are whatever the confirm claims -- their
    /// authenticity comes from THIS verification, nothing else.
    pub fn verify(
        &self,
        phone_public: &IdentityPublicKey,
        pc_id_pub: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Result<(), ProtocolError> {
        let payload = pairing_payload(pc_id_pub, nonce, &self.phone_id_pub, &self.phone_dh_pub);
        phone_public
            .verify(&payload, &self.signature)
            .map_err(|_| ProtocolError::SignatureInvalid)
    }
}

impl PairingAck {
    /// Sign on the PC side.
    pub fn sign(
        pc_id_secret: &IdentitySecretKey,
        nonce: &[u8; 32],
        pc_id_pub: &[u8; 32],
        phone_id_pub: &[u8; 32],
        phone_dh_pub: &[u8; 32],
    ) -> Self {
        let payload = pairing_payload(pc_id_pub, nonce, phone_id_pub, phone_dh_pub);
        let signature = pc_id_secret.sign(&payload);
        Self {
            nonce: *nonce,
            pc_id_pub: *pc_id_pub,
            phone_id_pub: *phone_id_pub,
            phone_dh_pub: *phone_dh_pub,
            signature,
        }
    }

    /// Verify on the phone side.
    pub fn verify(&self, pc_public: &IdentityPublicKey) -> Result<(), ProtocolError> {
        let payload = pairing_payload(
            &self.pc_id_pub,
            &self.nonce,
            &self.phone_id_pub,
            &self.phone_dh_pub,
        );
        pc_public
            .verify(&payload, &self.signature)
            .map_err(|_| ProtocolError::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_support::CounterEntropy;

    fn key() -> IdentitySecretKey {
        IdentitySecretKey::generate(&CounterEntropy).unwrap()
    }

    fn trio() -> ([u8; 32], [u8; 32], [u8; 32]) {
        (
            [0xAA; 32], // pc id pub
            [0xBB; 32], // nonce
            [0xCC; 32], // phone dh pub placeholder (id filled per test)
        )
    }

    #[test]
    fn confirm_sign_verify_round_trip() {
        let phone_key = key();
        let (pc_pub, nonce, _) = trio();
        let phone_id_pub = phone_key.public_key().to_bytes();
        let phone_dh_pub = [0xDD; 32];

        let confirm =
            PairingConfirm::sign(&phone_key, &pc_pub, &nonce, &phone_id_pub, &phone_dh_pub);
        confirm
            .verify(&phone_key.public_key(), &pc_pub, &nonce)
            .expect("valid confirm must verify");
    }

    #[test]
    fn payload_is_exact_spec_concatenation() {
        // Byte-level pin: context then the four 32-byte fields in spec
        // order. If this drifts, Android signatures stop verifying with
        // no error anywhere near the cause.
        let phone_key = key();
        let pc_pub = [0x11; 32];
        let nonce = [0x22; 32];
        let phone_id_pub = [0x33; 32];
        let phone_dh_pub = [0x44; 32];

        let confirm =
            PairingConfirm::sign(&phone_key, &pc_pub, &nonce, &phone_id_pub, &phone_dh_pub);

        // Recompute independently from the raw pieces the signer used:
        // signing is deterministic over the payload, so re-signing the
        // expected bytes must equal the stored signature.
        let mut expected = Vec::new();
        expected.extend_from_slice(b"conveyance-pair-v1");
        expected.extend_from_slice(&pc_pub);
        expected.extend_from_slice(&nonce);
        expected.extend_from_slice(&phone_id_pub);
        expected.extend_from_slice(&phone_dh_pub);
        let independent_sig = phone_key.sign(&expected);

        assert_eq!(confirm.signature.to_vec(), independent_sig.to_vec());
    }

    #[test]
    fn tampering_any_field_breaks_verification() {
        let phone_key = key();
        let (mut pc_pub, nonce, _) = trio();
        let phone_id_pub = phone_key.public_key().to_bytes();

        let confirm = PairingConfirm::sign(&phone_key, &pc_pub, &nonce, &phone_id_pub, &[0xDD; 32]);
        let pk = phone_key.public_key();

        confirm.verify(&pk, &pc_pub, &nonce).unwrap();

        // Wrong PC pubkey (different QR than what was signed).
        pc_pub[0] ^= 1;
        assert!(matches!(
            confirm.verify(&pk, &pc_pub, &nonce),
            Err(ProtocolError::SignatureInvalid)
        ));
        pc_pub[0] ^= 1;

        // Wrong nonce (replayed into a new ceremony).
        let mut other_nonce = nonce;
        other_nonce[31] ^= 1;
        assert!(matches!(
            confirm.verify(&pk, &pc_pub, &other_nonce),
            Err(ProtocolError::SignatureInvalid)
        ));

        // Tampered embedded DH key.
        let mut tampered = confirm.clone();
        tampered.phone_dh_pub[0] ^= 1;
        assert!(matches!(
            tampered.verify(&pk, &pc_pub, &nonce),
            Err(ProtocolError::SignatureInvalid)
        ));

        // Tampered signature bytes themselves.
        let mut tampered = confirm.clone();
        tampered.signature[63] ^= 1;
        assert!(matches!(
            tampered.verify(&pk, &pc_pub, &nonce),
            Err(ProtocolError::SignatureInvalid)
        ));

        // Entirely different phone identity claiming someone else's DH key.
        let impostor = key();
        let forged = PairingConfirm::sign(
            &impostor,
            &pc_pub,
            &nonce,
            &impostor.public_key().to_bytes(),
            &[0xDD; 32],
        );
        assert!(
            matches!(
                forged.verify(&pk, &pc_pub, &nonce),
                Err(ProtocolError::SignatureInvalid)
            ),
            "impostor signed with its own key but claims mismatched identity set"
        );
    }

    #[test]
    fn ack_sign_verify_and_cross_key_rejection() {
        let pc_key = key();
        let phone_key = key();
        let nonce = [0x22; 32];
        let pc_pub = pc_key.public_key().to_bytes();
        let phone_pub = phone_key.public_key().to_bytes();
        let phone_dh = [0xEE; 32];

        let ack = PairingAck::sign(&pc_key, &nonce, &pc_pub, &phone_pub, &phone_dh);

        ack.verify(&pc_key.public_key()).unwrap();

        // Phone-side check with the WRONG PC key fails.
        assert!(matches!(
            ack.verify(&phone_key.public_key()),
            Err(ProtocolError::SignatureInvalid)
        ));

        // A swapped field breaks it.
        let mut bad = ack.clone();
        std::mem::swap(&mut bad.nonce[0], &mut bad.pc_id_pub[0]);
        assert!(matches!(
            bad.verify(&pc_key.public_key()),
            Err(ProtocolError::SignatureInvalid)
        ));
    }
}
