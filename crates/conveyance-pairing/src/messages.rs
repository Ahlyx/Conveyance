//! PairingConfirm and PairingAck shared by the daemon and Android bridge.

use std::io::Cursor;

use crate::PairingError;
use conveyance_crypto::sign::{IdentityPublicKey, IdentitySecretKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const PAIR_CONTEXT: &[u8] = b"conveyance-pair-v1";
const MAX_PAIRING_MESSAGE_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingConfirm {
    pub phone_id_pub: [u8; 32],
    pub phone_dh_pub: [u8; 32],
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingAck {
    pub nonce: [u8; 32],
    pub pc_id_pub: [u8; 32],
    pub phone_id_pub: [u8; 32],
    pub phone_dh_pub: [u8; 32],
    #[serde(with = "signature_serde")]
    pub signature: [u8; 64],
}

/// Exact signature preimage: context || pc_id_pub || nonce || phone_id_pub
/// || phone_dh_pub. No JSON encoding or separators.
pub fn pairing_payload(
    pc_id_pub: &[u8; 32],
    nonce: &[u8; 32],
    phone_id_pub: &[u8; 32],
    phone_dh_pub: &[u8; 32],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(PAIR_CONTEXT.len() + 128);
    payload.extend_from_slice(PAIR_CONTEXT);
    payload.extend_from_slice(pc_id_pub);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(phone_id_pub);
    payload.extend_from_slice(phone_dh_pub);
    payload
}

impl PairingConfirm {
    pub fn sign(
        phone_id_secret: &IdentitySecretKey,
        pc_id_pub: &[u8; 32],
        nonce: &[u8; 32],
        phone_id_pub: &[u8; 32],
        phone_dh_pub: &[u8; 32],
    ) -> Self {
        let signature = phone_id_secret.sign(&pairing_payload(
            pc_id_pub,
            nonce,
            phone_id_pub,
            phone_dh_pub,
        ));
        Self {
            phone_id_pub: *phone_id_pub,
            phone_dh_pub: *phone_dh_pub,
            signature,
        }
    }

    pub fn verify(
        &self,
        phone_public: &IdentityPublicKey,
        pc_id_pub: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Result<(), PairingError> {
        phone_public
            .verify(
                &pairing_payload(pc_id_pub, nonce, &self.phone_id_pub, &self.phone_dh_pub),
                &self.signature,
            )
            .map_err(|_| PairingError::PairingFailed)
    }
}

impl PairingAck {
    pub fn sign(
        pc_id_secret: &IdentitySecretKey,
        nonce: &[u8; 32],
        pc_id_pub: &[u8; 32],
        phone_id_pub: &[u8; 32],
        phone_dh_pub: &[u8; 32],
    ) -> Self {
        let signature = pc_id_secret.sign(&pairing_payload(
            pc_id_pub,
            nonce,
            phone_id_pub,
            phone_dh_pub,
        ));
        Self {
            nonce: *nonce,
            pc_id_pub: *pc_id_pub,
            phone_id_pub: *phone_id_pub,
            phone_dh_pub: *phone_dh_pub,
            signature,
        }
    }

    pub fn verify(&self, pc_public: &IdentityPublicKey) -> Result<(), PairingError> {
        pc_public
            .verify(
                &pairing_payload(
                    &self.pc_id_pub,
                    &self.nonce,
                    &self.phone_id_pub,
                    &self.phone_dh_pub,
                ),
                &self.signature,
            )
            .map_err(|_| PairingError::PairingFailed)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PairingWireMessage {
    PairingConfirm(PairingConfirm),
    PairingAck(PairingAck),
}

pub fn encode_confirm_message(confirm: &PairingConfirm) -> Result<Vec<u8>, PairingError> {
    encode_message(&PairingWireMessage::PairingConfirm(confirm.clone()))
}

pub fn encode_ack_message(ack: &PairingAck) -> Result<Vec<u8>, PairingError> {
    encode_message(&PairingWireMessage::PairingAck(ack.clone()))
}

pub fn decode_confirm_message(bytes: &[u8]) -> Result<PairingConfirm, PairingError> {
    match decode_message(bytes)? {
        PairingWireMessage::PairingConfirm(confirm) => Ok(confirm),
        PairingWireMessage::PairingAck(_) => Err(PairingError::PairingFailed),
    }
}

pub fn decode_ack_message(bytes: &[u8]) -> Result<PairingAck, PairingError> {
    match decode_message(bytes)? {
        PairingWireMessage::PairingAck(ack) => Ok(ack),
        PairingWireMessage::PairingConfirm(_) => Err(PairingError::PairingFailed),
    }
}

fn encode_message(message: &PairingWireMessage) -> Result<Vec<u8>, PairingError> {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(message, &mut encoded).map_err(|_| PairingError::PairingFailed)?;
    if encoded.len() > MAX_PAIRING_MESSAGE_BYTES {
        return Err(PairingError::PairingFailed);
    }
    Ok(encoded)
}

fn decode_message(bytes: &[u8]) -> Result<PairingWireMessage, PairingError> {
    if bytes.len() > MAX_PAIRING_MESSAGE_BYTES {
        return Err(PairingError::PairingFailed);
    }
    let mut cursor = Cursor::new(bytes);
    let message: PairingWireMessage =
        ciborium::de::from_reader(&mut cursor).map_err(|_| PairingError::PairingFailed)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(PairingError::PairingFailed);
    }
    Ok(message)
}

mod signature_serde {
    use super::*;

    pub fn serialize<S: Serializer>(
        signature: &[u8; 64],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            let encoded = signature
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            serializer.serialize_str(&encoded)
        } else {
            serializer.serialize_bytes(signature)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = [u8; 64];
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a 64-byte Ed25519 signature")
            }
            fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
                value
                    .try_into()
                    .map_err(|_| E::custom("signature must be 64 bytes"))
            }
            fn visit_byte_buf<E: serde::de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
                value
                    .as_slice()
                    .try_into()
                    .map_err(|_| E::custom("signature must be 64 bytes"))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut bytes = [0u8; 64];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(65, &self));
                }
                Ok(bytes)
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.len() != 128 {
                    return Err(E::custom("signature must be 64 bytes"));
                }
                let mut bytes = [0u8; 64];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                        .map_err(E::custom)?;
                }
                Ok(bytes)
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use conveyance_crypto::dh::DhSecret;

    #[test]
    fn signing_preimage_and_wire_round_trip_are_stable() {
        let phone = IdentitySecretKey::from_bytes([1; 32]);
        let pc = IdentitySecretKey::from_bytes([2; 32]);
        let pc_pub = pc.public_key().to_bytes();
        let phone_id_pub = phone.public_key().to_bytes();
        let phone_dh_pub = DhSecret::from_bytes([3; 32]).public_key().to_bytes();
        let nonce = [4; 32];

        let confirm = PairingConfirm::sign(&phone, &pc_pub, &nonce, &phone_id_pub, &phone_dh_pub);
        confirm
            .verify(&phone.public_key(), &pc_pub, &nonce)
            .unwrap();
        assert_eq!(
            &pairing_payload(&pc_pub, &nonce, &phone_id_pub, &phone_dh_pub)[..PAIR_CONTEXT.len()],
            PAIR_CONTEXT
        );
        let encoded = encode_confirm_message(&confirm).unwrap();
        assert_eq!(decode_confirm_message(&encoded).unwrap(), confirm);

        let ack = PairingAck::sign(&pc, &nonce, &pc_pub, &phone_id_pub, &phone_dh_pub);
        ack.verify(&pc.public_key()).unwrap();
        let encoded = encode_ack_message(&ack).unwrap();
        assert_eq!(decode_ack_message(&encoded).unwrap(), ack);
    }

    #[test]
    fn ack_must_match_the_expected_phone_and_pc_fields() {
        let phone = IdentitySecretKey::from_bytes([1; 32]);
        let pc = IdentitySecretKey::from_bytes([2; 32]);
        let pc_pub = pc.public_key().to_bytes();
        let phone_id = phone.public_key().to_bytes();
        let phone_dh = DhSecret::from_bytes([3; 32]).public_key().to_bytes();
        let ack = PairingAck::sign(&pc, &[4; 32], &pc_pub, &phone_id, &phone_dh);
        ack.verify(&pc.public_key()).unwrap();
        let mut wrong_nonce = ack.clone();
        wrong_nonce.nonce[0] ^= 1;
        assert!(wrong_nonce.verify(&pc.public_key()).is_err());
    }
}
