//! Narrow, stateful UniFFI surface for the phone side of pairing.
//!
//! The QR, CBOR envelope, and signature preimage are supplied by the shared
//! `conveyance-pairing` crate. Kotlin gets metadata and wire bytes only; the
//! identity private key remains inside the `UnlockedIdentity` handle.

use std::sync::{Arc, Mutex, MutexGuard};

use conveyance_crypto::sign::IdentityPublicKey;
use conveyance_pairing::{
    PairingAck, PairingConfirm, PairingError, PairingQr, decode_ack_message,
    encode_confirm_message, pairing_payload,
};

use crate::PairingFfiError;
use crate::sealed::UnlockedIdentity;

#[derive(uniffi::Record, Clone)]
pub struct PairingConfirmPayload {
    pub phone_id_pub: Vec<u8>,
    pub phone_dh_pub: Vec<u8>,
    pub wire_message: Vec<u8>,
}

enum PairingPhase {
    Ready,
    ConfirmSent(PairingConfirmPayload),
    Paired,
}

/// A validated QR plus its one-shot phone-side protocol state.
#[derive(uniffi::Object)]
pub struct PendingPairing {
    qr: PairingQr,
    phase: Mutex<PairingPhase>,
}

#[uniffi::export]
pub fn parse_pairing_qr(
    encoded: String,
    now_unix: i64,
) -> Result<Arc<PendingPairing>, PairingFfiError> {
    let qr = PairingQr::parse(&encoded, now_unix).map_err(PairingFfiError::from)?;
    Ok(Arc::new(PendingPairing {
        qr,
        phase: Mutex::new(PairingPhase::Ready),
    }))
}

#[uniffi::export]
impl PendingPairing {
    pub fn pc_name(&self) -> String {
        self.qr.pc_name.clone()
    }

    pub fn pc_id_pub(&self) -> Vec<u8> {
        self.qr.pc_id_pub.to_vec()
    }

    pub fn pc_dh_pub(&self) -> Vec<u8> {
        self.qr.pc_dh_pub.to_vec()
    }

    pub fn ble_service_uuid(&self) -> Vec<u8> {
        self.qr.ble_service_uuid.to_vec()
    }

    pub fn expires(&self) -> i64 {
        self.qr.expires
    }

    /// Sign and encode one PairingConfirm. A QR handle may create a confirm
    /// only once, even if a caller accidentally invokes this concurrently.
    pub fn create_confirm(
        &self,
        identity: Arc<UnlockedIdentity>,
    ) -> Result<PairingConfirmPayload, PairingFfiError> {
        let mut phase = self.lock_phase();
        if !matches!(*phase, PairingPhase::Ready) {
            return Err(PairingFfiError::PairingFailed);
        }

        let phone_id_pub: [u8; 32] = identity
            .ed25519_public()
            .try_into()
            .map_err(|_| PairingFfiError::PairingFailed)?;
        let phone_dh_pub: [u8; 32] = identity
            .x25519_public()
            .try_into()
            .map_err(|_| PairingFfiError::PairingFailed)?;
        let payload = pairing_payload(
            &self.qr.pc_id_pub,
            &self.qr.nonce,
            &phone_id_pub,
            &phone_dh_pub,
        );
        let signature: [u8; 64] = identity
            .sign(payload)
            .try_into()
            .map_err(|_| PairingFfiError::PairingFailed)?;
        let confirm = PairingConfirm {
            phone_id_pub,
            phone_dh_pub,
            signature,
        };
        let result = PairingConfirmPayload {
            phone_id_pub: phone_id_pub.to_vec(),
            phone_dh_pub: phone_dh_pub.to_vec(),
            wire_message: encode_confirm_message(&confirm).map_err(PairingFfiError::from)?,
        };
        *phase = PairingPhase::ConfirmSent(result.clone());
        Ok(result)
    }

    /// Verify the PC's ack binds this exact QR and the phone identity used
    /// for its confirm. Successful verification consumes the pending flow.
    pub fn verify_ack(&self, wire_message: Vec<u8>) -> Result<(), PairingFfiError> {
        let mut phase = self.lock_phase();
        let PairingPhase::ConfirmSent(confirm_payload) = &*phase else {
            return Err(PairingFfiError::PairingFailed);
        };
        let confirm_payload = confirm_payload.clone();
        let ack = decode_ack_message(&wire_message).map_err(PairingFfiError::from)?;
        verify_ack_fields(&self.qr, &confirm_payload, &ack).map_err(PairingFfiError::from)?;
        *phase = PairingPhase::Paired;
        Ok(())
    }
}

impl PendingPairing {
    fn lock_phase(&self) -> MutexGuard<'_, PairingPhase> {
        self.phase
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn verify_ack_fields(
    qr: &PairingQr,
    confirm: &PairingConfirmPayload,
    ack: &PairingAck,
) -> Result<(), PairingError> {
    let phone_id_pub: [u8; 32] = confirm
        .phone_id_pub
        .as_slice()
        .try_into()
        .map_err(|_| PairingError::PairingFailed)?;
    let phone_dh_pub: [u8; 32] = confirm
        .phone_dh_pub
        .as_slice()
        .try_into()
        .map_err(|_| PairingError::PairingFailed)?;
    if ack.nonce != qr.nonce
        || ack.pc_id_pub != qr.pc_id_pub
        || ack.phone_id_pub != phone_id_pub
        || ack.phone_dh_pub != phone_dh_pub
    {
        return Err(PairingError::PairingFailed);
    }
    let pc_public =
        IdentityPublicKey::from_bytes(&qr.pc_id_pub).map_err(|_| PairingError::PairingFailed)?;
    ack.verify(&pc_public)
}

#[cfg(test)]
mod tests {
    use super::*;
    use conveyance_crypto::dh::DhSecret;
    use conveyance_crypto::sign::IdentitySecretKey;
    use conveyance_pairing::{PairingQr, SERVICE_UUID_BYTES, encode_ack_message};

    const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn pending(pc: &IdentitySecretKey) -> PendingPairing {
        let qr = PairingQr::new(
            1_700_000_000,
            pc.public_key().to_bytes(),
            DhSecret::from_bytes([2; 32]).public_key().to_bytes(),
            [3; 32],
            "test-pc",
            SERVICE_UUID_BYTES,
        )
        .unwrap()
        .encode()
        .unwrap();
        match Arc::try_unwrap(parse_pairing_qr(qr, 1_700_000_000).unwrap()) {
            Ok(pending) => pending,
            Err(_) => unreachable!(),
        }
    }

    fn phone_identity() -> Arc<UnlockedIdentity> {
        let content_key = vec![0x42; 32];
        let sealed =
            crate::sealed::create_sealed_identity(TEST_PHRASE.to_owned(), content_key.clone())
                .unwrap();
        crate::sealed::open_sealed_identity(sealed.blob, content_key).unwrap()
    }

    #[test]
    fn confirm_and_ack_use_the_shared_wire_protocol_and_one_shot_state() {
        let pc = IdentitySecretKey::from_bytes([0x55; 32]);
        let pending = pending(&pc);
        let phone = phone_identity();
        let confirm = pending.create_confirm(phone.clone()).unwrap();
        let parsed = conveyance_pairing::decode_confirm_message(&confirm.wire_message).unwrap();
        parsed
            .verify(
                &IdentityPublicKey::from_bytes(&confirm.phone_id_pub.clone().try_into().unwrap())
                    .unwrap(),
                &pending.qr.pc_id_pub,
                &pending.qr.nonce,
            )
            .unwrap();
        assert!(pending.create_confirm(phone).is_err());

        let ack = PairingAck::sign(
            &pc,
            &pending.qr.nonce,
            &pending.qr.pc_id_pub,
            &parsed.phone_id_pub,
            &parsed.phone_dh_pub,
        );
        pending
            .verify_ack(encode_ack_message(&ack).unwrap())
            .unwrap();
        assert!(
            pending
                .verify_ack(encode_ack_message(&ack).unwrap())
                .is_err()
        );
    }

    #[test]
    fn ack_cannot_change_any_bound_identity_field() {
        let pc = IdentitySecretKey::from_bytes([0x55; 32]);
        let pending = pending(&pc);
        let confirm = pending.create_confirm(phone_identity()).unwrap();
        let mut ack = PairingAck::sign(
            &pc,
            &pending.qr.nonce,
            &pending.qr.pc_id_pub,
            &confirm.phone_id_pub.clone().try_into().unwrap(),
            &confirm.phone_dh_pub.clone().try_into().unwrap(),
        );
        ack.nonce[0] ^= 1;
        assert!(
            pending
                .verify_ack(encode_ack_message(&ack).unwrap())
                .is_err()
        );
    }
}
