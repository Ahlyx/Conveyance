//! The QR payload: the out-of-band channel that makes pairing tamper-proof.
//!
//! Encoded as CBOR, then base64url without padding. Validation is strict and
//! bounded because the QR is unauthenticated input. Version mismatch is
//! reported before the other checks so the UI can explain incompatibility.

use std::io::Cursor;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use conveyance_crypto::dh::{DhPublic, DhSecret};
use conveyance_crypto::sign::IdentityPublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const QR_TTL: Duration = Duration::from_secs(60);
pub const PC_NAME_MAX_BYTES: usize = 64;
const MAX_ENCODED_QR_BYTES: usize = 4096;
const MAX_QR_FUTURE_SKEW_SECONDS: i64 = 120;

/// Raw byte form of the v1 BLE service UUID. `conveyance-core` re-exports
/// this constant for the PC GATT and QR code paths.
pub const SERVICE_UUID_BYTES: [u8; 16] = [
    0x70, 0x90, 0x31, 0xfe, 0xab, 0xea, 0x43, 0x7f, 0x80, 0x1e, 0xdc, 0x68, 0x72, 0x72, 0x3b, 0x1f,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingQr {
    #[serde(rename = "v")]
    pub version: u16,
    #[serde(rename = "pc_id_pub")]
    pub pc_id_pub: [u8; 32],
    #[serde(rename = "pc_dh_pub")]
    pub pc_dh_pub: [u8; 32],
    pub nonce: [u8; 32],
    pub expires: i64,
    #[serde(rename = "pc_name")]
    pub pc_name: String,
    #[serde(rename = "ble_service_uuid")]
    pub ble_service_uuid: [u8; 16],
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PairingError {
    #[error("pairing failed")]
    PairingFailed,
    #[error("QR code expired -- generate a new one")]
    QrExpired,
    #[error("incompatible protocol versions (found v{found}, expected v{expected})")]
    VersionMismatch { found: u16, expected: u16 },
    #[error("PC name exceeds 64 bytes ({0})")]
    PcNameTooLong(usize),
    #[error("QR encoding failed: {0}")]
    QrEncode(String),
    #[error("QR data corrupt")]
    QrCorrupt,
}

impl PairingQr {
    pub fn new(
        now_unix: i64,
        pc_id_pub: [u8; 32],
        pc_dh_pub: [u8; 32],
        nonce: [u8; 32],
        pc_name: &str,
        service_uuid_bytes: [u8; 16],
    ) -> Result<Self, PairingError> {
        if pc_name.len() > PC_NAME_MAX_BYTES {
            return Err(PairingError::PcNameTooLong(pc_name.len()));
        }
        let qr = Self {
            version: PROTOCOL_VERSION,
            pc_id_pub,
            pc_dh_pub,
            nonce,
            expires: now_unix
                .checked_add(QR_TTL.as_secs() as i64)
                .ok_or(PairingError::PairingFailed)?,
            pc_name: pc_name.to_owned(),
            ble_service_uuid: service_uuid_bytes,
        };
        qr.validate_fields(now_unix, false)?;
        Ok(qr)
    }

    pub fn encode(&self) -> Result<String, PairingError> {
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(self, &mut cbor)
            .map_err(|error| PairingError::QrEncode(error.to_string()))?;
        if cbor.len() > MAX_ENCODED_QR_BYTES {
            return Err(PairingError::QrEncode("payload too large".to_owned()));
        }
        Ok(URL_SAFE_NO_PAD.encode(cbor))
    }

    pub fn parse(encoded: &str, now_unix: i64) -> Result<Self, PairingError> {
        if encoded.len() > MAX_ENCODED_QR_BYTES {
            return Err(PairingError::QrCorrupt);
        }
        let cbor = URL_SAFE_NO_PAD
            .decode(encoded.trim())
            .map_err(|_| PairingError::QrCorrupt)?;
        if cbor.len() > MAX_ENCODED_QR_BYTES {
            return Err(PairingError::QrCorrupt);
        }
        if let Some(found) = decode_version(&cbor)
            && found != PROTOCOL_VERSION
        {
            return Err(PairingError::VersionMismatch {
                found,
                expected: PROTOCOL_VERSION,
            });
        }
        let mut cursor = Cursor::new(cbor.as_slice());
        let qr: Self =
            ciborium::de::from_reader(&mut cursor).map_err(|_| PairingError::QrCorrupt)?;
        if cursor.position() != cbor.len() as u64 {
            return Err(PairingError::QrCorrupt);
        }

        // Keep this first. Incompatible versions are the one QR-validation
        // failure the protocol permits the user interface to name explicitly.
        if qr.version != PROTOCOL_VERSION {
            return Err(PairingError::VersionMismatch {
                found: qr.version,
                expected: PROTOCOL_VERSION,
            });
        }
        qr.validate_fields(now_unix, true)?;
        Ok(qr)
    }

    pub fn is_expired(&self, now_unix: i64) -> bool {
        now_unix >= self.expires
    }

    fn validate_fields(&self, now_unix: i64, check_expiry: bool) -> Result<(), PairingError> {
        if self.pc_name.len() > PC_NAME_MAX_BYTES
            || self.ble_service_uuid != SERVICE_UUID_BYTES
            || self.nonce.iter().all(|byte| *byte == 0)
        {
            return Err(PairingError::PairingFailed);
        }
        IdentityPublicKey::from_bytes(&self.pc_id_pub).map_err(|_| PairingError::PairingFailed)?;

        // X25519 accepts arbitrary u-coordinates, but the low-order points
        // produce an all-zero shared secret. Reject them before connecting.
        let probe = DhSecret::from_bytes([0x42; 32]);
        let peer = DhPublic::from_bytes(self.pc_dh_pub);
        if probe.dh(&peer).iter().all(|byte| *byte == 0) {
            return Err(PairingError::PairingFailed);
        }

        if check_expiry {
            if self.is_expired(now_unix) {
                return Err(PairingError::QrExpired);
            }
            if self.expires.saturating_sub(now_unix) > MAX_QR_FUTURE_SKEW_SECONDS {
                return Err(PairingError::PairingFailed);
            }
        }
        Ok(())
    }

    #[cfg(feature = "render")]
    pub fn render_ascii(&self) -> String {
        use qrcode::QrCode;

        let encoded = self.encode().unwrap_or_default();
        let code = match QrCode::with_error_correction_level(encoded.as_bytes(), qrcode::EcLevel::H)
        {
            Ok(code) => code,
            Err(_) => return String::from("<payload too large for QR -- report this bug>"),
        };
        let width = code.width();
        let colors: Vec<bool> = code
            .to_colors()
            .into_iter()
            .map(|color| color == qrcode::Color::Dark)
            .collect();
        let quiet = 2usize;
        let padded = width + quiet * 2;
        let dark = |x: usize, y: usize| -> bool {
            if x < quiet || y < quiet || x >= quiet + width || y >= quiet + width {
                return false;
            }
            colors[(y - quiet) * width + (x - quiet)]
        };

        let mut output = String::new();
        let mut y = 0;
        while y < padded {
            for x in 0..padded {
                let top = dark(x, y);
                let bottom = y + 1 < padded && dark(x, y + 1);
                output.push(match (top, bottom) {
                    (true, true) => '\u{2588}',
                    (true, false) => '\u{2580}',
                    (false, true) => '\u{2584}',
                    (false, false) => ' ',
                });
            }
            output.push('\n');
            y += 2;
        }
        output
            .lines()
            .map(|line| format!("  {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Read the version field before decoding the version-specific payload
/// shape. A future version can add or rename fields and still receive the
/// protocol's explicit incompatibility error.
fn decode_version(cbor: &[u8]) -> Option<u16> {
    use ciborium::value::Value;

    let mut cursor = Cursor::new(cbor);
    let value: Value = ciborium::de::from_reader(&mut cursor).ok()?;
    if cursor.position() != cbor.len() as u64 {
        return None;
    }
    let Value::Map(fields) = value else {
        return None;
    };
    fields
        .into_iter()
        .find_map(|(key, value)| match (key, value) {
            (Value::Text(key), Value::Integer(version)) if key == "v" => {
                u16::try_from(version).ok()
            }
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use conveyance_crypto::dh::DhSecret;
    use conveyance_crypto::sign::IdentitySecretKey;

    fn sample(now: i64) -> PairingQr {
        PairingQr::new(
            now,
            IdentitySecretKey::from_bytes([1; 32])
                .public_key()
                .to_bytes(),
            DhSecret::from_bytes([2; 32]).public_key().to_bytes(),
            [3; 32],
            "dev-machine",
            SERVICE_UUID_BYTES,
        )
        .unwrap()
    }

    #[test]
    fn round_trip_via_cbor_base64url() {
        let qr = sample(1_700_000_000);
        let text = qr.encode().unwrap();
        let back = PairingQr::parse(&text, 1_700_000_000).unwrap();
        assert_eq!(back, qr);
        assert_eq!(back.expires, 1_700_000_060);
        assert_eq!(back.ble_service_uuid, SERVICE_UUID_BYTES);
    }

    #[test]
    fn expiry_boundary_and_version_precedence_are_pinned() {
        let qr = sample(1_700_000_000);
        let text = qr.encode().unwrap();
        assert_eq!(
            PairingQr::parse(&text, 1_700_000_060),
            Err(PairingError::QrExpired)
        );
        assert!(PairingQr::parse(&text, 1_700_000_059).is_ok());

        let mut old_version = qr;
        old_version.version = 2;
        let encoded = encode_unchecked(&old_version);
        assert_eq!(
            PairingQr::parse(&encoded, 1_700_500_000),
            Err(PairingError::VersionMismatch {
                found: 2,
                expected: 1
            })
        );

        #[derive(Serialize)]
        struct FutureShape {
            v: u16,
            added_in_v2: bool,
        }
        let future_shape = FutureShape {
            v: 2,
            added_in_v2: true,
        };
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&future_shape, &mut cbor).unwrap();
        assert_eq!(
            PairingQr::parse(&URL_SAFE_NO_PAD.encode(cbor), 1_700_000_000),
            Err(PairingError::VersionMismatch {
                found: 2,
                expected: 1
            })
        );
    }

    #[test]
    fn rejects_bad_key_service_nonce_and_excess_future_expiry() {
        let now = 1_700_000_000;
        let good = sample(now);
        for mutation in 0..4 {
            let mut bad = good.clone();
            match mutation {
                0 => bad.pc_id_pub = [0; 32],
                1 => bad.pc_dh_pub = [0; 32],
                2 => bad.ble_service_uuid = [0; 16],
                _ => bad.nonce = [0; 32],
            }
            let text = encode_unchecked(&bad);
            assert_eq!(
                PairingQr::parse(&text, now),
                Err(PairingError::PairingFailed)
            );
        }

        let mut far_future = good;
        far_future.expires = now + 121;
        assert_eq!(
            PairingQr::parse(&encode_unchecked(&far_future), now),
            Err(PairingError::PairingFailed)
        );
    }

    #[test]
    fn rejects_trailing_cbor_and_oversized_qr() {
        let qr = sample(1_700_000_000);
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(&qr, &mut cbor).unwrap();
        cbor.push(0);
        assert_eq!(
            PairingQr::parse(&URL_SAFE_NO_PAD.encode(cbor), 1_700_000_000),
            Err(PairingError::QrCorrupt)
        );
        assert_eq!(
            PairingQr::parse(&"A".repeat(MAX_ENCODED_QR_BYTES + 1), 1_700_000_000),
            Err(PairingError::QrCorrupt)
        );
    }

    fn encode_unchecked(qr: &PairingQr) -> String {
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(qr, &mut cbor).unwrap();
        URL_SAFE_NO_PAD.encode(cbor)
    }
}
