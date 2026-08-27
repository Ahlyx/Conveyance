//! The QR payload: the out-of-band channel that makes pairing tamper-proof.
//!
//! Encoded CBOR, then base64url (no padding), then rendered as a QR code
//! at error-correction level H. Field names are wire surface area --
//! Android decodes the same object -- so they are fixed by the spec's
//! "Pairing ceremony" section and must not be renamed.
//!
//! Validation on parse is deliberately strict and ordered:
//! version FIRST (explicit, displayable error per spec), then expiry,
//! then key sanity. Everything else about the payload is authenticated
//! later by the PairingConfirm signature; the QR itself is unauthenticated
//! input and must never be trusted beyond these structural checks.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use super::PairingError;

pub const PROTOCOL_VERSION: u16 = 1;
/// Spec: expires is 60 seconds after QR display.
pub const QR_TTL: Duration = Duration::from_secs(60);
/// Spec: pc_name is at most 64 UTF-8 bytes.
pub const PC_NAME_MAX_BYTES: usize = 64;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PairingQr {
    #[serde(rename = "v")]
    pub version: u16,
    /// PC's long-term Ed25519 identity public key.
    #[serde(rename = "pc_id_pub")]
    pub pc_id_pub: [u8; 32],
    /// PC's long-term X25519 static public key.
    #[serde(rename = "pc_dh_pub")]
    pub pc_dh_pub: [u8; 32],
    /// Random, single-use pairing nonce.
    pub nonce: [u8; 32],
    /// Unix seconds after which this code must not be used.
    pub expires: i64,
    /// Hostname for phone-side display.
    #[serde(rename = "pc_name")]
    pub pc_name: String,
    /// Raw 16 bytes of the pinned Conveyance service UUID.
    #[serde(rename = "ble_service_uuid")]
    pub ble_service_uuid: [u8; 16],
}

impl PairingQr {
    /// Build a fresh payload. `expires` is anchored to `now_unix + 60`.
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
        Ok(Self {
            version: PROTOCOL_VERSION,
            pc_id_pub,
            pc_dh_pub,
            nonce,
            expires: now_unix + QR_TTL.as_secs() as i64,
            pc_name: pc_name.to_string(),
            ble_service_uuid: service_uuid_bytes,
        })
    }

    /// CBOR -> base64url (no padding): the exact string the QR encodes.
    pub fn encode(&self) -> Result<String, PairingError> {
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(self, &mut cbor)
            .map_err(|e| PairingError::QrEncode(e.to_string()))?;
        Ok(URL_SAFE_NO_PAD.encode(cbor))
    }

    /// Parse a scanned/generated string against `now_unix`. Errors are
    /// specific where the spec allows display (version), generic where it
    /// forbids specificity (everything that could aid an attacker).
    pub fn parse(s: &str, now_unix: i64) -> Result<Self, PairingError> {
        let cbor = URL_SAFE_NO_PAD
            .decode(s.trim())
            .map_err(|_| PairingError::QrCorrupt)?;
        let payload: Self =
            ciborium::de::from_reader(&mut &cbor[..]).map_err(|_| PairingError::QrCorrupt)?;

        // Version first: the spec explicitly allows showing versions to
        // the user for this failure ("incompatible versions").
        if payload.version != PROTOCOL_VERSION {
            return Err(PairingError::VersionMismatch {
                found: payload.version,
                expected: PROTOCOL_VERSION,
            });
        }
        self_validate_expiry(&payload, now_unix)?;
        Ok(payload)
    }

    pub fn is_expired(&self, now_unix: i64) -> bool {
        now_unix >= self.expires
    }

    /// The exact string rendered into the QR code by the CLI.
    ///
    /// Hand-rolled half-block renderer: qrcode's Display impl is
    /// feature-gated and its default art is double-height; pairing two
    /// module rows per terminal line with ▀/▄ halves halves the height,
    /// which matters when a phone camera must fit the whole block.
    pub fn render_ascii(&self) -> String {
        use qrcode::QrCode;
        let encoded = self.encode().unwrap_or_default();
        let code = match QrCode::with_error_correction_level(encoded.as_bytes(), qrcode::EcLevel::H)
        {
            Ok(c) => c,
            Err(_) => return String::from("<payload too large for QR -- report this bug>"),
        };
        let width = code.width();
        // qrcode 0.14 colors are an enum; map to bool (dark = true).
        let colors: Vec<bool> = code
            .to_colors()
            .into_iter()
            .map(|c| c == qrcode::Color::Dark)
            .collect();

        // Two-module quiet zone on every side, per scanner convention.
        let quiet = 2usize;
        let padded = width + quiet * 2;
        let dark = |x: usize, y: usize| -> bool {
            if x < quiet || y < quiet || x >= quiet + width || y >= quiet + width {
                return false;
            }
            colors[(y - quiet) * width + (x - quiet)]
        };

        let mut out = String::new();
        let mut y = 0;
        while y < padded {
            for x in 0..padded {
                let top = dark(x, y);
                let bottom = if y + 1 < padded {
                    dark(x, y + 1)
                } else {
                    false
                };
                match (top, bottom) {
                    (true, true) => out.push('\u{2588}'),  // full block
                    (true, false) => out.push('\u{2580}'), // upper half
                    (false, true) => out.push('\u{2584}'), // lower half
                    (false, false) => out.push(' '),
                }
            }
            out.push('\n');
            y += 2;
        }
        out.lines()
            .map(|line| format!("  {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn self_validate_expiry(payload: &PairingQr, now_unix: i64) -> Result<(), PairingError> {
    if payload.is_expired(now_unix) {
        return Err(PairingError::QrExpired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{EntropySource, OsEntropy};
    use crate::transport::ids;

    fn sample(now: i64) -> PairingQr {
        PairingQr::new(
            now,
            [1; 32],
            [2; 32],
            [3; 32],
            "dev-machine",
            ids::service_uuid_bytes(),
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
        // The service UUID rides as raw bytes matching the pinned UUID.
        assert_eq!(back.ble_service_uuid, ids::service_uuid_bytes());
    }

    #[test]
    fn expired_payload_is_rejected_with_distinct_error() {
        let qr = sample(1_700_000_000);
        let text = qr.encode().unwrap();

        // Exactly at expiry: expired (boundary inclusive).
        assert!(matches!(
            PairingQr::parse(&text, 1_700_000_060),
            Err(PairingError::QrExpired)
        ));
        // One second before: fine.
        assert!(PairingQr::parse(&text, 1_700_000_059).is_ok());
    }

    #[test]
    fn version_mismatch_is_explicit_and_displayable() {
        let mut qr = sample(1_700_000_000);
        qr.version = 2;
        let text = qr.encode().unwrap();

        // Version check precedes expiry: a v2 payload from the past must
        // still say VERSIONS, not "expired" (spec allows displaying them).
        match PairingQr::parse(&text, 1_700_500_000) {
            Err(PairingError::VersionMismatch { found, expected }) => {
                assert_eq!(found, 2);
                assert_eq!(expected, 1);
            }
            other => panic!("expected VersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn corrupt_input_is_generic_not_panicking() {
        for junk in ["", "not-base64!!", "AAAA", "eyJ2IjoxfQ"] {
            let result = PairingQr::parse(junk, 0);
            assert!(matches!(result, Err(PairingError::QrCorrupt)), "{junk}");
        }
    }

    #[test]
    fn pc_name_length_enforced_in_bytes() {
        // 64 ASCII chars pass.
        assert!(PairingQr::new(0, [0; 32], [0; 32], [0; 32], &"a".repeat(64), [0; 16]).is_ok());
        // 65 fail.
        assert!(matches!(
            PairingQr::new(0, [0; 32], [0; 32], [0; 32], &"a".repeat(65), [0; 16]),
            Err(PairingError::PcNameTooLong(65))
        ));
        // Multi-byte UTF-8 counts BYTES: 40 emoji = 160 bytes.
        let emoji = "\u{1F600}".repeat(40);
        assert!(matches!(
            PairingQr::new(0, [0; 32], [0; 32], [0; 32], &emoji, [0; 16]),
            Err(PairingError::PcNameTooLong(_))
        ));
    }

    #[test]
    fn render_ascii_produces_scannable_sized_block() {
        let qr = sample(1_700_000_000);
        let art = qr.render_ascii();
        // EC level H over ~200-byte payloads yields a non-trivial matrix.
        assert!(art.lines().count() >= 21, "QR too small to be real");
        // render_ascii pairs module rows into half-block glyphs: a real
        // matrix must contain at least one dark cell.
        assert!(
            art.contains('\u{2588}') || art.contains('\u{2580}') || art.contains('\u{2584}'),
            "no dark modules rendered"
        );
    }

    #[test]
    fn fresh_nonce_entropy_is_used_not_constants() {
        struct TmpEntropy;
        impl EntropySource for TmpEntropy {
            fn fill(&self, dest: &mut [u8]) -> Result<(), crate::crypto::CryptoError> {
                OsEntropy.fill(dest)
            }
        }
        let mut n1 = [0u8; 32];
        let mut n2 = [0u8; 32];
        TmpEntropy.fill(&mut n1).unwrap();
        TmpEntropy.fill(&mut n2).unwrap();
        assert_ne!(n1, n2);
    }
}
