//! The cross-implementation Noise_KK test-vector set.
//!
//! [`build_document`] runs a full fixed-ephemeral handshake and a few
//! transport messages through *this crate's* wrapper and records the
//! bytes. Two consumers:
//!
//! * `examples/emit_noise_fixtures.rs` writes it to
//!   `android/app/src/androidTest/assets/noise_fixtures.json`, which the
//!   Android **instrumented** suite replays through the real
//!   snow-backed UniFFI bridge — asserting the phone produces the same
//!   handshake and transport bytes the PC daemon would.
//! * The `#[cfg(test)]` block below rebuilds it and diffs the committed
//!   file, so a change to the wrapper that is not mirrored into the
//!   fixture fails `cargo test`, not just Android CI's diff gate.
//!
//! The emitter also asserts, before writing, that the wrapper's message
//! 1 / message 2 bytes are **identical to raw `snow`** driven with the
//! same keys and ephemerals. A wrapper that ever grew a prologue, a PSK,
//! or a non-empty payload would fail that assert here rather than in
//! Phase 11 against the real daemon.
//!
//! Everything is fixed — a fixed ephemeral has no forward secrecy, which
//! is why this whole module is gated behind `test-vectors` /
//! `cfg(test)`.

use serde_json::{Value, json};

use crate::{Role, SessionHandshake};
use conveyance_crypto::Secret;
use conveyance_crypto::dh::DhSecret;

/// Bump when the document shape changes so a stale Kotlin loader fails
/// loudly rather than skipping fields.
pub const SCHEMA_VERSION: u64 = 1;

// Fixed key material. Any 32 bytes are a valid X25519 secret (the impl
// clamps); these are not phrase-derived because the `test-vectors` FFI
// path takes a raw static, not an `UnlockedIdentity` handle.
const PHONE_STATIC: [u8; 32] = [0x11; 32];
const PC_STATIC: [u8; 32] = [0x22; 32];
const PHONE_EPHEMERAL: [u8; 32] = [0x33; 32];
const PC_EPHEMERAL: [u8; 32] = [0x44; 32];
const WRONG_PC_STATIC: [u8; 32] = [0x99; 32];

const PHONE_TO_PC_PLAINTEXTS: [&[u8]; 3] =
    [b"{\"type\":\"ping\"}", b"a second transport message", b""];
const PC_TO_PHONE_PLAINTEXTS: [&[u8]; 2] = [b"{\"type\":\"pong\"}", b"{\"decision\":\"approved\"}"];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    DhSecret::from_bytes(*secret).public_key().to_bytes()
}

/// A completed pair of transports from a fixed-ephemeral KK handshake.
fn handshake_pair(
    phone_static: &[u8; 32],
    pc_static: &[u8; 32],
) -> (
    crate::SessionTransport,
    crate::SessionTransport,
    Vec<u8>,
    Vec<u8>,
) {
    let phone = Secret::from_bytes(*phone_static);
    let pc = Secret::from_bytes(*pc_static);
    let pc_pub = public_of(pc_static);
    let phone_pub = public_of(phone_static);

    let mut init =
        SessionHandshake::with_fixed_ephemeral(Role::Initiator, &phone, &pc_pub, &PHONE_EPHEMERAL)
            .expect("fixed-ephemeral initiator builds");
    let mut resp =
        SessionHandshake::with_fixed_ephemeral(Role::Responder, &pc, &phone_pub, &PC_EPHEMERAL)
            .expect("fixed-ephemeral responder builds");

    let m1 = init.write_message(b"").expect("msg 1");
    resp.read_message(&m1).expect("responder reads msg 1");
    let m2 = resp.write_message(b"").expect("msg 2");
    init.read_message(&m2).expect("initiator reads msg 2");

    (
        init.into_transport().expect("initiator transport"),
        resp.into_transport().expect("responder transport"),
        m1,
        m2,
    )
}

/// Message 1 / message 2 computed with **raw snow**, no wrapper.
fn raw_snow_messages() -> (Vec<u8>, Vec<u8>) {
    let params: snow::params::NoiseParams = crate::PATTERN.parse().unwrap();
    let pc_pub = public_of(&PC_STATIC);
    let phone_pub = public_of(&PHONE_STATIC);

    let mut init = snow::Builder::new(params.clone())
        .local_private_key(&PHONE_STATIC)
        .unwrap()
        .remote_public_key(&pc_pub)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&PHONE_EPHEMERAL)
        .build_initiator()
        .unwrap();
    let mut resp = snow::Builder::new(params)
        .local_private_key(&PC_STATIC)
        .unwrap()
        .remote_public_key(&phone_pub)
        .unwrap()
        .fixed_ephemeral_key_for_testing_only(&PC_EPHEMERAL)
        .build_responder()
        .unwrap();

    let mut buf = vec![0u8; 65535];
    let n = init.write_message(b"", &mut buf).unwrap();
    let m1 = buf[..n].to_vec();
    let mut buf2 = vec![0u8; 65535];
    resp.read_message(&m1, &mut buf2).unwrap();
    let n = resp.write_message(b"", &mut buf).unwrap();
    let m2 = buf[..n].to_vec();
    (m1, m2)
}

/// Build the full fixture document. Deterministic: same bytes every call.
pub fn build_document() -> Value {
    let (mut phone_tx, mut pc_tx, m1, m2) = handshake_pair(&PHONE_STATIC, &PC_STATIC);

    // Defense in depth: the wrapper must add nothing snow doesn't.
    let (raw_m1, raw_m2) = raw_snow_messages();
    assert_eq!(
        m1, raw_m1,
        "wrapper message 1 differs from raw snow — a prologue / PSK / payload crept in"
    );
    assert_eq!(m2, raw_m2, "wrapper message 2 differs from raw snow");

    let phone_to_pc: Vec<Value> = PHONE_TO_PC_PLAINTEXTS
        .iter()
        .map(|pt| {
            json!({ "plaintext_hex": hex(pt), "ciphertext_hex": hex(&phone_tx.send(pt).unwrap()) })
        })
        .collect();
    let pc_to_phone: Vec<Value> = PC_TO_PHONE_PLAINTEXTS
        .iter()
        .map(|pt| {
            json!({ "plaintext_hex": hex(pt), "ciphertext_hex": hex(&pc_tx.send(pt).unwrap()) })
        })
        .collect();

    // reject: wrong PC static -> the phone's read of the honest msg2 fails.
    let wrong_pc_pub = public_of(&WRONG_PC_STATIC);
    let phone = Secret::from_bytes(PHONE_STATIC);
    let mut bad_init = SessionHandshake::with_fixed_ephemeral(
        Role::Initiator,
        &phone,
        &wrong_pc_pub,
        &PHONE_EPHEMERAL,
    )
    .unwrap();
    let _ = bad_init.write_message(b"").unwrap();
    assert!(
        matches!(
            bad_init.read_message(&m2),
            Err(crate::NoiseError::HandshakeFailed)
        ),
        "a phone that used the wrong PC static must fail reading the honest msg2"
    );

    // reject: a tampered pc->phone ciphertext, decrypted by a fresh phone.
    // Two handshake instances with the same fixed material derive the
    // same transport keys, so a nonce-0 ciphertext from one opens on the
    // other -- unless a byte is flipped.
    let (_, mut sender_pc_tx, ..) = handshake_pair(&PHONE_STATIC, &PC_STATIC);
    let mut tampered = sender_pc_tx.send(b"tamper me").unwrap();
    tampered[0] ^= 0x80;
    let (mut verifier_phone_tx, ..) = handshake_pair(&PHONE_STATIC, &PC_STATIC);
    assert!(
        matches!(
            verifier_phone_tx.receive(&tampered),
            Err(crate::NoiseError::SessionEnded)
        ),
        "a tampered transport message must fail to open"
    );

    json!({
        "schema_version": SCHEMA_VERSION,
        "_comment": "Emitted by `cargo run -p conveyance-noise --features test-vectors \
                     --example emit_noise_fixtures`. Do not hand-edit. CI regenerates and \
                     fails on any diff.",
        "pattern": crate::PATTERN,
        "note": "phone = initiator, pc = responder. Handshake payloads empty, no prologue, no PSK.",
        "phone": {
            "x25519_secret_hex": hex(&PHONE_STATIC),
            "x25519_public_hex": hex(&public_of(&PHONE_STATIC)),
            "ephemeral_hex": hex(&PHONE_EPHEMERAL),
        },
        "pc": {
            "x25519_secret_hex": hex(&PC_STATIC),
            "x25519_public_hex": hex(&public_of(&PC_STATIC)),
            "ephemeral_hex": hex(&PC_EPHEMERAL),
        },
        "handshake": { "msg1_hex": hex(&m1), "msg2_hex": hex(&m2) },
        "transport": { "phone_to_pc": phone_to_pc, "pc_to_phone": pc_to_phone },
        "reject": {
            "wrong_pc_public_hex": hex(&wrong_pc_pub),
            "wrong_pc_expect": "HandshakeFailed",
            "tampered_pc_to_phone_ciphertext_hex": hex(&tampered),
            "tampered_expect": "SessionEnded",
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_is_deterministic() {
        assert_eq!(build_document(), build_document());
    }

    #[test]
    fn committed_fixture_matches_current_wrapper() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../android/app/src/androidTest/assets/noise_fixtures.json");
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

        let mut fresh = serde_json::to_string_pretty(&build_document()).unwrap();
        fresh.push('\n');

        if committed != fresh {
            let first = committed
                .lines()
                .zip(fresh.lines())
                .enumerate()
                .find(|(_, (a, b))| a != b)
                .map(|(i, (a, b))| format!("line {}:\n  committed: {a}\n  current:   {b}", i + 1))
                .unwrap_or_else(|| "(length differs)".to_string());
            panic!(
                "noise_fixtures.json is stale.\n{first}\n\nRegenerate:\n  \
                 cargo run -p conveyance-noise --features test-vectors --example \
                 emit_noise_fixtures -- android/app/src/androidTest/assets/noise_fixtures.json"
            );
        }
    }
}
