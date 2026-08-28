//! The canonical cross-implementation test-vector set for this crate.
//!
//! [`build_document`] returns a JSON value with one object per primitive,
//! each computed straight from this crate's public API. Two consumers:
//!
//! * `examples/emit_fixtures.rs` writes it to
//!   `android/app/src/androidTest/assets/crypto_fixtures.json`, which the
//!   Android app's instrumented tests load and replay through the UniFFI
//!   bridge — asserting the Kotlin path reproduces every value byte for
//!   byte.
//! * `tests/fixture_drift.rs` rebuilds it and compares against that
//!   committed file, so a change to any primitive here that is not
//!   reflected in the fixture fails `cargo test` immediately, not just in
//!   the Android CI diff gate.
//!
//! That round trip — Rust primitive -> fixture -> Kotlin assertion — is
//! the parity guarantee the UniFFI decision is paying for. It has to be
//! observable, so it lives in the shipped crate rather than only in a
//! build script.
//!
//! Everything here is a *fixed* vector. Generation paths
//! (`generate_recovery_phrase`, raw key generation) cannot be fixtures —
//! a CSPRNG output is asserted by property on the Kotlin side instead.

use serde_json::{Value, json};

use crate::aead::{self, AeadKey, Nonce};
use crate::canonical_json::canonicalize;
use crate::dh::DhSecret;
use crate::hashchain::{self, ChainRow, LogEvent};
use crate::hkdf_blake2s;
use crate::kdf;
use crate::recovery::RecoveryPhrase;
use crate::sealed;
use crate::sign::IdentitySecretKey;
use crate::signing::signing_payload;

/// Bump when the fixture's shape changes, so a stale Kotlin loader fails
/// loudly rather than silently skipping fields.
pub const SCHEMA_VERSION: u64 = 1;

/// Build the full fixture document. Deterministic: same bytes every call.
pub fn build_document() -> Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        "_comment": "Emitted by `cargo run -p conveyance-crypto --example emit_fixtures`. \
                     Do not hand-edit. CI regenerates this file and fails on any diff.",
        "hkdf_blake2s": hkdf_blake2s_fixture(),
        "signing_payload": signing_payload_fixture(),
        "canonical_json": canonical_json_fixture(),
        "ed25519": ed25519_fixture(),
        "argon2id_dek": argon2id_dek_fixture(),
        "aead_chacha20poly1305": aead_fixture(),
        "recovery": recovery_fixture(),
        "sealed_identity": sealed_identity_fixture(),
        "hash_chain": hash_chain_fixture(),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// -- HKDF-BLAKE2s ----------------------------------------------------------

fn hkdf_blake2s_fixture() -> Value {
    let seed = [0x5au8; 64];
    let cases: Vec<Value> = [
        (&b"conveyance-v1-identity-ed25519"[..], 32usize),
        (&b"conveyance-v1-identity-x25519"[..], 32),
        (&b"length probe"[..], 65),
    ]
    .into_iter()
    .map(|(info, len)| {
        let mut okm = vec![0u8; len];
        hkdf_blake2s(&seed, info, &mut okm);
        json!({
            "ikm_hex": hex(&seed),
            "info_utf8": std::str::from_utf8(info).unwrap(),
            "length": len,
            "okm_hex": hex(&okm),
        })
    })
    .collect();

    json!({
        "description": "HKDF-BLAKE2s (RFC 5869), salt omitted = 32 zero bytes. \
                        Frozen to conveyance-crypto; no third-party vectors exist.",
        "cases": cases,
    })
}

// -- signing_payload -----------------------------------------------------

fn signing_payload_fixture() -> Value {
    let cases: Vec<Value> = [
        (
            &b"conveyance-approve-v1"[..],
            r#"{"decision":"approved","req_id":"aa00"}"#,
        ),
        (
            &b"conveyance-execute-v1"[..],
            r#"{"executed_at":9,"req_id":"aa00","status":"ok"}"#,
        ),
        (&b""[..], ""),
    ]
    .into_iter()
    .map(|(ctx, body)| {
        json!({
            "context_utf8": std::str::from_utf8(ctx).unwrap(),
            "canonical_body": body,
            "payload_hex": hex(&signing_payload(ctx, body)),
        })
    })
    .collect();

    json!({
        "description": "context || canonical_json(body), plain byte concatenation, no separator.",
        "cases": cases,
    })
}

// -- canonical JSON ----------------------------------------------------

fn canonical_ok(input: &str) -> Value {
    let v: Value = serde_json::from_str(input).expect("fixture input parses");
    json!({ "input": input, "canonical": canonicalize(&v).expect("in-domain") })
}

fn canonical_err(input: &str) -> Value {
    let v: Value = serde_json::from_str(input).expect("fixture input parses");
    assert!(canonicalize(&v).is_err(), "expected {input} to be rejected");
    json!({ "input": input, "error": "OutsideCanonicalDomain" })
}

fn canonical_json_fixture() -> Value {
    let ok = vec![
        // Key ordering is by UTF-16 code unit, not code point (RFC 8785
        // 3.2.3). Keys are JSON \u escapes so `input` stays pure ASCII.
        // U+1D11E is a surrogate pair whose high unit 0xD834 orders it
        // before U+FFFF, where a code-point sort would put it last; "\r"
        // (0x0D) sorts first and re-emits as the "\r" short escape.
        canonical_ok(r#"{"€":"euro","\r":"cr","￿":"ffff","𝄞":"clef","A":"a"}"#),
        // Insignificant-whitespace stripping and nested key sort.
        canonical_ok(r#"{ "b": 1, "a": [ 3, 2, {"y": true, "x": null} ] }"#),
        // ApprovalResponse-shaped: optional `reason` absent vs present.
        canonical_ok(r#"{"decision":"approved","req_id":"aa00"}"#),
        canonical_ok(r#"{"decision":"denied","reason":"user_tap","req_id":"aa00"}"#),
        // Integers past 2^53 emitted exactly (documented divergence from
        // stock JCS; Android must match).
        canonical_ok(r#"{"n":9007199254740993,"neg":-9007199254740993}"#),
        canonical_ok(r#"{"max":18446744073709551615,"min":-9223372036854775808}"#),
        // Empty containers survive.
        canonical_ok(r#"{"a":{},"b":[]}"#),
    ];
    let err = vec![
        canonical_err(r#"{"x":1.5}"#),
        canonical_err(r#"{"x":3.0}"#),
        canonical_err(r#"{"x":1e30}"#),
        // Integer past u64 degrades to f64 on parse -> same rejection.
        canonical_err(r#"{"x":99999999999999999999999}"#),
    ];

    json!({
        "description": "RFC 8785 JCS restricted to the Conveyance domain (ints, strings, \
                        bools, null, arrays, objects). Floats and out-of-range integers \
                        are rejected, not formatted. `input` is raw JSON text.",
        "cases_ok": ok,
        "cases_error": err,
    })
}

// -- Ed25519 ----------------------------------------------------------

fn ed25519_fixture() -> Value {
    // RFC 8032 §7.1 TEST 1 (empty message) and TEST 2 (single byte).
    let vectors = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "72",
        ),
    ];
    let cases: Vec<Value> = vectors
        .into_iter()
        .map(|(sk_hex, msg_hex)| {
            let sk = IdentitySecretKey::from_bytes(unhex(sk_hex).try_into().unwrap());
            let msg = unhex(msg_hex);
            let sig = sk.sign(&msg);
            json!({
                "secret_hex": sk_hex,
                "message_hex": msg_hex,
                "public_hex": hex(&sk.public_key().to_bytes()),
                "signature_hex": hex(&sig),
            })
        })
        .collect();

    let sk = IdentitySecretKey::from_bytes(unhex(vectors[0].0).try_into().unwrap());
    let mut bad_sig = sk.sign(b"");
    bad_sig[0] ^= 0x01;

    json!({
        "description": "Ed25519 (RFC 8032 §7.1). `verify_fail` must not verify.",
        "cases": cases,
        "verify_fail": {
            "public_hex": hex(&sk.public_key().to_bytes()),
            "message_hex": "",
            "signature_hex": hex(&bad_sig),
        },
    })
}

// -- Argon2id DEK ---------------------------------------------------

fn argon2id_dek_fixture() -> Value {
    // One case only: m=64 MiB, t=3 is costly on the CI emulator.
    let passphrase = b"correct horse battery staple";
    let salt = [0x5au8; 16];
    let dek = kdf::derive_dek(passphrase, &salt).expect("valid params");
    json!({
        "description": "Argon2id, spec params (m=65536 KiB, t=3, p=1, 32-byte out, \
                        16-byte salt). One case: the 64 MiB cost is real on an emulator. \
                        No third-party vector for these params; frozen to conveyance-crypto.",
        "cases": [{
            "passphrase_utf8": std::str::from_utf8(passphrase).unwrap(),
            "salt_hex": hex(&salt),
            "dek_hex": hex(&dek),
        }],
    })
}

// -- ChaCha20-Poly1305 AEAD --------------------------------------

fn aead_fixture() -> Value {
    // RFC 8439 §2.8.2 worked example.
    let key = unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = unhex("070000004041424344454647");
    let aad = unhex("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
    let seal_with = |pt: &[u8], ad: &[u8]| {
        aead::seal(
            &AeadKey::from_bytes(key.clone().try_into().unwrap()),
            &Nonce(nonce.clone().try_into().unwrap()),
            pt,
            ad,
        )
    };
    let sealed = seal_with(&plaintext, &aad);
    let empty_sealed = seal_with(&[], &[]);
    let mut tampered = sealed.clone();
    tampered[0] ^= 0x01;

    json!({
        "description": "ChaCha20-Poly1305 (RFC 8439 §2.8.2). `sealed_hex` is ciphertext||tag. \
                        `tamper` (first byte of sealed flipped) must fail to open.",
        "cases": [
            {
                "key_hex": hex(&key),
                "nonce_hex": hex(&nonce),
                "aad_hex": hex(&aad),
                "plaintext_hex": hex(&plaintext),
                "sealed_hex": hex(&sealed),
            },
            {
                "key_hex": hex(&key),
                "nonce_hex": hex(&nonce),
                "aad_hex": "",
                "plaintext_hex": "",
                "sealed_hex": hex(&empty_sealed),
            },
        ],
        "tamper": {
            "key_hex": hex(&key),
            "nonce_hex": hex(&nonce),
            "aad_hex": hex(&aad),
            "sealed_hex": hex(&tampered),
        },
    })
}

// -- Recovery: phrase -> identity keys ------------------------------

fn recovery_fixture() -> Value {
    // BIP-39's most-quoted 24-word vector (all-zero entropy). Conveyance
    // derives with an EMPTY passphrase, so the derived keys have no
    // third-party publication and are frozen to conveyance-crypto.
    let zeros_24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon art";
    let phrase = RecoveryPhrase::from_words(zeros_24).expect("valid phrase");
    let keyset = phrase.to_seed("").derive_identity_keys();
    let ed_secret = *keyset.ed25519_secret.expose();
    let x_secret = *keyset.x25519_secret.expose();
    let ed_public = IdentitySecretKey::from_bytes(ed_secret)
        .public_key()
        .to_bytes();
    let x_public = DhSecret::from_bytes(x_secret).public_key().to_bytes();

    json!({
        "description": "24-word phrase -> BIP-39 seed (empty passphrase) -> HKDF-BLAKE2s \
                        identity keys. `bad_phrase` must be rejected (BadRecoveryPhrase).",
        "cases": [{
            "phrase": zeros_24,
            "ed25519_secret_hex": hex(&ed_secret),
            "ed25519_public_hex": hex(&ed_public),
            "x25519_secret_hex": hex(&x_secret),
            "x25519_public_hex": hex(&x_public),
        }],
        "bad_phrase": zeros_24.replace(" art", " zoo"),
    })
}

// -- Sealed identity (Phase 10.2) -------------------------------

fn sealed_identity_fixture() -> Value {
    let zeros_24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon art";
    let phrase = RecoveryPhrase::from_words(zeros_24).expect("valid phrase");
    let content_key = [0x11u8; 32];
    let message = b"conveyance-v1 phase 10.2 sealed identity";

    // Seal (random nonce -> blob is NOT pinned), reopen, and sign a fixed
    // message. Public keys and the Ed25519 signature are deterministic
    // functions of the derived key; the Kotlin side asserts
    // open(create(phrase, ck)).{ed25519_public, x25519_public, sign(msg)}
    // reproduces these, and that a wrong content key fails.
    let out = sealed::seal_identity(&crate::OsEntropy, &content_key, &phrase).expect("seal");
    let secrets = sealed::open_identity(&content_key, &out.blob).expect("open");
    let sig = IdentitySecretKey::from_bytes(secrets.ed25519()).sign(message);

    json!({
        "description": "create_sealed_identity(phrase, content_key) then open_sealed_identity: \
                        public keys match the recovery vector, sign(message) is deterministic. \
                        The blob carries a random nonce and is not pinned. Opening with \
                        wrong_content_key must fail (DecryptionFailed).",
        "phrase": zeros_24,
        "content_key_hex": hex(&content_key),
        "wrong_content_key_hex": hex(&[0x22u8; 32]),
        "message_hex": hex(message),
        "ed25519_public_hex": hex(&out.ed25519_public),
        "x25519_public_hex": hex(&out.x25519_public),
        "signature_hex": hex(&sig),
    })
}

// -- Hash chain ---------------------------------------------------

fn chain_event(n: u8) -> LogEvent {
    LogEvent {
        req_id: [n; 16],
        event_type: "approval_granted".to_string(),
        payload_json: format!(r#"{{"decision":"approved","n":{n}}}"#),
        timestamp: 1_700_000_000 + n as i64,
    }
}

fn event_json(e: &LogEvent) -> Value {
    json!({
        "req_id_hex": hex(&e.req_id),
        "event_type": e.event_type,
        "payload_json": e.payload_json,
        "timestamp": e.timestamp,
    })
}

fn row_json(r: &ChainRow) -> Value {
    json!({
        "event": event_json(&r.event),
        "prev_hash_hex": hex(&r.prev_hash),
        "hash_hex": hex(&r.hash),
    })
}

fn hash_chain_fixture() -> Value {
    let single = chain_event(1);
    let content = String::from_utf8(hashchain::event_content_json(&single)).unwrap();
    let single_hash = hashchain::compute_entry_hash(&hashchain::GENESIS_PREV_HASH, &single);

    let events: Vec<LogEvent> = (1..=4).map(chain_event).collect();
    let intact = hashchain::build_chain(&events);

    let mut tampered = intact.clone();
    tampered[2].event.payload_json = r#"{"decision":"approved","n":99}"#.to_string();

    let mut removed = intact.clone();
    removed.remove(1);

    json!({
        "description": "SHA-256 hash chain. `single` pins one row's content-json and hash. \
                        `intact` verifies (Intact, 4 rows). `content_tampered` -> \
                        Broken/ContentTampered at index 2. `link_broken` -> \
                        Broken/LinkBroken at index 1. Genesis prev_hash is 32 zero bytes.",
        "genesis_prev_hash_hex": hex(&hashchain::GENESIS_PREV_HASH),
        "single": {
            "event": event_json(&single),
            "event_content_json": content,
            "row_hash_hex": hex(&single_hash),
        },
        "intact": intact.iter().map(row_json).collect::<Vec<_>>(),
        "content_tampered": {
            "rows": tampered.iter().map(row_json).collect::<Vec<_>>(),
            "expect_index": 2,
            "expect_kind": "ContentTampered",
        },
        "link_broken": {
            "rows": removed.iter().map(row_json).collect::<Vec<_>>(),
            "expect_index": 1,
            "expect_kind": "LinkBroken",
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
    fn document_has_every_primitive_group() {
        let d = build_document();
        for key in [
            "hkdf_blake2s",
            "signing_payload",
            "canonical_json",
            "ed25519",
            "argon2id_dek",
            "aead_chacha20poly1305",
            "recovery",
            "sealed_identity",
            "hash_chain",
        ] {
            assert!(d.get(key).is_some(), "missing fixture group {key}");
        }
    }
}
