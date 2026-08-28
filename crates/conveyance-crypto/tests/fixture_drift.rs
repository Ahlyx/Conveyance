//! Fails the moment the committed cross-implementation fixture stops
//! matching what this crate's primitives actually produce.
//!
//! The Android instrumented suite trusts
//! `android/app/src/androidTest/assets/crypto_fixtures.json` as ground
//! truth for the Kotlin<->Rust parity check. If a change here alters any
//! primitive's output, that file is stale and the Android assertion would
//! be comparing Kotlin against a frozen wrong answer. This test catches
//! that in `cargo test`, before it ever reaches Android CI's diff gate.
//!
//! Fix on failure: rerun the emitter and commit the result.
//!   cargo run -p conveyance-crypto --example emit_fixtures -- \
//!     android/app/src/androidTest/assets/crypto_fixtures.json

use std::path::PathBuf;

/// The committed fixture, relative to this crate's manifest dir.
fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../android/app/src/androidTest/assets/crypto_fixtures.json")
}

#[test]
fn committed_fixture_matches_current_primitives() {
    let path = fixture_path();
    let committed = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("cannot read {}: {e}", path.display());
    });

    let mut fresh = serde_json::to_string_pretty(&conveyance_crypto::fixtures::build_document())
        .expect("fixture doc serializes");
    fresh.push('\n');

    if committed != fresh {
        // Point at the first differing line so the failure is actionable
        // without diffing 14 KB by eye.
        let first_diff = committed
            .lines()
            .zip(fresh.lines())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map(|(i, (a, b))| format!("line {}:\n  committed: {a}\n  current:   {b}", i + 1))
            .unwrap_or_else(|| "(length differs, no line mismatch before EOF)".to_string());

        panic!(
            "crypto_fixtures.json is stale.\n{first_diff}\n\n\
             Regenerate and commit:\n  \
             cargo run -p conveyance-crypto --example emit_fixtures -- \
             android/app/src/androidTest/assets/crypto_fixtures.json"
        );
    }
}
