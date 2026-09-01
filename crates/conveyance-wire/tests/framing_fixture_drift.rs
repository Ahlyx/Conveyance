//! Fails the moment the committed framing fixture stops matching what
//! this crate's framing rules actually produce.
//!
//! The Android JVM unit suite trusts
//! `android/app/src/test/resources/framing_fixtures.json` as ground
//! truth for the Kotlin<->Rust framing parity check. If a change here
//! alters split/ack/reassembly output, that file is stale and the Kotlin
//! assertion would be comparing against a frozen wrong answer. This test
//! catches it in `cargo test`, before Android CI's diff gate.
//!
//! Fix on failure: rerun the emitter and commit the result.
//!   cargo run -p conveyance-wire --example emit_framing_fixtures -- \
//!     android/app/src/test/resources/framing_fixtures.json

use std::path::PathBuf;

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../android/app/src/test/resources/framing_fixtures.json")
}

#[test]
fn committed_fixture_matches_current_framing() {
    let path = fixture_path();
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

    let mut fresh = serde_json::to_string_pretty(&conveyance_wire::fixtures::build_document())
        .expect("fixture doc serializes");
    fresh.push('\n');

    if committed != fresh {
        let first_diff = committed
            .lines()
            .zip(fresh.lines())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .map(|(i, (a, b))| format!("line {}:\n  committed: {a}\n  current:   {b}", i + 1))
            .unwrap_or_else(|| "(length differs, no line mismatch before EOF)".to_string());

        panic!(
            "framing_fixtures.json is stale.\n{first_diff}\n\n\
             Regenerate and commit:\n  \
             cargo run -p conveyance-wire --example emit_framing_fixtures -- \
             android/app/src/test/resources/framing_fixtures.json"
        );
    }
}
