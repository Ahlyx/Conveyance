//! Writes the cross-implementation test-vector fixture to a file.
//!
//!   cargo run -p conveyance-crypto --example emit_fixtures -- <out-file>
//!
//! The vectors themselves live in `conveyance_crypto::fixtures` so a test
//! (`tests/fixture_drift.rs`) can rebuild and compare without shelling
//! out. This binary is just the file writer: the Android app's
//! instrumented suite loads the committed output and replays every case
//! through the UniFFI bridge, and CI regenerates it here and fails on any
//! diff.

use std::io::Write;

fn main() {
    let out_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: emit_fixtures <out-file>");
        std::process::exit(2);
    });

    // Pretty-print with a trailing newline: a clean text diff and
    // `git diff --exit-code` friendly.
    let mut text = serde_json::to_string_pretty(&conveyance_crypto::fixtures::build_document())
        .expect("fixture doc serializes");
    text.push('\n');

    let mut f = std::fs::File::create(&out_path).unwrap_or_else(|e| {
        eprintln!("cannot create {out_path}: {e}");
        std::process::exit(1);
    });
    f.write_all(text.as_bytes()).expect("write fixture");
    eprintln!("wrote {} bytes to {out_path}", text.len());
}
