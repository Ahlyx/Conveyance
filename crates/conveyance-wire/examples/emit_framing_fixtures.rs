//! Writes the cross-implementation framing test-vector fixture to a file.
//!
//!   cargo run -p conveyance-wire --example emit_framing_fixtures -- <out-file>
//!
//! The vectors live in `conveyance_wire::fixtures` so `tests/
//! framing_fixture_drift.rs` can rebuild and compare without shelling
//! out. This binary is just the writer: the Android app's JVM unit tests
//! load the committed output and replay every case through the Kotlin
//! framing port, and CI regenerates it here and fails on any diff.

use std::io::Write;

fn main() {
    let out_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: emit_framing_fixtures <out-file>");
        std::process::exit(2);
    });

    // Pretty-print with a trailing newline: clean text diff, friendly to
    // `git diff --exit-code`.
    let mut text = serde_json::to_string_pretty(&conveyance_wire::fixtures::build_document())
        .expect("fixture doc serializes");
    text.push('\n');

    let mut f = std::fs::File::create(&out_path).unwrap_or_else(|e| {
        eprintln!("cannot create {out_path}: {e}");
        std::process::exit(1);
    });
    f.write_all(text.as_bytes()).expect("write fixture");
    eprintln!("wrote {} bytes to {out_path}", text.len());
}
