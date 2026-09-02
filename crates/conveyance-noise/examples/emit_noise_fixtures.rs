//! Writes the cross-implementation Noise test-vector fixture to a file.
//!
//!   cargo run -p conveyance-noise --features test-vectors \
//!     --example emit_noise_fixtures -- <out-file>
//!
//! The vectors live in `conveyance_noise::fixtures` so a `#[cfg(test)]`
//! check can rebuild and diff them without shelling out. This binary is
//! just the writer: the Android instrumented suite loads the committed
//! output and replays every case through the real snow-backed UniFFI
//! bridge, and CI regenerates it here and fails on any diff.

use std::io::Write;

fn main() {
    let out_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: emit_noise_fixtures <out-file>");
        std::process::exit(2);
    });

    let mut text = serde_json::to_string_pretty(&conveyance_noise::fixtures::build_document())
        .expect("fixture doc serializes");
    text.push('\n');

    let mut f = std::fs::File::create(&out_path).unwrap_or_else(|e| {
        eprintln!("cannot create {out_path}: {e}");
        std::process::exit(1);
    });
    f.write_all(text.as_bytes()).expect("write fixture");
    eprintln!("wrote {} bytes to {out_path}", text.len());
}
