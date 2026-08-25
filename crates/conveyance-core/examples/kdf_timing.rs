//! Measures a full Argon2id derivation at the spec's parameters
//! (m=65536 KiB, t=3, p=1) on this machine.
//!
//! The spec says: tune upward if a full derivation completes in under
//! 500 ms. This binary is how that decision gets made -- run it on the
//! target hardware class and compare. It uses release-mode dependencies
//! (`cargo run --release --example kdf_timing`); debug numbers are
//! meaningless for memory-hard KDFs.
//!
//! The salt here is arbitrary; its value does not affect timing.

use conveyance_core::crypto::kdf::{KdfParams, derive_dek_with_params};

fn main() {
    let params = KdfParams::spec();
    let passphrase = b"timing probe passphrase";
    let salt = [0x42u8; 16];

    // One warm-up (page-faults the 64 MiB), then three timed runs.
    let _ = derive_dek_with_params(passphrase, &salt, params).expect("spec params are valid");

    let mut total = std::time::Duration::ZERO;
    for run in 1..=3 {
        let start = std::time::Instant::now();
        let dek = derive_dek_with_params(passphrase, &salt, params).expect("spec params are valid");
        let elapsed = start.elapsed();
        total += elapsed;
        println!(
            "run {run}: {elapsed:>10.1?}  (dek[0..4] = {:02x?})",
            &dek[..4]
        );
    }

    let avg = total / 3;
    println!("average: {avg:.1?}");
    println!(
        "guidance: spec tunes upward only if average < 500 ms; current params m={} KiB t={} p={}",
        params.m_kib, params.t_cost, params.p_cost
    );
}
