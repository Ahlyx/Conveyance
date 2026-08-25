#![no_main]

// Fuzz target: the framing parser. Feeds arbitrary bytes as one blob AND
// as arbitrarily-cut chunks (exercising multi-ingest reassembly paths),
// plus ACK-shaped frames. Any panic is a bug; typed errors are success.

use libfuzzer_sys::fuzz_target;
use conveyance_core::wire::framing::{encode_ack, Framer};

fn drive(data: &[u8]) {
    // Mode 1: whole blob in one ingest.
    let mut framer = Framer::new();
    let _ = framer.ingest(data);

    // Mode 2: chunked at pseudo-random boundaries derived from the input
    // itself (deterministic per-input, so libFuzzer's corpus stays
    // meaningful).
    if data.len() > 8 {
        let mut framer = Framer::new();
        let mut rest = data;
        while !rest.is_empty() {
            let step = usize::from(rest[0] | 1) % 64 + 6; // 6..=69, header-sized floor
            let cut = usize::min(step, rest.len());
            let (chunk, tail) = rest.split_at(cut);
            let _ = framer.ingest(chunk);
            rest = tail;
        }
    }

    // Mode 3: an ACK built from input bits, then whatever follows.
    if data.len() >= 2 {
        let acked = u16::from_be_bytes([data[0], data[1]]);
        let mut framer = Framer::new();
        let _ = framer.ingest(&encode_ack(acked));
        let _ = framer.ingest(&data[2..]);
    }
}

fuzz_target!(|data: &[u8]| {
    drive(data);
});
