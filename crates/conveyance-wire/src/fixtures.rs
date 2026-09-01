//! The cross-implementation framing test-vector set.
//!
//! [`build_document`] returns a JSON value computed straight from this
//! crate's public API. Two consumers:
//!
//! * `examples/emit_framing_fixtures.rs` writes it to
//!   `android/app/src/test/resources/framing_fixtures.json`, which the
//!   Android app's JVM unit tests load and replay through the Kotlin
//!   framing port — asserting the Kotlin path reproduces every byte.
//! * `tests/framing_fixture_drift.rs` rebuilds it and compares against
//!   that committed file, so a change to the framing rules here that is
//!   not mirrored into the fixture fails `cargo test` immediately, not
//!   just in Android CI's diff gate.
//!
//! Rust emits, Kotlin replays, CI drift-gates — the same pattern
//! `conveyance-crypto` uses for the primitives. Sign-extension bugs and
//! the earlier canonical-JSON bug were both caught this way; framing is
//! the next surface that deserves it.
//!
//! Every vector is *fixed* — no RNG anywhere in the framing layer — so
//! the document is byte-identical on every call.

use serde_json::{Value, json};

use crate::assembler::InboundAssembler;
use crate::framing::{
    ATT_PDU_OVERHEAD, DEFAULT_REASSEMBLY_CAP, FLAG_ACK, FLAG_END, FLAG_START, FrameError, Framer,
    HEADER_LEN, MIN_ATT_MTU, encode_ack, encode_frame, max_frame_payload, split_message,
};

/// Bump when the document's shape changes so a stale Kotlin loader fails
/// loudly rather than skipping fields.
pub const SCHEMA_VERSION: u64 = 1;

/// Build the full fixture document. Deterministic: same bytes every call.
pub fn build_document() -> Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        "_comment": "Emitted by `cargo run -p conveyance-wire --example emit_framing_fixtures`. \
                     Do not hand-edit. CI regenerates this file and fails on any diff.",
        "constants": constants(),
        "max_frame_payload": max_frame_payload_group(),
        "split": split_group(),
        "ack": ack_group(),
        "reassemble_ok": reassemble_ok_group(),
        "reassemble_err": reassemble_err_group(),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// -- constants ----------------------------------------------------------

fn constants() -> Value {
    json!({
        "description": "The Kotlin port asserts its own constants equal these.",
        "header_len": HEADER_LEN,
        "flag_start": FLAG_START,
        "flag_end": FLAG_END,
        "flag_ack": FLAG_ACK,
        "reassembly_cap": DEFAULT_REASSEMBLY_CAP,
        "att_pdu_overhead": ATT_PDU_OVERHEAD,
        "min_att_mtu": MIN_ATT_MTU,
    })
}

// -- max_frame_payload ------------------------------------------------

fn max_frame_payload_group() -> Value {
    let cases: Vec<Value> = [0u16, 22, 23, 24, 27, 100, 185, 247, 512, 517]
        .into_iter()
        .map(|att_mtu| json!({ "att_mtu": att_mtu, "max_payload": max_frame_payload(att_mtu) }))
        .collect();
    json!({
        "description": "max_frame_payload(att_mtu) = max(att_mtu, 23) - 3 - 6.",
        "cases": cases,
    })
}

// -- split -----------------------------------------------------------

/// One `split_message` case. Asserts the frames reassemble to the input
/// so a bad vector can never be committed.
fn split_case(name: &str, message: &[u8], max_payload: usize, start_seq: u16) -> Value {
    let (frames, next) = split_message(message, max_payload, start_seq).expect("valid split");

    let mut framer = Framer::new();
    let mut got: Option<Vec<u8>> = None;
    for f in &frames {
        if let Some(m) = framer.ingest(f).expect("own frames ingest") {
            got = Some(m);
        }
    }
    assert_eq!(
        got.as_deref(),
        Some(message),
        "{name}: split_message output does not round-trip"
    );

    json!({
        "name": name,
        "message_hex": hex(message),
        "max_payload": max_payload,
        "start_seq": start_seq,
        "expected_next_seq": next,
        "frames_hex": frames.iter().map(|f| hex(f)).collect::<Vec<_>>(),
    })
}

fn split_group() -> Value {
    let ramp: Vec<u8> = (0..800u32).map(|i| (i % 251) as u8).collect();
    json!({
        "description": "split_message(message, max_payload, start_seq). frames_hex are whole \
                        frames (6-byte header + payload) in order. The Kotlin splitter must \
                        reproduce them exactly, and feeding them to a Framer must yield \
                        message_hex.",
        "cases": [
            split_case("single_start_end", b"ping", 1000, 7),
            split_case("zero_length_is_one_empty_start_end", b"", 500, 0),
            split_case("exact_multiple_no_empty_tail", &[9u8; 1000], 500, 0),
            split_case("seq_wraps_u16", b"wraparound", 3, u16::MAX - 2),
            split_case("mtu23_multiframe", &ramp[..80], max_frame_payload(23), 0),
            split_case("mtu247_multiframe", &ramp, max_frame_payload(247), 100),
        ],
    })
}

// -- ack -----------------------------------------------------------

fn ack_group() -> Value {
    let cases: Vec<Value> = [0u16, 30, 65535]
        .into_iter()
        .map(|acked_seq| {
            let frame = encode_ack(acked_seq);
            assert_eq!(
                Framer::new().ingest(&frame).expect("ack ingests"),
                None,
                "ack must yield no message"
            );
            json!({ "acked_seq": acked_seq, "frame_hex": hex(&frame) })
        })
        .collect();
    json!({
        "description": "encode_ack(seq): flags = ACK (4), empty payload, seq echoes the argument. \
                        A receiver accepts it, returns no message, and does not advance its \
                        expected sequence.",
        "cases": cases,
    })
}

// -- reassemble_ok --------------------------------------------------

/// Feed `stream` to an `InboundAssembler`, both whole and re-sliced at
/// `chunk_offsets`, asserting both produce the same messages.
fn reassemble_ok_case(name: &str, stream: &[u8], chunk_offsets: &[usize]) -> Value {
    let expected = InboundAssembler::new()
        .ingest(stream)
        .expect("valid stream ingests");

    let mut sliced = InboundAssembler::new();
    let mut got: Vec<Vec<u8>> = Vec::new();
    let mut prev = 0usize;
    for &off in chunk_offsets {
        got.extend(sliced.ingest(&stream[prev..off]).expect("slice ingests"));
        prev = off;
    }
    got.extend(sliced.ingest(&stream[prev..]).expect("tail ingests"));
    assert_eq!(got, expected, "{name}: sliced ingest != whole ingest");

    json!({
        "name": name,
        "input_hex": hex(stream),
        "wire_chunk_offsets": chunk_offsets,
        "expected_messages_hex": expected.iter().map(|m| hex(m)).collect::<Vec<_>>(),
    })
}

fn reassemble_ok_group() -> Value {
    // A 3+ frame message at the 23-byte MTU.
    let body: Vec<u8> = (0..70u32).map(|i| (i * 3) as u8).collect();
    let (multi, next) = split_message(&body, max_frame_payload(23), 0).unwrap();
    let multi_stream: Vec<u8> = multi.concat();

    // Two independent single-frame messages, contiguous.
    let (a, an) = split_message(b"first", 1000, next).unwrap();
    let (b, _) = split_message(b"the second one", 1000, an).unwrap();
    let two_stream: Vec<u8> = a.iter().chain(b.iter()).flatten().copied().collect();

    // START, then an ACK, then the middle and END frames.
    let (thr, _) = split_message(b"payload spanning frames", 8, 30).unwrap();
    let mut ack_stream = thr[0].clone();
    ack_stream.extend_from_slice(&encode_ack(30));
    for f in &thr[1..] {
        ack_stream.extend_from_slice(f);
    }

    // Offsets that fall inside a header and inside a payload.
    let mid_header = HEADER_LEN + 2;
    let mid_second_frame = multi[0].len() + HEADER_LEN + 1;

    json!({
        "description": "Feed input_hex bytes to an InboundAssembler. wire_chunk_offsets (may be \
                        empty) are byte offsets at which to break the stream into successive \
                        ingest() calls — proving reassembly is independent of how the transport \
                        chunks the wire. Result must equal expected_messages_hex.",
        "cases": [
            reassemble_ok_case("multiframe_one_ingest", &multi_stream, &[]),
            reassemble_ok_case(
                "multiframe_sliced_across_header_and_payload",
                &multi_stream,
                &[1, mid_header, mid_second_frame],
            ),
            reassemble_ok_case("two_messages_one_ingest", &two_stream, &[]),
            reassemble_ok_case(
                "two_messages_split_between_them",
                &two_stream,
                &[a[0].len()],
            ),
            reassemble_ok_case("interleaved_ack_ignored", &ack_stream, &[]),
        ],
    })
}

// -- reassemble_err -----------------------------------------------

fn err_json(e: &FrameError) -> Value {
    match e {
        FrameError::FrameTruncated => json!({ "kind": "FrameTruncated" }),
        FrameError::FrameLengthMismatch { declared, actual } => {
            json!({ "kind": "FrameLengthMismatch", "declared": declared, "actual": actual })
        }
        FrameError::NonZeroReserved => json!({ "kind": "NonZeroReserved" }),
        FrameError::IllegalFlags { bits } => json!({ "kind": "IllegalFlags", "bits": bits }),
        FrameError::StrayMiddleFrame => json!({ "kind": "StrayMiddleFrame" }),
        FrameError::NestedMessage => json!({ "kind": "NestedMessage" }),
        FrameError::SequenceGap { expected, got } => {
            json!({ "kind": "SequenceGap", "expected": expected, "got": got })
        }
        FrameError::MessageTooLarge { size, cap } => json!({
            "kind": "MessageTooLarge",
            "size": size,
            "cap": cap,
            "spec_code": "conveyance/message_too_large",
        }),
        FrameError::InvalidSplitSize => json!({ "kind": "InvalidSplitSize" }),
    }
}

/// Feed `frames` to a `Framer` (cap `cap`) one at a time; the sequence
/// must fail with exactly `expected`, on some frame.
fn err_case(name: &str, frames: Vec<Vec<u8>>, cap: usize, expected: FrameError) -> Value {
    let mut framer = Framer::with_cap(cap);
    let mut hit: Option<FrameError> = None;
    for f in &frames {
        if let Err(e) = framer.ingest(f) {
            hit = Some(e);
            break;
        }
    }
    assert_eq!(hit.as_ref(), Some(&expected), "{name}");

    json!({
        "name": name,
        "cap": cap,
        "input_frames_hex": frames.iter().map(|f| hex(f)).collect::<Vec<_>>(),
        "error": err_json(&expected),
    })
}

fn reassemble_err_group() -> Value {
    const CAP: usize = DEFAULT_REASSEMBLY_CAP;

    let mut nonzero_reserved = encode_frame(0, FLAG_START | FLAG_END, b"x");
    nonzero_reserved[5] = 1;

    let mut len_mismatch = encode_frame(0, FLAG_START | FLAG_END, b"abc");
    len_mismatch[0] = 0x00;
    len_mismatch[1] = 0x0A; // declares 10, only 3 follow

    // START, MIDDLE, END at seqs 10/11/12 (12 payload bytes at 4/frame).
    let (triple, _) = split_message(&[0u8; 12], 4, 10).unwrap();
    // Two independent pure-START frames.
    let (chain_a, _) = split_message(&[1u8; 12], 4, 0).unwrap();
    let (chain_b, _) = split_message(&[2u8; 12], 4, 100).unwrap();
    // Four 50-byte frames; cap 64 overflows on the second.
    let (oversized, _) = split_message(&[7u8; 200], 50, 0).unwrap();

    json!({
        "description": "Feed input_frames_hex to a Framer with reassembly cap `cap`, one frame \
                        per ingest(). The run must terminate with `error` — the session ends on \
                        it. Anything but MessageTooLarge is an internal protocol violation with \
                        no client-facing code.",
        "cases": [
            err_case("truncated_header", vec![vec![0xAA, 0xBB, 0xCC]], CAP, FrameError::FrameTruncated),
            err_case("nonzero_reserved", vec![nonzero_reserved], CAP, FrameError::NonZeroReserved),
            err_case(
                "undefined_flag_bit",
                vec![encode_frame(0, 0b1000, b"")],
                CAP,
                FrameError::IllegalFlags { bits: 0b1000 },
            ),
            err_case(
                "length_prefix_mismatch",
                vec![len_mismatch],
                CAP,
                FrameError::FrameLengthMismatch { declared: 10, actual: 3 },
            ),
            err_case(
                "ack_with_payload",
                vec![encode_frame(5, FLAG_ACK, b"z")],
                CAP,
                FrameError::IllegalFlags { bits: FLAG_ACK },
            ),
            err_case(
                "second_start_mid_message",
                vec![chain_a[0].clone(), chain_b[0].clone()],
                CAP,
                FrameError::NestedMessage,
            ),
            err_case(
                "middle_frame_while_idle",
                vec![triple[1].clone()],
                CAP,
                FrameError::StrayMiddleFrame,
            ),
            err_case(
                "sequence_gap_drops_middle",
                vec![triple[0].clone(), triple[2].clone()],
                CAP,
                FrameError::SequenceGap { expected: 11, got: 12 },
            ),
            err_case(
                "reassembly_cap_exceeded",
                vec![oversized[0].clone(), oversized[1].clone()],
                64,
                FrameError::MessageTooLarge { size: 100, cap: 64 },
            ),
        ],
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
    fn document_has_every_group() {
        let d = build_document();
        for key in [
            "constants",
            "max_frame_payload",
            "split",
            "ack",
            "reassemble_ok",
            "reassemble_err",
        ] {
            assert!(d.get(key).is_some(), "missing group {key}");
        }
    }
}
