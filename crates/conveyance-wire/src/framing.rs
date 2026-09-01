//! Length-prefixed, sequenced framing per the spec's "Framing" section.
//!
//! ```text
//! uint16 length;   // big-endian, length of `payload`
//! uint16 seq;      // per-connection monotonic
//! uint8  flags;    // bit0 START, bit1 END, bit2 ACK
//! uint8  reserved; // zero
//! byte   payload[length]
//! ```
//!
//! A message fitting one MTU is a single START|END frame; larger messages
//! are START, zero+ middles, END. Reassembly is strict: frames must
//! arrive in order (BLE notify delivers in order; Noise rejects reorder
//! at the session layer anyway), only one message may be mid-flight, and
//! the accumulated payload may never exceed the cap -- exceeding it is
//! `message_too_large`, which terminates the session.
//!
//! ACK frames carry no payload and echo the seq they acknowledge. They do
//! NOT consume sequence numbers and are skipped by continuity checking:
//! v1 has no retransmit machinery (BLE notify + in-order delivery make it
//! dead weight); ACKs exist so phase 7 can correlate delivery when a
//! consumer actually needs to.

use thiserror::Error;

/// Every way a frame or a reassembly step can be rejected.
///
/// `PartialEq` is derived (no opaque payloads here) so fixture-parity
/// vectors can assert an exact expected variant. Framing errors are
/// internal: they terminate the session (`protocol_violation`) but only
/// `MessageTooLarge` has a client-facing spec code.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame shorter than the 6-byte header")]
    FrameTruncated,
    #[error("frame declares {declared} payload bytes but {actual} follow")]
    FrameLengthMismatch { declared: usize, actual: usize },
    #[error("frame has reserved byte set to nonzero")]
    NonZeroReserved,
    #[error("illegal flag combination: {bits:#010b}")]
    IllegalFlags { bits: u8 },
    #[error("middle frame received while not reassembling a message")]
    StrayMiddleFrame,
    #[error("second START frame while a message is mid-reassembly")]
    NestedMessage,
    #[error("sequence gap: expected {expected}, got {got}")]
    SequenceGap { expected: u16, got: u16 },
    #[error("reassembly buffer limit exceeded ({size} > {cap} bytes)")]
    MessageTooLarge { size: usize, cap: usize },
    #[error("split requested with zero-byte per-frame payload")]
    InvalidSplitSize,
}

impl FrameError {
    /// Spec error-model code, where one exists. Only `MessageTooLarge`
    /// surfaces to the client (`conveyance/message_too_large`); the rest
    /// are internal protocol violations.
    pub fn spec_code(&self) -> Option<&'static str> {
        match self {
            FrameError::MessageTooLarge { .. } => Some("conveyance/message_too_large"),
            _ => None,
        }
    }
}

pub const FLAG_START: u8 = 0b001;
pub const FLAG_END: u8 = 0b010;
pub const FLAG_ACK: u8 = 0b100;

/// All valid flag masks: single-frame, pure-start/middle/end, or ack.
const LEGAL_FLAGS: [u8; 5] = [FLAG_START | FLAG_END, FLAG_START, FLAG_END, 0, FLAG_ACK];

pub const HEADER_LEN: usize = 6;

/// Spec: reassembly buffer per side MUST be capped, default 128 KiB.
pub const DEFAULT_REASSEMBLY_CAP: usize = 128 * 1024;

/// ATT opcode + attribute handle: the bytes a write or notification PDU
/// spends before the value. A frame must fit `att_mtu - ATT_PDU_OVERHEAD`.
pub const ATT_PDU_OVERHEAD: usize = 3;

/// The BLE minimum ATT MTU. A sender that has not seen an MTU exchange
/// MUST assume this (spec "Framing").
pub const MIN_ATT_MTU: usize = 23;

/// Largest frame *payload* that keeps a whole frame — this 6-byte header
/// plus the payload — inside one GATT operation at the given negotiated
/// ATT MTU. Spec "Framing": `HEADER_LEN + payload <= att_mtu - 3`, i.e.
/// `max_payload = att_mtu - 3 - HEADER_LEN`.
///
/// Both transports feed this straight into [`split_message`] as
/// `max_payload`. An `att_mtu` below [`MIN_ATT_MTU`] (including a platform
/// that reports 0 before negotiation) is treated as 23, so the result is
/// always `>= MIN_ATT_MTU - 3 - HEADER_LEN` (14) and never zero.
pub fn max_frame_payload(att_mtu: u16) -> usize {
    (att_mtu as usize).max(MIN_ATT_MTU) - ATT_PDU_OVERHEAD - HEADER_LEN
}

/// Encode one frame. `payload.len()` must fit in u16.
pub fn encode_frame(seq: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    assert!(
        payload.len() <= u16::MAX as usize,
        "frame payload exceeds u16 -- split_message must chunk"
    );
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.push(flags);
    out.push(0);
    out.extend_from_slice(payload);
    out
}

/// Build an ACK acknowledging `acked_seq`. Empty payload, no new seq
/// consumed.
pub fn encode_ack(acked_seq: u16) -> Vec<u8> {
    encode_frame(acked_seq, FLAG_ACK, &[])
}

/// Split one application message into wire frames carrying at most
/// `max_payload` payload bytes each. Callers derive `max_payload` from
/// the negotiated MTU via [`max_frame_payload`].
///
/// Returns the encoded frames in order plus the next free sequence number
/// (frames consume seqs; ACKs never do).
pub fn split_message(
    message: &[u8],
    max_payload: usize,
    start_seq: u16,
) -> Result<(Vec<Vec<u8>>, u16), FrameError> {
    if max_payload == 0 {
        return Err(FrameError::InvalidSplitSize);
    }

    let count = message.len().div_ceil(max_payload).max(1);
    let mut frames = Vec::with_capacity(count);
    let mut offset = 0usize;

    for i in 0..count {
        let end = usize::min(offset + max_payload, message.len());
        let payload = &message[offset..end];
        offset = end;

        let flags = match i {
            0 if count == 1 => FLAG_START | FLAG_END,
            0 => FLAG_START,
            _ if i == count - 1 => FLAG_END,
            _ => 0,
        };
        frames.push(encode_frame(
            start_seq.wrapping_add(i as u16),
            flags,
            payload,
        ));
    }

    // div_ceil already accounts for an exact multiple (len = 2*max gives
    // count = 2, chunks [max][max], the second carrying END with a full
    // payload). The only empty final frame is the len == 0 case, where
    // .max(1) forces one empty START|END frame. Both pinned by tests.
    Ok((frames, start_seq.wrapping_add(count as u16)))
}

#[derive(Debug)]
enum Progress {
    Idle,
    Assembling,
}

/// Reassembly half-connection. One per direction.
#[derive(Debug)]
pub struct Framer {
    cap: usize,
    progress: Progress,
    /// Next expected sequence number (data frames only; ACKs skip this).
    next_seq: Option<u16>,
    buffer: Vec<u8>,
}

impl Default for Framer {
    fn default() -> Self {
        Self::new()
    }
}

impl Framer {
    pub fn new() -> Self {
        Self::with_cap(DEFAULT_REASSEMBLY_CAP)
    }

    pub fn with_cap(cap: usize) -> Self {
        Self {
            cap,
            progress: Progress::Idle,
            next_seq: None,
            buffer: Vec::new(),
        }
    }

    /// Feed raw bytes from the wire. Returns `Some(message)` when a full
    /// application message completed (END frame received).
    pub fn ingest(&mut self, frame_bytes: &[u8]) -> Result<Option<Vec<u8>>, FrameError> {
        if frame_bytes.len() < HEADER_LEN {
            return Err(FrameError::FrameTruncated);
        }
        let declared = u16::from_be_bytes([frame_bytes[0], frame_bytes[1]]) as usize;
        let seq = u16::from_be_bytes([frame_bytes[2], frame_bytes[3]]);
        let flags = frame_bytes[4];
        let reserved = frame_bytes[5];
        let payload = &frame_bytes[HEADER_LEN..];

        if reserved != 0 {
            return Err(FrameError::NonZeroReserved);
        }
        if !LEGAL_FLAGS.contains(&flags) {
            return Err(FrameError::IllegalFlags { bits: flags });
        }
        if payload.len() != declared {
            return Err(FrameError::FrameLengthMismatch {
                declared,
                actual: payload.len(),
            });
        }

        // ACKs reference history; they neither advance nor check seq.
        if flags == FLAG_ACK {
            if !payload.is_empty() {
                return Err(FrameError::IllegalFlags { bits: flags });
            }
            return Ok(None);
        }

        // Shape-versus-progress violations are diagnosed BEFORE sequence
        // continuity: a second START mid-message is that violation, no
        // matter what sequence number it claims.
        match flags {
            f if f & FLAG_START != 0 && !matches!(self.progress, Progress::Idle) => {
                return Err(FrameError::NestedMessage);
            }
            0 => {
                if matches!(self.progress, Progress::Idle) {
                    return Err(FrameError::StrayMiddleFrame);
                }
            }
            _ => {}
        }

        match self.next_seq {
            Some(expected) if seq != expected => {
                return Err(FrameError::SequenceGap { expected, got: seq });
            }
            other => {
                self.next_seq = Some(match other {
                    Some(e) => e.wrapping_add(1),
                    None => seq.wrapping_add(1),
                });
            }
        }

        match flags {
            f if f == (FLAG_START | FLAG_END) => Ok(Some(payload.to_vec())),
            FLAG_START => {
                self.buffer.clear();
                self.buffer.extend_from_slice(payload);
                self.progress = Progress::Assembling;
                self.check_cap()?;
                Ok(None)
            }
            0 => {
                self.buffer.extend_from_slice(payload);
                self.check_cap()?;
                Ok(None)
            }
            FLAG_END => {
                // A bare END means its START vanished -- gap-class
                // corruption regardless of payload emptiness.
                if matches!(self.progress, Progress::Idle) {
                    return Err(FrameError::SequenceGap {
                        expected: seq.wrapping_sub(1),
                        got: seq,
                    });
                }
                self.buffer.extend_from_slice(payload);
                self.check_cap()?;
                self.progress = Progress::Idle;
                Ok(Some(std::mem::take(&mut self.buffer)))
            }
            _ => unreachable!("flags validated against LEGAL_FLAGS"),
        }
    }

    fn check_cap(&self) -> Result<(), FrameError> {
        if self.buffer.len() > self.cap {
            return Err(FrameError::MessageTooLarge {
                size: self.buffer.len(),
                cap: self.cap,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_message_is_one_start_end_frame() {
        let (frames, next) = split_message(b"ping", 1000, 7).unwrap();
        assert_eq!(next, 8);
        assert_eq!(frames.len(), 1);

        // Header shape pinned byte-for-byte.
        assert_eq!(&frames[0][0..2], &[0x00, 0x04]); // len BE
        assert_eq!(&frames[0][2..4], &[0x00, 0x07]); // seq BE
        assert_eq!(frames[0][4], FLAG_START | FLAG_END);
        assert_eq!(frames[0][5], 0);
        assert_eq!(&frames[0][6..], b"ping");

        // And it ingests straight through an idle framer.
        let out = Framer::new().ingest(&frames[0]).unwrap();
        assert_eq!(out.as_deref(), Some(&b"ping"[..]));
    }

    #[test]
    fn large_message_splits_and_reassembles_across_many_frames() {
        let message: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let (frames, next) = split_message(&message, 500, 0).unwrap();
        assert_eq!(frames.len(), 20);
        assert_eq!(next, 20);

        let mut framer = Framer::new();
        let mut assembled = None;
        for f in &frames {
            if let Some(done) = framer.ingest(f).unwrap() {
                assembled = Some(done);
            }
        }
        assert_eq!(assembled.as_deref(), Some(&message[..]));
    }

    #[test]
    fn exact_multiple_of_frame_size_has_no_spurious_empty_tail() {
        // 1000 bytes in 500-byte frames: exactly two FULL frames, the
        // second carrying END. No empty third frame.
        let message = vec![9u8; 1000];
        let (frames, _) = split_message(&message, 500, 0).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(&frames[0][4], &FLAG_START);
        assert_eq!(&frames[1][4], &FLAG_END);
        assert_eq!(&frames[1][0..2], &[0x01, 0xF4]); // 500 BE

        let zero: Vec<u8> = vec![];
        let (frames, _) = split_message(&zero, 500, 0).unwrap();
        assert_eq!(frames.len(), 1, "empty message is one empty START|END");
        let out = Framer::new().ingest(&frames[0]).unwrap();
        assert_eq!(out.as_deref(), Some(&[][..]));
    }

    #[test]
    fn seq_wraps_u16_without_error() {
        let message = b"wrap";
        let (frames, _) = split_message(message, 2, u16::MAX - 1).unwrap();
        assert_eq!(frames.len(), 2);

        let mut framer = Framer::new();
        let first = &frames[0];
        let seq0 = u16::from_be_bytes([first[2], first[3]]);
        assert_eq!(seq0, u16::MAX - 1);
        framer.ingest(first).unwrap();
        // Second frame's seq is MAX; continuity wraps past it cleanly.
        assert_eq!(u16::from_be_bytes([frames[1][2], frames[1][3]]), u16::MAX);
        let done = framer.ingest(&frames[1]).unwrap();
        // Reassembly returns the WHOLE message, not just the final chunk.
        assert_eq!(done.as_deref(), Some(&b"wrap"[..]));
    }

    #[test]
    fn malformed_frames_produce_typed_errors_never_panics() {
        let mut framer = Framer::new();

        // Truncated header lengths 0..5.
        for n in 0..HEADER_LEN {
            assert!(
                matches!(
                    framer.ingest(&vec![0xAA; n]),
                    Err(FrameError::FrameTruncated)
                ),
                "len {n}"
            );
        }

        // Declared length exceeds what follows.
        let mut bad_len = encode_frame(0, FLAG_START | FLAG_END, b"abc");
        bad_len[0] = 0xFF;
        assert!(matches!(
            framer.ingest(&bad_len),
            Err(FrameError::FrameLengthMismatch {
                declared: 65283,
                actual: 3
            })
        ));

        // Nonzero reserved byte.
        let mut bad_res = encode_frame(0, FLAG_START | FLAG_END, b"x");
        bad_res[5] = 1;
        assert!(matches!(
            framer.ingest(&bad_res),
            Err(FrameError::NonZeroReserved)
        ));

        // Undefined flag bits / illegal combos.
        for flags in [0b1000, 0b1001, 0b1010, 0b1100, 0b111, 0b110] {
            let bad = encode_frame(0, flags, b"");
            assert!(
                matches!(framer.ingest(&bad), Err(FrameError::IllegalFlags { .. })),
                "flags {flags:#b}"
            );
        }

        // Zero-size split is rejected up front.
        assert!(split_message(b"", 0, 0).is_err());
    }

    #[test]
    fn sequence_discipline_enforced() {
        let message = vec![1u8; 900];
        let (frames, _) = split_message(&message, 300, 10).unwrap(); // 3 frames: 10,11,12

        // Dropping the middle breaks continuity at the third.
        let mut framer = Framer::new();
        framer.ingest(&frames[0]).unwrap();
        assert!(matches!(
            framer.ingest(&frames[2]),
            Err(FrameError::SequenceGap {
                expected: 11,
                got: 12
            })
        ));

        // Stray middle frame with no START.
        let mut fresh = Framer::new();
        assert!(matches!(
            fresh.ingest(&frames[1]),
            Err(FrameError::StrayMiddleFrame)
        ));

        // Reordering across independent single-frame messages: A at seq
        // 5 completes, then B at seq 7 skips 6.
        let (a, _) = split_message(b"AAA", 4, 5).unwrap();
        let (b, _) = split_message(b"BBB", 4, 7).unwrap();
        let mut framer = Framer::new();
        assert_eq!(framer.ingest(&a[0]).unwrap().as_deref(), Some(&b"AAA"[..]));
        assert!(matches!(
            framer.ingest(&b[0]),
            Err(FrameError::SequenceGap {
                expected: 6,
                got: 7
            })
        ));
    }

    #[test]
    fn nested_start_rejected() {
        let (a, _) = split_message(b"first-message", 4, 0).unwrap();
        let (b, _) = split_message(b"second", 4, 100).unwrap();

        let mut framer = Framer::new();
        framer.ingest(&a[0]).unwrap(); // START
        assert!(matches!(
            framer.ingest(&b[0]),
            Err(FrameError::NestedMessage)
        ));
    }

    #[test]
    fn reassembly_cap_yields_message_too_large_with_spec_code() {
        // Cap 64 bytes; a 200-byte message overflows mid-reassembly.
        let oversized = [7u8; 200];
        let (frames, _) = split_message(&oversized, 50, 0).unwrap();
        let mut framer = Framer::with_cap(64);

        framer.ingest(&frames[0]).unwrap(); // 50 bytes, under cap
        let err = framer.ingest(&frames[1]).unwrap_err();
        match err {
            FrameError::MessageTooLarge { size, cap } => {
                assert_eq!(cap, 64);
                assert!(size > 64);
                assert_eq!(err.spec_code(), Some("conveyance/message_too_large"));
            }
            other => panic!("expected MessageTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn ack_frames_pass_through_and_do_not_disturb_sequence() {
        let (frames, _) = split_message(b"hello world acked", 6, 30).unwrap();

        let mut framer = Framer::new();
        framer.ingest(&frames[0]).unwrap(); // START seq 30

        // ACK the START: parses fine, returns None, consumes nothing.
        let ack = encode_ack(30);
        assert!(matches!(framer.ingest(&ack), Ok(None)));

        // Continuation still expects seq 31 despite the interleaved ACK.
        framer.ingest(&frames[1]).unwrap();
        let done = framer.ingest(&frames[2]).unwrap();
        assert_eq!(done.as_deref(), Some(&b"hello world acked"[..]));
    }

    #[test]
    fn max_frame_payload_matches_the_spec_formula() {
        // att_mtu - 3 - 6, with anything under 23 pinned to 23.
        assert_eq!(max_frame_payload(0), 14);
        assert_eq!(max_frame_payload(22), 14);
        assert_eq!(max_frame_payload(23), 14);
        assert_eq!(max_frame_payload(185), 176);
        assert_eq!(max_frame_payload(247), 238);
        assert_eq!(max_frame_payload(512), 503);
        assert_eq!(max_frame_payload(517), 508);
    }

    /// The sizing contract: a frame produced with `max_frame_payload` as
    /// the split size never exceeds one ATT PDU (`att_mtu - 3`) on the
    /// wire, at any MTU and any message length, and still round-trips.
    #[test]
    fn every_emitted_frame_fits_one_att_pdu() {
        for att_mtu in [23u16, 24, 27, 100, 185, 247, 512, 517] {
            let budget = max_frame_payload(att_mtu);
            let pdu_limit = (att_mtu as usize).max(MIN_ATT_MTU) - ATT_PDU_OVERHEAD;
            for msg_len in [
                0usize,
                1,
                13,
                14,
                15,
                budget,
                budget + 1,
                3 * budget + 7,
                5000,
            ] {
                let msg = vec![0xABu8; msg_len];
                let (frames, _) = split_message(&msg, budget, 0).unwrap();
                for f in &frames {
                    assert!(
                        (HEADER_LEN..=pdu_limit).contains(&f.len()),
                        "att_mtu={att_mtu} msg_len={msg_len}: frame len {} outside {HEADER_LEN}..={pdu_limit}",
                        f.len(),
                    );
                }
                let mut framer = Framer::new();
                let mut got = None;
                for f in &frames {
                    if let Some(m) = framer.ingest(f).unwrap() {
                        got = Some(m);
                    }
                }
                assert_eq!(
                    got.as_deref(),
                    Some(&msg[..]),
                    "att_mtu={att_mtu} msg_len={msg_len}"
                );
            }
        }
    }

    /// Deterministic seeded soak: adversarial mutations of *valid frame
    /// traffic* through the parser. Panics fail the test; typed errors
    /// pass. Complements the coverage-guided fuzz target
    /// (`fuzz/fuzz_targets/frame_ingest.rs`) on Linux CI, and the
    /// cross-layer soak in `conveyance-core::wire` that also feeds the
    /// mutated bytes to the CBOR message decoder.
    #[test]
    fn mutation_soak_over_valid_traffic_produces_errors_not_panics() {
        struct Lcg(u64);
        impl Lcg {
            fn next(&mut self) -> u64 {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                self.0 >> 16
            }
        }
        let mut rng = Lcg(0xC0FFEE);

        // Valid multi-frame streams to mutate: a message split at a small
        // MTU so START/middle/END all appear, plus single START|END and
        // ACK shapes.
        let base_streams: Vec<Vec<u8>> = (0..8)
            .map(|n| {
                let body = vec![(n * 31) as u8; (n as usize + 1) * 13];
                let (frames, _) = split_message(&body, 7, (n as u16) * 5).unwrap();
                let mut stream: Vec<u8> = frames.concat();
                stream.extend_from_slice(&encode_ack((n as u16) * 5));
                stream
            })
            .collect();

        // Soak 1: mutate whole-frame byte streams.
        for iteration in 0..50_000u32 {
            let src = &base_streams[(rng.next() % base_streams.len() as u64) as usize];
            let mut bytes = src.clone();
            let flips = 1 + (rng.next() % 8) as usize;
            for _ in 0..flips {
                let idx = (rng.next() as usize) % bytes.len().max(1);
                if idx < bytes.len() {
                    bytes[idx] ^= (rng.next() & 0xFF) as u8;
                }
            }
            if rng.next() & 1 == 1 && !bytes.is_empty() {
                bytes.truncate((rng.next() as usize) % bytes.len());
            }

            let mut framer = Framer::new();
            let _ = framer.ingest(&bytes); // must not panic

            // Occasionally drive the framer with the mutated bytes SPLIT
            // into arbitrary frame-ish pieces to stress multi-ingest.
            if iteration % 7 == 0 && bytes.len() > 8 {
                let cut = (rng.next() as usize) % (bytes.len() - 1);
                let mut f2 = Framer::new();
                let _ = f2.ingest(&bytes[..cut]);
                let _ = f2.ingest(&bytes[cut..]);
            }
        }

        // Soak 2: random garbage frames entirely.
        for _ in 0..20_000u32 {
            let len = (rng.next() as usize) % 300;
            let junk: Vec<u8> = (0..len).map(|_| (rng.next() & 0xFF) as u8).collect();
            let mut framer = Framer::new();
            let _ = framer.ingest(&junk);
        }
    }
}
