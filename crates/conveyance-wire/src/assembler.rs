//! Byte-stream reassembly: raw link bytes -> whole application messages.

use crate::framing::{DEFAULT_REASSEMBLY_CAP, FrameError, Framer, HEADER_LEN};

/// Reassembles raw link bytes into whole application messages.
///
/// Why this exists on top of a bare [`Framer`]: a GATT operation is
/// bounded by the negotiated MTU, which can be smaller than one frame,
/// so a single frame may arrive split across several notifications — and
/// frames themselves chain into messages. This type buffers the byte
/// stream, slices out complete frames on the `HEADER_LEN + declared`
/// boundary, and feeds each to ONE persistent [`Framer`] so every rule
/// (reserved byte, flag legality, sequence continuity, the 128 KiB cap)
/// is enforced in exactly one place. One per direction; discard it with
/// the link on disconnect.
///
/// The length prefix is checked against the cap *before* the buffer is
/// grown toward it: a hostile `declared` never causes an allocation.
#[derive(Debug, Default)]
pub struct InboundAssembler {
    buffer: Vec<u8>,
    framer: Framer,
}

impl InboundAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed inbound bytes; returns every application message that
    /// completed on this call, in order. A frame that never completes is
    /// buffered for the next call; an over-cap length prefix is
    /// `MessageTooLarge` before any buffering toward it.
    pub fn ingest(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, FrameError> {
        const CAP: usize = DEFAULT_REASSEMBLY_CAP;

        self.buffer.extend_from_slice(bytes);
        if self.buffer.len() > CAP {
            return Err(FrameError::MessageTooLarge {
                size: self.buffer.len(),
                cap: CAP,
            });
        }

        let mut messages = Vec::new();
        loop {
            if self.buffer.len() < HEADER_LEN {
                return Ok(messages);
            }
            let declared = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;

            // Validate the length prefix against the cap BEFORE draining:
            // never allocate toward an attacker-chosen size.
            if declared > CAP {
                return Err(FrameError::MessageTooLarge {
                    size: declared,
                    cap: CAP,
                });
            }
            let total = HEADER_LEN + declared;
            if self.buffer.len() < total {
                return Ok(messages);
            }
            let frame: Vec<u8> = self.buffer.drain(..total).collect();

            if let Some(message) = self.framer.ingest(&frame)? {
                messages.push(message);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{encode_ack, max_frame_payload, split_message};

    #[test]
    fn a_frame_split_across_ingests_reassembles() {
        let msg = vec![0x42u8; 400];
        let (frames, _) = split_message(&msg, max_frame_payload(23), 0).unwrap();
        let stream: Vec<u8> = frames.concat();

        // Feed the whole stream one byte at a time.
        let mut asm = InboundAssembler::new();
        let mut out = Vec::new();
        for b in &stream {
            out.extend(asm.ingest(&[*b]).unwrap());
        }
        assert_eq!(out, vec![msg]);
    }

    #[test]
    fn arbitrary_cut_points_reassemble_and_multiple_messages_emerge_in_one_ingest() {
        let a = b"first".to_vec();
        let b = b"second message a bit longer".to_vec();
        let (fa, next) = split_message(&a, 4, 0).unwrap();
        let (fb, _) = split_message(&b, 4, next).unwrap();
        let stream: Vec<u8> = fa.iter().chain(fb.iter()).flatten().copied().collect();

        // One ingest of the entire concatenation yields both messages.
        let mut asm = InboundAssembler::new();
        assert_eq!(asm.ingest(&stream).unwrap(), vec![a.clone(), b.clone()]);

        // And an ugly 3-way cut yields the same.
        let mut asm = InboundAssembler::new();
        let mut out = Vec::new();
        for chunk in [&stream[..3], &stream[3..7], &stream[7..]] {
            out.extend(asm.ingest(chunk).unwrap());
        }
        assert_eq!(out, vec![a, b]);
    }

    #[test]
    fn interleaved_ack_is_ignored_by_the_stream_path() {
        let msg = b"payload across three frames here".to_vec();
        let (frames, _) = split_message(&msg, 8, 30).unwrap();
        assert!(frames.len() >= 3);

        let mut stream = frames[0].clone();
        stream.extend_from_slice(&encode_ack(30)); // ACK between START and the rest
        for f in &frames[1..] {
            stream.extend_from_slice(f);
        }

        let mut asm = InboundAssembler::new();
        assert_eq!(asm.ingest(&stream).unwrap(), vec![msg]);
    }

    #[test]
    fn a_length_prefix_over_the_cap_is_rejected_before_buffering() {
        // Header only: declared length = 0xFFFF, far over any single
        // frame but under the 128 KiB cap — so this is accepted as a
        // (very large) pending frame, not an error.
        let mut asm = InboundAssembler::new();
        let big_but_legal = [0xFF, 0xFF, 0, 0, 0b011, 0];
        assert_eq!(asm.ingest(&big_but_legal).unwrap(), Vec::<Vec<u8>>::new());

        // Now a stream whose first two bytes alone can't exceed u16, so
        // the cap is tripped by the accumulated buffer instead: push more
        // than 128 KiB of bytes.
        let mut asm = InboundAssembler::new();
        let flood = vec![0u8; DEFAULT_REASSEMBLY_CAP + 1];
        assert!(matches!(
            asm.ingest(&flood),
            Err(FrameError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn framing_errors_propagate_through_the_stream_path() {
        // A bare middle frame (no START) is a stray-middle violation.
        let (frames, _) = split_message(&[7u8; 30], 8, 0).unwrap();
        let mut asm = InboundAssembler::new();
        assert!(matches!(
            asm.ingest(&frames[1]),
            Err(FrameError::StrayMiddleFrame)
        ));
    }
}
