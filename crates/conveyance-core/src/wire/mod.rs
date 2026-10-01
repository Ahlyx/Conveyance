//! Compatibility exports for the shared application protocol and framing.

pub use conveyance_protocol::binding;
pub use conveyance_protocol::message;
pub use conveyance_protocol::{MismatchCause, ProtocolError};
pub use conveyance_wire::framing;

#[cfg(test)]
mod tests {
    use super::framing::Framer;
    use super::message::{Pong, ReqId, WireMessage, decode, encode};

    /// Cross-layer soak: mutated valid CBOR-message bytes fed through
    /// both the framer and message decoder. Neither may panic.
    #[test]
    fn mutation_soak_across_framing_and_message_decode() {
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
        let base_messages: Vec<Vec<u8>> = (0..8)
            .map(|n| {
                encode(&WireMessage::Pong(Pong {
                    req_id: ReqId([(n * 17) as u8; 16]),
                    timestamp: n as i64,
                }))
                .unwrap()
            })
            .collect();

        for _ in 0..50_000u32 {
            let src = &base_messages[(rng.next() % base_messages.len() as u64) as usize];
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
            let _ = Framer::new().ingest(&bytes);
            let _ = decode(&bytes);
        }
    }
}
