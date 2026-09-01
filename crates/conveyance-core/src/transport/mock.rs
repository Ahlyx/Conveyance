//! In-memory transport: two cross-wired links over bounded tokio
//! channels.
//!
//! Every automated test runs against this. It implements the same
//! [`Link`](super::Link) contract as the real BLE module: ordered byte
//! chunks, backpressure via channel capacity, and typed disconnection
//! the moment the peer's side drops -- mid-reassembly included.

use std::time::Duration;

use tokio::sync::mpsc;

use super::{Link, Transport, TransportError};

/// Default per-direction channel capacity.
pub const DEFAULT_CAPACITY: usize = 256;
/// Default max write: large enough that whole frames pass in one op,
/// matching a generous MTU.
pub const DEFAULT_MAX_WRITE: usize = 512;

pub struct MockTransport {
    max_write: usize,
    tx: Option<mpsc::Sender<Vec<u8>>>,
    rx: Option<mpsc::Receiver<Vec<u8>>>,
}

impl MockTransport {
    /// Two cross-wired transports: whatever A sends arrives at B, and
    /// the reverse.
    pub fn pair() -> (MockTransport, MockTransport) {
        Self::pair_with(DEFAULT_CAPACITY, DEFAULT_MAX_WRITE)
    }

    pub fn pair_with(capacity: usize, max_write: usize) -> (MockTransport, MockTransport) {
        let (tx_a, rx_b) = mpsc::channel(capacity);
        let (tx_b, rx_a) = mpsc::channel(capacity);
        (
            MockTransport {
                max_write,
                tx: Some(tx_a),
                rx: Some(rx_a),
            },
            MockTransport {
                max_write,
                tx: Some(tx_b),
                rx: Some(rx_b),
            },
        )
    }
}

impl Transport for MockTransport {
    type Link = MockLink;

    /// Instant -- there is no radio. The timeout exists for trait parity
    /// with the real transport and is ignored.
    async fn connect(&mut self, _timeout: Duration) -> Result<Self::Link, TransportError> {
        let rx = self.rx.take().ok_or(TransportError::InvalidState(
            "this MockTransport already produced its link",
        ))?;
        let tx = self.tx.take().ok_or(TransportError::InvalidState(
            "this MockTransport already produced its link",
        ))?;
        Ok(MockLink {
            tx: Some(tx),
            rx: Some(rx),
            max_write: self.max_write,
            closed: false,
        })
    }
}

pub struct MockLink {
    /// Taken (None) once shut down: dropping our sender is what closes
    /// the peer's receive side -- a live clone here would make the peer
    /// wait forever instead of seeing Disconnected.
    tx: Option<mpsc::Sender<Vec<u8>>>,
    rx: Option<mpsc::Receiver<Vec<u8>>>,
    max_write: usize,
    closed: bool,
}

impl Link for MockLink {
    fn max_write_len(&self) -> usize {
        self.max_write
    }

    async fn send(&mut self, chunk: &[u8]) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::InvalidState("link shut down"));
        }
        if chunk.len() > self.max_write + crate::wire::framing::HEADER_LEN {
            // Contract enforcement: callers pass max_write_len() to
            // split_message as the PAYLOAD budget, so a well-formed frame
            // is that plus the 6-byte header. A larger chunk is a caller
            // bug we refuse rather than silently splitting (splitting is
            // framing's explicit job, not an accident).
            return Err(TransportError::InvalidState("chunk exceeds max_write_len"));
        }
        let tx = self
            .tx
            .as_ref()
            .ok_or(TransportError::InvalidState("link shut down"))?;
        match tx.send(chunk.to_vec()).await {
            Ok(()) => Ok(()),
            Err(_) => Err(TransportError::Disconnected),
        }
    }

    async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        if self.closed {
            return Err(TransportError::InvalidState("link shut down"));
        }
        match &mut self.rx {
            Some(rx) => match rx.recv().await {
                Some(chunk) => Ok(chunk),
                None => Err(TransportError::Disconnected),
            },
            None => Err(TransportError::InvalidState("link shut down")),
        }
    }

    /// Close our send side AND drop our receive side. The peer observes
    /// Disconnected on its next recv; our own subsequent ops observe
    /// InvalidState. Dropping both channel halves is what makes this real.
    fn shutdown(&mut self) {
        self.closed = true;
        self.tx = None;
        self.rx = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::test_suite;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn shared_suite_echo_through_full_stack() {
        test_suite::echo_through_full_stack(|| async {
            let (mut a, mut b) = MockTransport::pair();
            Ok((
                a.connect(Duration::ZERO).await?,
                b.connect(Duration::ZERO).await?,
            ))
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn shared_suite_multi_frame_send_respects_max_write_len() {
        test_suite::multi_frame_send_respects_max_write_len(|| async {
            // A small budget so the message is many frames.
            let (mut a, mut b) = MockTransport::pair_with(256, 20);
            Ok((
                a.connect(Duration::ZERO).await?,
                b.connect(Duration::ZERO).await?,
            ))
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn shared_suite_mid_reassembly_disconnect_is_typed() {
        test_suite::disconnect_mid_reassembly_is_typed(|| async {
            let (mut a, mut b) = MockTransport::pair();
            Ok((
                a.connect(Duration::ZERO).await?,
                b.connect(Duration::ZERO).await?,
            ))
        })
        .await
        .unwrap();
    }

    #[test]
    fn backpressure_blocks_third_send_at_capacity_two() {
        use std::sync::Arc;
        // current_thread + explicit yields make ordering deterministic.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();

        rt.block_on(async {
            let (mut ta, mut tb) = MockTransport::pair_with(2, 512);
            let mut la = ta.connect(Duration::ZERO).await.unwrap();
            let mut lb = tb.connect(Duration::ZERO).await.unwrap();
            drop(tb); // transport halves are factories; links are live

            let progress = Arc::new(AtomicUsize::new(0));
            let writer = {
                let progress = progress.clone();
                tokio::spawn(async move {
                    for i in 1..=5u8 {
                        la.send(format!("msg-{i}").as_bytes()).await.unwrap();
                        progress.fetch_add(1, Ordering::SeqCst);
                    }
                })
            };

            // Capacity is 2: sends 1 and 2 land; 3 blocks until we read.
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
            assert_eq!(
                progress.load(Ordering::SeqCst),
                2,
                "third send must still be blocked by backpressure"
            );

            assert_eq!(lb.recv().await.unwrap(), "msg-1".as_bytes());
            assert_eq!(lb.recv().await.unwrap(), "msg-2".as_bytes());
            assert_eq!(lb.recv().await.unwrap(), "msg-3".as_bytes());

            // Drain the rest; writer finishes.
            assert_eq!(lb.recv().await.unwrap(), "msg-4".as_bytes());
            assert_eq!(lb.recv().await.unwrap(), "msg-5".as_bytes());
            writer.await.unwrap();
        });
    }

    #[test]
    fn shutdown_semantics_are_explicit() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let (mut ta, mut tb) = MockTransport::pair();
            let mut la = ta.connect(Duration::ZERO).await.unwrap();
            let mut lb = tb.connect(Duration::ZERO).await.unwrap();

            la.shutdown();
            assert!(matches!(
                la.send(b"x").await,
                Err(TransportError::InvalidState(_))
            ));
            // Peer sees the channel close as disconnection.
            assert!(matches!(lb.recv().await, Err(TransportError::Disconnected)));
        });
    }

    #[test]
    fn oversized_chunk_is_refused_not_split_silently() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let (mut ta, tb) = MockTransport::pair_with(8, 16);
            let mut la = ta.connect(Duration::ZERO).await.unwrap();
            drop(tb);

            let big = vec![0u8; 32];
            assert!(matches!(
                la.send(&big).await,
                Err(TransportError::InvalidState("chunk exceeds max_write_len"))
            ));
        });
    }

    #[test]
    fn connect_is_single_use() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let (mut ta, _tb) = MockTransport::pair();
            ta.connect(Duration::ZERO).await.unwrap();
            assert!(matches!(
                ta.connect(Duration::ZERO).await,
                Err(TransportError::InvalidState(_))
            ));
        });
    }
}
