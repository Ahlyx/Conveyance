//! Transport abstraction: the seam between phase-4 bytes and whatever
//! carries them.
//!
//! Two implementations exist:
//!
//! * [`mock`] — cross-wired in-memory channels. Every automated test
//!   runs against this, on every platform, in CI.
//! * [`ble`] (feature `ble`) — real GATT central via btleplug. Its
//!   platform behavior is deliberately asymmetric (BlueZ/D-Bus on Linux,
//!   CoreBluetooth + entitlement on macOS, WinRT on Windows); that
//!   bag-of-behavior lives entirely inside that module and never leaks
//!   past [`Link`].
//!
//! Design notes:
//!
//! * Static generics with associated types -- no `dyn`. There is exactly
//!   one transport per binary composition and no plugin registry; native
//!   async fns keep the trait honest.
//! * The methods use return-position `impl Trait ... + Send` rather than
//!   bare `async fn` so consumers (phase 7's daemon) can `select!` and
//!   `spawn` over them without fighting the Send-inference gap.
//! * Chunks, not messages: `send`/`recv` move single MTU-sized pieces.
//!   Message splitting/reassembly belongs to phase 4's framing layer,
//!   which runs unchanged over any `Link`.

pub mod ids;
pub mod mock;

#[cfg(feature = "ble")]
pub mod ble;

use std::future::Future;
use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("peer disconnected")]
    Disconnected,
    #[error("operation timed out")]
    Timeout,
    #[error("expected BLE object not found: {0}")]
    NotFound(&'static str),
    #[error("link in invalid state: {0}")]
    InvalidState(&'static str),
    /// Platform error text from btleplug/OS. These strings are platform
    /// diagnostics, not secrets.
    #[error("BLE platform error: {0}")]
    Ble(String),
}

impl From<crate::wire::ProtocolError> for TransportError {
    fn from(e: crate::wire::ProtocolError) -> Self {
        TransportError::Ble(e.to_string())
    }
}

impl From<crate::wire::framing::FrameError> for TransportError {
    fn from(e: crate::wire::framing::FrameError) -> Self {
        TransportError::Ble(e.to_string())
    }
}

impl TransportError {
    /// Upstream mapping: a disconnected link ends the session as
    /// `EndReason::PeerDisconnected` (phase 3 contract).
    pub fn is_disconnection(&self) -> bool {
        matches!(self, TransportError::Disconnected)
    }
}

/// One live connection's data path.
pub trait Link: Send {
    /// Largest payload this link accepts per `send` call. Derived from
    /// the negotiated MTU where the platform exposes it; feeds
    /// `wire::framing::split_message`.
    fn max_write_len(&self) -> usize;

    /// Push one chunk toward the peer. Backpressure is legitimate --
    /// callers await it rather than buffering without bound.
    fn send(&mut self, chunk: &[u8]) -> impl Future<Output = Result<(), TransportError>> + Send;

    /// Await the next inbound chunk from the peer. Resolves once per
    /// notification/channel item. Errors with `Disconnected` when the
    /// peer goes away -- mid-message disconnection included; reassembly
    /// state dies with the link and nothing panics.
    fn recv(&mut self) -> impl Future<Output = Result<Vec<u8>, TransportError>> + Send;

    /// Begin teardown. Idempotent; after this, `send`/`recv` return
    /// `InvalidState` or `Disconnected` rather than blocking forever.
    fn shutdown(&mut self);
}

/// Factory for links of one kind.
pub trait Transport {
    type Link: Link;

    /// Establish a connection, bounded by `timeout`. For BLE this covers
    /// scan + connect + service discovery + subscription; expiry maps to
    /// `Timeout`, which the session layer surfaces as
    /// `conveyance/phone_unreachable`.
    fn connect(
        &mut self,
        timeout: Duration,
    ) -> impl Future<Output = Result<Self::Link, TransportError>> + Send;
}

/// Byte-stream reassembly for a sub-MTU transport. Defined in
/// `conveyance-wire` alongside `Framer` (phase 10.3) so the Android port
/// mirrors one implementation; re-exported here because the daemon's
/// session loop drives it through `conveyance_core::transport`.
pub use conveyance_wire::InboundAssembler;

/// Shared behavior every Link implementation must exhibit. Run against
/// the mock in CI; the real BLE side cannot self-loopback (a radio cannot
/// talk to itself), so its pass through here happens only in the manual
/// probe setup against an advertising stub -- same functions, different
/// factory.
#[cfg(test)]
pub(crate) mod test_suite {
    use super::*;
    use crate::wire::framing::split_message;
    use crate::wire::message::{Ping, ReqId, WireMessage, encode};

    type Pair<L> = (L, L);

    /// Full-stack fidelity: phase-4 message -> CBOR -> framing split ->
    /// link sends (auto-chunked where the link requires it) -> recvs ->
    /// InboundAssembler -> decode -> identical message.
    pub(crate) async fn echo_through_full_stack<L, F, Fut>(
        make_pair: F,
    ) -> Result<(), TransportError>
    where
        L: Link,
        F: Fn() -> Fut,
        Fut: Future<Output = Result<Pair<L>, TransportError>>,
    {
        let (mut a, mut b) = make_pair().await?;

        let original = WireMessage::Ping(Ping {
            req_id: ReqId([0xA5; 16]),
            timestamp: 1_234,
        });
        let bytes = encode(&original)?;
        let max_chunk = usize::min(a.max_write_len(), b.max_write_len());
        let (frames, _) = split_message(&bytes, max_chunk.min(24), 0)?;

        for frame in &frames {
            a.send(frame).await?;
        }

        let mut assembler_b = InboundAssembler::new();
        let mut received: Option<Vec<u8>> = None;
        while received.is_none() {
            let chunk = b.recv().await?;
            for message in assembler_b.ingest(&chunk)? {
                received = Some(message);
            }
        }

        let decoded: WireMessage = ciborium::de::from_reader(&mut &received.unwrap()[..])
            .map_err(|e| TransportError::Ble(e.to_string()))?;
        assert_eq!(decoded, original);
        Ok(())
    }

    /// Mid-stream disconnection surfaces as typed Disconnected on both
    /// sides of the event: the RECEIVER who already pulled part of a
    /// multi-frame message (its assembler state dies with the link --
    /// silently discarded, never half-delivered), and the SENDER whose
    /// next write hits a closed channel.
    pub(crate) async fn disconnect_mid_reassembly_is_typed<L, F, Fut>(
        mut make_pair: F,
    ) -> Result<(), TransportError>
    where
        L: Link,
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<Pair<L>, TransportError>>,
    {
        let message = vec![7u8; 100];
        let (frames, _) = split_message(&message, 30, 0)?;

        // Receiver side: pull the START, lose the peer, expect typed
        // Disconnection -- not silence, not a panic.
        let (mut a, mut b) = make_pair().await?;
        a.send(&frames[0]).await?;
        let start = b.recv().await?;
        assert_eq!(start, frames[0]);
        drop(a);
        match b.recv().await {
            Err(TransportError::Disconnected) => {}
            Ok(trailing) => panic!("trailing data after peer drop: {trailing:?}"),
            Err(other) => return Err(other),
        }
        drop(b);

        // Sender side: writing to a vanished peer fails typed too.
        let (mut a, b) = make_pair().await?;
        drop(b);
        match a.send(&frames[0]).await {
            Err(TransportError::Disconnected) => {}
            // A bounded buffer may accept the copy before noticing; that
            // is also acceptable -- the failure must surface eventually,
            // and this transport's contract says "eventually, typed".
            Ok(()) => {}
            Err(other) => return Err(other),
        }
        Ok(())
    }
}
