//! The daemon's seam to the phone transport.
//!
//! conveyance-core's `Transport`/`Link` traits use native `impl Trait`
//! methods and static generics on purpose (one transport per binary, no
//! plugin registry). That shape is not object-safe, but the session owner
//! wants ONE concrete type to hold regardless of what carries the bytes
//! -- mock in tests, btleplug in production. This module provides that
//! erased surface as a thin wrapper layer; it adds no logic of its own
//! and never touches framing or Noise.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use conveyance_core::transport::{Link, Transport};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Object-safe view of one live phone connection. Mirrors
/// [`conveyance_core::transport::Link`] exactly -- ordered chunks, typed
/// disconnection, explicit shutdown -- so nothing is lost through the
/// erasure.
pub trait PhoneLink: Send {
    fn max_write_len(&self) -> usize;
    fn send<'a>(
        &'a mut self,
        chunk: &'a [u8],
    ) -> BoxFuture<'a, Result<(), conveyance_core::transport::TransportError>>;
    fn recv(
        &mut self,
    ) -> BoxFuture<'_, Result<Vec<u8>, conveyance_core::transport::TransportError>>;
    fn shutdown(&mut self);
}

impl<L: Link> PhoneLink for L {
    fn max_write_len(&self) -> usize {
        Link::max_write_len(self)
    }

    fn send<'a>(
        &'a mut self,
        chunk: &'a [u8],
    ) -> BoxFuture<'a, Result<(), conveyance_core::transport::TransportError>> {
        Box::pin(Link::send(self, chunk))
    }

    fn recv(
        &mut self,
    ) -> BoxFuture<'_, Result<Vec<u8>, conveyance_core::transport::TransportError>> {
        Box::pin(Link::recv(self))
    }

    fn shutdown(&mut self) {
        Link::shutdown(self)
    }
}

/// Factory for [`PhoneLink`]s: "reach the paired phone" as one method.
/// Dial timeout expiry maps to `Timeout`, which the session owner
/// surfaces as `conveyance/phone_unreachable`.
pub trait PhoneDialer: Send {
    fn dial(
        &mut self,
        timeout: Duration,
    ) -> BoxFuture<'_, Result<Box<dyn PhoneLink>, conveyance_core::transport::TransportError>>;
}
/// Every core `Transport` automatically dials into the erased surface.
impl<T> PhoneDialer for T
where
    T: Transport + Send,
    T::Link: 'static,
{
    fn dial(
        &mut self,
        timeout: Duration,
    ) -> BoxFuture<'_, Result<Box<dyn PhoneLink>, conveyance_core::transport::TransportError>> {
        Box::pin(async move {
            let link = Transport::connect(self, timeout).await?;
            Ok(Box::new(link) as Box<dyn PhoneLink>)
        })
    }
}

/// Production dialer over real BLE. Constructed lazily on first dial:
/// adapter initialization can fail on machines without radios, and the
/// daemon must still come up to answer `status` -- a missing radio
/// surfaces as `phone_unreachable` at session start instead of blocking
/// startup. Feature-gated exactly like the underlying module.
#[cfg(feature = "ble")]
#[derive(Default)]
pub struct LazyBleDialer {
    inner: Option<conveyance_core::transport::ble::BleTransport>,
}

#[cfg(feature = "ble")]
impl PhoneDialer for LazyBleDialer {
    fn dial(
        &mut self,
        timeout: Duration,
    ) -> BoxFuture<'_, Result<Box<dyn PhoneLink>, conveyance_core::transport::TransportError>> {
        Box::pin(async move {
            if self.inner.is_none() {
                // Already a TransportError: no re-mapping needed.
                self.inner = Some(conveyance_core::transport::ble::BleTransport::new().await?);
            }
            // Checked immediately above.
            let transport = self.inner.as_mut().expect("initialized above");
            let link = Transport::connect(transport, timeout).await?;
            Ok(Box::new(link) as Box<dyn PhoneLink>)
        })
    }
}

/// Compiled without `ble`: there is no way to reach any phone. Session
/// start reports that honestly instead of pretending to scan.
pub struct NoTransportDialer;

impl PhoneDialer for NoTransportDialer {
    fn dial(
        &mut self,
        _timeout: Duration,
    ) -> BoxFuture<'_, Result<Box<dyn PhoneLink>, conveyance_core::transport::TransportError>> {
        Box::pin(async {
            Err(conveyance_core::transport::TransportError::InvalidState(
                "this build has no BLE support",
            ))
        })
    }
}
