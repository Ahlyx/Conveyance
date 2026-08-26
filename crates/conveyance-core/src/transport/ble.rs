//! Real GATT-central transport via btleplug.
//!
//! Platform reality check (expected work, not scope creep): Linux speaks
//! BlueZ over D-Bus and behaves differently across distro BlueZ
//! versions; macOS is CoreBluetooth and needs the Bluetooth entitlement
//! plus a first-use system prompt; Windows is WinRT -- usually the most
//! consistent central-role platform, with its own async quirks. All of
//! that lives HERE. Consumers see only [`Link`](super::Link).
//!
//! SECURITY NOTE -- scan matching is deliberately permissive: a peer is
//! accepted when its advertisement lists the Conveyance service UUID OR
//! carries it in service-data. Android's advertising API places the UUID
//! in different fields depending on OS version, vendor, and advertising
//! mode; strict list-only matching silently fails against real phones.
//! Permissiveness here is safe because scan matching decides only *who
//! to attempt a connection with*, never *who to trust*: nothing is
//! authenticated until the Noise KK handshake (phase 3) succeeds against
//! the stored pairing.

use std::time::Duration;

use btleplug::api::{
    Central, CharPropFlags, Characteristic, Manager as _, Peripheral as _, ScanFilter, WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral};
use tokio::sync::mpsc;
use uuid::Uuid;

use super::{Link, Transport, TransportError};

pub use super::ids::{PC_TO_PHONE_TX_UUID, PHONE_TO_PC_TX_UUID, SERVICE_UUID};

pub fn service_uuid() -> Uuid {
    Uuid::parse_str(SERVICE_UUID).expect("pinned constant must parse")
}

fn pc_to_phone_uuid() -> Uuid {
    Uuid::parse_str(PC_TO_PHONE_TX_UUID).expect("pinned constant must parse")
}

fn phone_to_pc_uuid() -> Uuid {
    Uuid::parse_str(PHONE_TO_PC_TX_UUID).expect("pinned constant must parse")
}

/// Fallback when the platform cannot report a write length: the BLE
/// minimum MTU (23) minus 3 bytes of ATT overhead.
const MIN_WRITE_LEN: usize = 20;
/// Ceiling used when the platform DOES report; keeps phase-4 framing
/// chunks comfortable without stressing small-MTU peers.
const KNOWN_GOOD_WRITE_LEN: usize = 512;

pub struct BleTransport {
    manager: Manager,
    /// How long one advertisement sweep sleeps before checking matches.
    /// Total connect budget stays bounded by Transport::connect's timeout.
    sweep_time: Duration,
}

impl BleTransport {
    pub async fn new() -> Result<Self, TransportError> {
        let manager = Manager::new()
            .await
            .map_err(|e| TransportError::Ble(e.to_string()))?;
        Ok(Self {
            manager,
            sweep_time: Duration::from_millis(250),
        })
    }

    async fn first_adapter(&self) -> Result<Adapter, TransportError> {
        let adapters = self
            .manager
            .adapters()
            .await
            .map_err(|e| TransportError::Ble(e.to_string()))?;
        adapters.into_iter().next().ok_or(TransportError::NotFound(
            "no Bluetooth adapter on this machine",
        ))
    }

    /// True when an advertisement names the Conveyance service, either
    /// in its service list or in service-data (see module SECURITY NOTE).
    async fn advert_matches(per: &Peripheral) -> bool {
        match per.properties().await {
            Ok(Some(props)) => {
                props.services.contains(&service_uuid())
                    || props.service_data.keys().any(|u| *u == service_uuid())
            }
            _ => false,
        }
    }
}

impl Transport for BleTransport {
    type Link = BleLink;

    async fn connect(&mut self, timeout: Duration) -> Result<Self::Link, TransportError> {
        use futures_lite::StreamExt;

        let deadline = tokio::time::Instant::now() + timeout;
        let adapter = self.first_adapter().await?;
        adapter
            .start_scan(ScanFilter {
                services: vec![service_uuid()],
            })
            .await
            .map_err(|e| TransportError::Ble(e.to_string()))?;

        // ---- scan ------------------------------------------------------
        let peripheral: Peripheral = 'scan: loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(TransportError::Timeout);
            }
            tokio::time::sleep(step_sleep(self.sweep_time, deadline)).await;

            let peripherals = adapter
                .peripherals()
                .await
                .map_err(|e| TransportError::Ble(e.to_string()))?;
            for per in peripherals {
                if Self::advert_matches(&per).await {
                    break 'scan per;
                }
            }
        };

        // ---- connect + discover ---------------------------------------
        peripheral
            .connect_with_timeout(timeout)
            .await
            .map_err(|_| TransportError::Timeout)?;
        peripheral
            .discover_services()
            .await
            .map_err(|e| TransportError::Ble(e.to_string()))?;

        let service = peripheral
            .services()
            .into_iter()
            .find(|s| s.uuid == service_uuid())
            .ok_or(TransportError::NotFound("Conveyance service"))?;
        let write_char: Characteristic = service
            .characteristics
            .iter()
            .find(|c| c.uuid == pc_to_phone_uuid())
            .cloned()
            .ok_or(TransportError::NotFound("pc_to_phone_tx characteristic"))?;
        let notify_char: Characteristic = service
            .characteristics
            .iter()
            .find(|c| c.uuid == phone_to_pc_uuid())
            .cloned()
            .ok_or(TransportError::NotFound("phone_to_pc_tx characteristic"))?;

        // Sanity on roles, since a stub advertiser could wire them wrong:
        // pc_to_phone must be writable by us, phone_to_pc must notify.
        if !write_char
            .properties
            .contains(CharPropFlags::WRITE_WITHOUT_RESPONSE)
            && !write_char.properties.contains(CharPropFlags::WRITE)
        {
            return Err(TransportError::NotFound(
                "pc_to_phone_tx lacks a write property",
            ));
        }
        if !notify_char.properties.contains(CharPropFlags::NOTIFY) {
            return Err(TransportError::NotFound(
                "phone_to_pc_tx lacks the notify property",
            ));
        }

        peripheral
            .subscribe(&notify_char)
            .await
            .map_err(|e| TransportError::Ble(e.to_string()))?;

        // ---- notification pump -----------------------------------------
        let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
        let mut stream = peripheral
            .notifications()
            .await
            .map_err(|e| TransportError::Ble(e.to_string()))?;
        let expected = notify_char.uuid;
        tokio::spawn(async move {
            while let Some(note) = stream.next().await {
                // Filter here so foreign-characteristic noise never
                // reaches the session layer.
                if note.uuid == expected && tx.send(note.value).await.is_err() {
                    return; // link dropped: stop pumping
                }
            }
            // Stream ended == connection lost. The receiving half turns
            // that into TransportError::Disconnected.
        });

        // Negotiated MTU minus 3 bytes of ATT overhead, clamped to sane
        // bounds. This is what phase-4 split_message sizes chunks with.
        let max_write = (peripheral.mtu() as usize)
            .saturating_sub(3)
            .clamp(MIN_WRITE_LEN, KNOWN_GOOD_WRITE_LEN);

        Ok(BleLink {
            peripheral,
            write_char,
            max_write,
            rx,
        })
    }
}

fn step_sleep(sweep: Duration, deadline: tokio::time::Instant) -> Duration {
    let now = tokio::time::Instant::now();
    sweep.min(deadline.saturating_duration_since(now))
}

pub struct BleLink {
    peripheral: Peripheral,
    write_char: Characteristic,
    max_write: usize,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl Link for BleLink {
    fn max_write_len(&self) -> usize {
        self.max_write
    }

    async fn send(&mut self, chunk: &[u8]) -> Result<(), TransportError> {
        if chunk.len() > self.max_write {
            return Err(TransportError::InvalidState(
                "chunk exceeds negotiated max_write_len",
            ));
        }
        // Spec: pc_to_phone_tx is write-without-response. A few platforms
        // (WinRT on some characteristic configs) reject that mode; fall
        // back to WithResponse exactly once rather than failing the
        // session over an OS quirk.
        match self
            .peripheral
            .write(&self.write_char, chunk, WriteType::WithoutResponse)
            .await
        {
            Ok(()) => Ok(()),
            Err(first) => self
                .peripheral
                .write(&self.write_char, chunk, WriteType::WithResponse)
                .await
                .map_err(|second| {
                    TransportError::Ble(format!(
                        "without-response: {first}; with-response: {second}"
                    ))
                }),
        }
    }

    async fn recv(&mut self) -> Result<Vec<u8>, TransportError> {
        match self.rx.recv().await {
            Some(chunk) => Ok(chunk),
            None => Err(TransportError::Disconnected),
        }
    }

    fn shutdown(&mut self) {
        // disconnect() is async but Link::shutdown is sync; drive it on
        // the runtime rather than dropping it unawaited. Requires a live
        // tokio context, which every caller of this crate has.
        let per = self.peripheral.clone();
        tokio::spawn(async move {
            if let Err(e) = per.disconnect().await {
                // Best effort: dropping our handle also tears down on all
                // supported backends; log-grade failure at most.
                eprintln!("ble shutdown disconnect error: {e}");
            }
        });
    }
}
