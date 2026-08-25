//! Manual BLE probe: scan for the Conveyance service, connect, print
//! what we find, then echo every notification back on pc_to_phone_tx.
//!
//! Run with an advertising stub (nRF Connect on any Android phone:
//! advertise the service UUID with the two characteristics -- notify on
//! phone_to_pc_tx, write-without-response on pc_to_phone_tx):
//!
//! ```text
//! cargo run --release --features ble --example ble_probe
//! ```
//!
//! Expected output: adapter found -> peripheral matched -> connected ->
//! characteristics resolved -> subscription live. Writing anything from
//! the stub's side should arrive here and be echoed back to the stub.

#[cfg(feature = "ble")]
mod run {
    use conveyance_core::transport::{
        Link as _, Transport,
        ble::{BleTransport, PC_TO_PHONE_TX_UUID, PHONE_TO_PC_TX_UUID, SERVICE_UUID},
    };
    use std::time::Duration;

    pub async fn main_async() {
        println!("Conveyance BLE probe");
        println!("  service      : {SERVICE_UUID}");
        println!("  pc_to_phone  : {PC_TO_PHONE_TX_UUID}");
        println!("  phone_to_pc  : {PHONE_TO_PC_TX_UUID}");

        let mut transport = BleTransport::new()
            .await
            .expect("no Bluetooth adapter / backend (check platform support)");

        println!("scanning for up to 30s...");
        let mut link = transport
            .connect(Duration::from_secs(30))
            .await
            .expect("connect failed: is the stub advertising?");
        println!(
            "connected. max_write_len = {} bytes; echoing notifications back.",
            link.max_write_len()
        );

        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            if tokio::time::Instant::now() >= deadline {
                println!("60s elapsed -- done.");
                return;
            }
            match tokio::time::timeout(Duration::from_secs(5), link.recv()).await {
                Err(_) => continue, // quiet 5s windows are normal while idle
                Ok(Ok(chunk)) => {
                    println!("recv {} bytes: {:02x?}", chunk.len(), chunk);
                    link.send(&chunk).await.expect("echo send failed");
                    println!("echoed back.");
                }
                Ok(Err(e)) => {
                    println!("link error: {e}");
                    return;
                }
            }
        }
    }
}

#[cfg(not(feature = "ble"))]
mod run {
    pub async fn main_async() {
        eprintln!(
            "built without feature 'ble' -- rebuild with: cargo run --features ble --example ble_probe"
        );
        std::process::exit(2);
    }
}

#[tokio::main]
async fn main() {
    run::main_async().await;
}
