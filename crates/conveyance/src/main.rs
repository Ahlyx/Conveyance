//! The Conveyance command line.
//!
//! Subcommands appear here as phases implement them. `pair` is first
//! (phase 6); daemon/shim/log subcommands follow in phases 7-9 and will
//! call into their crates' library surfaces rather than duplicating
//! logic here.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "conveyance",
    version,
    about = "Phone-approved capability broker for MCP tool calls"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start pairing: render a QR for the phone to scan, wait for the
    /// ceremony to complete.
    Pair {
        /// Hostname shown on the phone. Defaults to this machine's name.
        #[arg(long)]
        name: Option<String>,
    },
}

#[cfg(feature = "ble")]
fn data_dir() -> Result<std::path::PathBuf, String> {
    conveyance_core::paths::data_dir().map_err(|e| e.to_string())
}

#[cfg(feature = "ble")]
fn hostname_fallback() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "this-pc".to_string())
}

/// Load the long-term identity, generating + persisting it on first run.
/// Generation happens ONLY inside this explicit user-invoked command --
/// never as a side effect of some other command loading storage.
#[cfg(feature = "ble")]
fn load_or_create_identity(
    path: &std::path::Path,
) -> Result<conveyance_core::storage::identity::StoredIdentity, String> {
    use conveyance_core::storage::identity::{OsKeyring, StoredIdentity};

    match StoredIdentity::load(path, &OsKeyring) {
        Ok(id) => Ok(id),
        Err(conveyance_core::storage::StorageError::IdentityFileNotFound(_)) => {
            println!("no identity found -- generating one");
            let id = StoredIdentity::generate(&conveyance_core::crypto::OsEntropy)
                .map_err(|e| format!("entropy failure during identity generation: {e}"))?;
            id.save(path, &OsKeyring, &conveyance_core::crypto::OsEntropy)
                .map_err(|e| format!("failed to persist new identity: {e}"))?;
            println!("identity written to {}", path.display());
            Ok(id)
        }
        Err(e) => Err(format!(
            "cannot load identity: {e}\n\
             If the OS keychain is locked or unavailable, unlock it and retry."
        )),
    }
}

impl Command {
    async fn run(self) -> Result<(), String> {
        match self {
            Command::Pair { name } => pair(name).await,
        }
    }
}

#[cfg(feature = "ble")]
async fn pair(name: Option<String>) -> Result<(), String> {
    use conveyance_core::pairing::{CeremonyContext, CeremonyLimits, NonceGuard, run_pairing};
    use conveyance_core::transport::ble::BleTransport;

    let data = data_dir()?;
    let mut transport = BleTransport::new()
        .await
        .map_err(|e| format!("Bluetooth unavailable on this machine: {e}"))?;

    let identity = load_or_create_identity(&data.join("identity.enc"))?;
    let signer = identity.identity_key();
    let store = conveyance_core::storage::pairings::PairingsDb::open(&data.join("pairings.db"))
        .map_err(|e| e.to_string())?;
    let mut nonces = NonceGuard::open(&data.join("pairing-nonce-bloom.bin"));

    let mut ctx = CeremonyContext {
        pc_id_secret: &signer,
        pc_dh_pub: *identity.x25519_secret.expose(),
        pc_name: name.unwrap_or_else(hostname_fallback),
        service_uuid_bytes: conveyance_core::transport::ids::service_uuid_bytes(),
        store: &store,
        nonces: &mut nonces,
    };

    println!("Pairing: scan this QR with Conveyance on your phone.");
    println!("The code expires in 60 seconds.\n");

    let peer = run_pairing(&mut transport, &mut ctx, CeremonyLimits::spec(), |qr| {
        println!("{}", qr.render_ascii());
        println!("Waiting for phone to advertise and confirm...\n");
    })
    .await
    .map_err(|e| e.to_string())?;

    println!(
        "PAIRED. Phone handle: {}",
        conveyance_core::storage::pairings::phone_id_for(&peer.phone_id_pub)
    );
    Ok(())
}

#[cfg(not(feature = "ble"))]
async fn pair(_name: Option<String>) -> Result<(), String> {
    Err(
        "this build lacks BLE support; rebuild with:\n  cargo build --release --features ble"
            .to_string(),
    )
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(msg) = cli.command.run().await {
        // Exit codes: 1 = operation failed; the stub binaries' 2 for
        // unimplemented remains reserved to them.
        eprintln!("{msg}");
        std::process::exit(1);
    }
}
