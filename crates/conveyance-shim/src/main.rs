//! The Conveyance MCP shim.
//!
//! Phase 0 stub, same rationale as the daemon stub: buildable now,
//! honest about not working yet. Real behavior (JSON-RPC over stdio,
//! IPC to the daemon) arrives in phase 8.

fn main() {
    if std::env::args()
        .skip(1)
        .any(|arg| arg == "-V" || arg == "--version")
    {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return;
    }

    eprintln!("conveyance-shim: not implemented yet (phase 8 of CONVEYANCE_PHASES.md)");
    std::process::exit(2);
}
