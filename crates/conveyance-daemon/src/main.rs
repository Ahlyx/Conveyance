//! The Conveyance daemon.
//!
//! Phase 0 stub: exists so the workspace builds and so `--version` works
//! from day one. It exits nonzero rather than pretending to run -- a stub
//! that exited 0 would look healthy to scripts and MCP client configs
//! while doing nothing.

fn main() {
    if std::env::args()
        .skip(1)
        .any(|arg| arg == "-V" || arg == "--version")
    {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return;
    }

    eprintln!("conveyance-daemon: not implemented yet (phase 7 of CONVEYANCE_PHASES.md)");
    std::process::exit(2);
}
