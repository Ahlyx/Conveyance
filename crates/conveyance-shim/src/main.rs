//! The `conveyance-mcp-shim` binary: MCP over stdio for external
//! clients (Claude Code, mcp-inspector). All logic lives in the
//! library so the `conveyance mcp-shim` CLI subcommand and this bin
//! are the same code.

use conveyance_daemon::effective_socket;
use conveyance_daemon::load_config_or_defaults;

fn main() {
    if std::env::args().any(|arg| arg == "-V" || arg == "--version") {
        println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        return;
    }

    let mut socket: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => match args.next() {
                Some(s) => socket = Some(s),
                None => die("missing value for --socket"),
            },
            other => die(&format!(
                "unknown argument {other:?} (usage: [--socket NAME])"
            )),
        }
    }

    let socket = socket.unwrap_or_else(|| {
        load_config_or_defaults()
            .map(|cfg| effective_socket(&cfg))
            .unwrap_or_else(|e| die(&format!("cannot resolve daemon socket: {e}")))
    });

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| die(&format!("cannot start async runtime: {e}")));

    eprintln!("conveyance shim: serving MCP on stdio (daemon socket '{socket}')");
    match runtime.block_on(conveyance_shim::run(&socket)) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("conveyance shim: {e}");
            std::process::exit(1);
        }
    }
}

fn die(message: &str) -> ! {
    eprintln!("conveyance-mcp-shim: {message}");
    std::process::exit(2);
}
