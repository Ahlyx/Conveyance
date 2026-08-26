//! The `conveyance-daemon` binary: a thin wrapper over the library
//! surface. All logic lives in the lib so the CLI's `conveyance daemon`
//! subcommand and this binary are the same code with different arg
//! parsing.

fn main() {
    let mut socket: Option<String> = None;
    let mut config_path: Option<std::path::PathBuf> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--socket" => {
                socket = Some(
                    args.next()
                        .unwrap_or_else(|| die("missing value for --socket")),
                );
            }
            "--config" => {
                config_path = Some(std::path::PathBuf::from(
                    args.next()
                        .unwrap_or_else(|| die("missing value for --config")),
                ));
            }
            other => die(&format!(
                "unknown argument {other:?} (usage: [--config PATH] [--socket NAME])"
            )),
        }
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| die(&format!("cannot start async runtime: {e}")));

    let code = runtime.block_on(async move {
        let raw = if let Some(path) = config_path {
            match conveyance_core::config::Config::load_from_path(&path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("cannot load {}: {e}", path.display());
                    return 1;
                }
            }
        } else {
            match conveyance_daemon::load_config_or_defaults() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{e}");
                    return 1;
                }
            }
        };

        let mut config = match conveyance_daemon::resolve_config(&raw) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{e}");
                return 1;
            }
        };
        if let Some(s) = socket {
            config.socket = s;
        }

        match conveyance_daemon::run(config).await {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("{e}");
                1
            }
        }
    });

    std::process::exit(code);
}

fn die(message: &str) -> ! {
    eprintln!("conveyance-daemon: {message}");
    std::process::exit(2);
}
