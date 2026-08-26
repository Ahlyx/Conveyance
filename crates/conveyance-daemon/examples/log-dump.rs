//! Dump an executions.db log as JSONL for inspection and E2E
//! assertions. Read-only; never modifies the database.
//!
//! Usage: cargo run -p conveyance-daemon --example log-dump -- <path.db>

use conveyance_core::storage::logdb::LogDb;
use conveyance_core::wire::message::ReqId;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: log-dump <executions.db>");
        std::process::exit(2);
    });

    let db = match LogDb::open(std::path::Path::new(&path)) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("cannot open {path}: {e}");
            std::process::exit(1);
        }
    };

    match db.verify() {
        Ok(Ok(n)) => eprintln!("chain verified: {n} rows intact"),
        Ok(Err(issue)) => {
            eprintln!("CHAIN BROKEN: {issue}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("cannot verify: {e}");
            std::process::exit(1);
        }
    }

    for ev in db.events().expect("events readable after verify") {
        println!(
            "{}",
            serde_json::json!({
                "req_id": ReqId(ev.req_id).hex(),
                "event_type": ev.event_type,
                "payload": serde_json::from_str::<serde_json::Value>(&ev.payload_json)
                    .unwrap_or(serde_json::Value::String(ev.payload_json.clone())),
                "timestamp": ev.timestamp,
            })
        );
    }
}
