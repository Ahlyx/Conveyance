//! `conveyance log ...`: query, verify, export, diff over the
//! execution log. Shapes follow auditmcp's CLI ergonomics (required-
//! unit durations, --tool/--status filters, JSONL export, verify's
//! distinct exit codes) adapted to Conveyance's schema.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use conveyance_core::crypto::sign::IdentityPublicKey;
use conveyance_core::storage::logdb::{LogDb, VerifyVerdict};
use conveyance_core::storage::logdiff::{self, PcEvent, SigFailure};
use conveyance_core::wire::message::ReqId;

use crate::CliError;

// ---- shared filter plumbing ----------------------------------------------------

/// The filter set shared by `query` and `export`.
pub struct QueryFilter {
    pub since: Option<String>,
    pub tool: Option<String>,
    pub status: Option<String>,
    pub verbose: bool,
    pub anomalous: bool,
}

/// Parse auditmcp-style durations: digits plus a REQUIRED unit suffix.
/// A bare number is rejected rather than guessed at -- `--since 30`
/// meaning thirty of WHAT is a bug waiting to be written.
fn parse_since(raw: &str) -> Result<std::time::Duration, CliError> {
    let fail = || {
        CliError::fail(format!(
            "invalid --since value '{raw}': use a duration with a unit suffix (45s, 30m, 2h, 1d)"
        ))
    };
    if raw.len() < 2 {
        return Err(fail());
    }
    let (digits, unit) = raw.split_at(raw.len() - 1);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(fail());
    }
    let n: u64 = digits.parse().map_err(|_| fail())?;
    match unit {
        "s" => Ok(std::time::Duration::from_secs(n)),
        "m" => Ok(std::time::Duration::from_secs(n * 60)),
        "h" => Ok(std::time::Duration::from_secs(n * 3600)),
        "d" => Ok(std::time::Duration::from_secs(n * 86400)),
        _ => Err(fail()),
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn open_log(path: &Path) -> Result<LogDb, CliError> {
    LogDb::open(path).map_err(|e| CliError::fail(e.to_string()))
}

/// One row flattened for filtering/printing.
struct Row {
    req_id: [u8; 16],
    event_type: String,
    payload: serde_json::Value,
    timestamp: i64,
}

impl Row {
    fn service(&self) -> Option<&str> {
        self.payload.get("service").and_then(|v| v.as_str())
    }

    fn status(&self) -> Option<&str> {
        self.payload.get("status").and_then(|v| v.as_str())
    }

    /// Security-relevant rows per the spec's threat model: requests
    /// that timed out, executions that did not succeed cleanly, and
    /// integrity notes (bad signatures et al).
    fn anomalous(&self) -> bool {
        match self.event_type.as_str() {
            "request_timeout" | "daemon_note" => true,
            "execute_result" => self.status() != Some("ok"),
            _ => false,
        }
    }
}

fn load_rows(db: &LogDb) -> Result<Vec<Row>, CliError> {
    Ok(db
        .events()
        .map_err(|e| CliError::fail(e.to_string()))?
        .into_iter()
        .map(|ev| Row {
            payload: serde_json::from_str(&ev.payload_json)
                .unwrap_or(serde_json::Value::String(ev.payload_json.clone())),
            req_id: ev.req_id,
            event_type: ev.event_type,
            timestamp: ev.timestamp,
        })
        .collect())
}

fn apply_filters(rows: Vec<Row>, f: &QueryFilter) -> Result<Vec<Row>, CliError> {
    let cutoff = match &f.since {
        Some(raw) => {
            let d = parse_since(raw)?;
            Some(unix_now().saturating_sub(d.as_secs() as i64))
        }
        None => None,
    };

    let mut out = Vec::new();
    for row in rows {
        if let Some(cut) = cutoff
            && row.timestamp < cut
        {
            continue;
        }
        if let Some(tool) = &f.tool
            && row.service() != Some(tool.as_str())
        {
            continue;
        }
        if let Some(status) = &f.status
            && (row.event_type != "execute_result" || row.status() != Some(status.as_str()))
        {
            continue;
        }
        if f.anomalous && !row.anomalous() {
            continue;
        }
        out.push(row);
    }
    Ok(out)
}

// ---- query ---------------------------------------------------------------------

pub fn query(filter: QueryFilter, db_path: PathBuf) -> Result<(), CliError> {
    let db = open_log(&db_path)?;
    let rows = apply_filters(load_rows(&db)?, &filter)?;
    if rows.is_empty() {
        println!("(no matching entries)");
        return Ok(());
    }

    for row in &rows {
        if filter.verbose {
            let pretty = serde_json::to_string_pretty(&serde_json::json!({
                "req_id": ReqId(row.req_id).hex(),
                "event_type": row.event_type,
                "timestamp": row.timestamp,
                "payload": row.payload,
            }))
            .unwrap_or_default();
            println!("{pretty}");
        } else {
            // Compact line: time, short id, event, and the most useful
            // coordinate present. Full payloads live one --verbose away.
            let service = row.service().unwrap_or("-");
            let extra = match row.event_type.as_str() {
                "execute_result" => format!("status={}", row.status().unwrap_or("?")),
                "approval_denied" | "approval_granted" | "request_timeout" => String::new(),
                _ => String::new(),
            };
            let id8 = &ReqId(row.req_id).hex()[..8];
            println!(
                "{} {} {} {} {}",
                row.timestamp, id8, row.event_type, service, extra
            );
        }
    }
    Ok(())
}

// ---- verify ----------------------------------------------------------------------

/// Outcome of verify carrying the SPEC exit code (0/1/2).
pub struct VerifyExit {
    pub code: i32,
    pub message: String,
}

impl From<CliError> for VerifyExit {
    fn from(e: CliError) -> Self {
        VerifyExit {
            code: e.code.max(2),
            message: e.message,
        }
    }
}

pub fn verify(repair: bool, yes: bool, db_path: PathBuf) -> Result<(), VerifyExit> {
    let db = open_log(&db_path)?;
    match db.verify_with_meta().map_err(|e| VerifyExit {
        code: 2,
        message: e.to_string(),
    })? {
        VerifyVerdict::Intact(n) => {
            println!("chain intact ({n} entries)");
            Ok(())
        }
        VerifyVerdict::ChainBroken(issue) => Err(VerifyExit {
            code: 1,
            message: format!(
                "CHAIN VERIFICATION FAILED: {issue}\nThe execution log has been altered; \
                 treat its contents as untrusted evidence."
            ),
        }),
        VerifyVerdict::MetaStale {
            recorded_head,
            computed_head,
            rows,
        } => {
            if !repair {
                return Err(VerifyExit {
                    code: 2,
                    message: format!(
                        "chain intact ({rows} entries) but derived head metadata is stale\n\
                         recorded: {recorded_head}\ncomputed:  {computed_head}\n\
                         run with --repair [--yes] to rewrite it from the chain"
                    ),
                });
            }
            if !yes {
                // Dry run by default: metadata repair is harmless, but
                // the flag discipline keeps every write deliberate.
                println!(
                    "dry run: would rewrite recorded head {recorded_head} -> {computed_head}; \
                     pass --yes to apply"
                );
                return Err(VerifyExit {
                    code: 2,
                    message: String::new(),
                });
            }
            db.repair_meta().map_err(|e| VerifyExit {
                code: 2,
                message: e.to_string(),
            })?;
            println!("metadata repaired from chain");
            Ok(())
        }
    }
}

// ---- export ----------------------------------------------------------------------

pub fn export(
    filter: QueryFilter,
    output: Option<PathBuf>,
    db_path: PathBuf,
) -> Result<(), CliError> {
    let db = open_log(&db_path)?;
    let filtered = apply_filters(load_rows(&db)?, &filter)?;

    // Full fidelity: chain columns ride along so an export is a complete
    // offline artifact, not just events.
    let all_rows = db.rows().map_err(|e| CliError::fail(e.to_string()))?;
    let by_req_and_ts: std::collections::HashMap<(String, i64), (String, String)> = all_rows
        .iter()
        .map(|r| {
            (
                (ReqId(r.event.req_id).hex(), r.event.timestamp),
                (
                    conveyance_core::crypto::hex_encode(&r.prev_hash),
                    conveyance_core::crypto::hex_encode(&r.hash),
                ),
            )
        })
        .collect();

    let mut lines = Vec::with_capacity(filtered.len());
    for row in &filtered {
        let hex_id = ReqId(row.req_id).hex();
        let (prev_hash, hash) = by_req_and_ts
            .get(&(hex_id.clone(), row.timestamp))
            .cloned()
            .unwrap_or_default();
        let line = serde_json::json!({
            "req_id": hex_id,
            "event_type": row.event_type,
            "payload": row.payload,
            "timestamp": row.timestamp,
            "prev_hash": prev_hash,
            "hash": hash,
        });
        lines.push(line.to_string());
    }

    let mut body = lines.join("\n");
    if !lines.is_empty() {
        body.push('\n');
    }

    match output {
        None => {
            print!("{body}");
            Ok(())
        }
        // Atomic write via temp+rename: a reader (or a crash) never sees
        // half an export.
        Some(path) => {
            let tmp = path.with_extension("jsonl.tmp");
            {
                let mut file = std::fs::File::create(&tmp)
                    .map_err(|e| CliError::fail(format!("cannot create {}: {e}", tmp.display())))?;
                file.write_all(body.as_bytes())
                    .map_err(|e| CliError::fail(format!("write failed: {e}")))?;
                file.sync_all()
                    .map_err(|e| CliError::fail(format!("sync failed: {e}")))?;
            }
            std::fs::rename(&tmp, &path)
                .map_err(|e| CliError::fail(format!("rename failed: {e}")))?;
            println!("exported {} entries to {}", lines.len(), path.display());
            Ok(())
        }
    }
}

// ---- diff --------------------------------------------------------------------------

pub struct DiffPaths {
    pub pairings_db: PathBuf,
    pub executions_db: PathBuf,
}

pub fn diff(phone_export: &Path, paths: DiffPaths) -> Result<(), CliError> {
    // Unsigned/malformed phone entries refuse the whole run BEFORE any
    // reconciliation happens (spec MUST NOT accept them).
    let text = std::fs::read_to_string(phone_export)
        .map_err(|e| CliError::fail(format!("cannot read {}: {e}", phone_export.display())))?;
    let phone_rows = logdiff::parse_phone_export(&text)
        .map_err(|err| CliError::fail(format!("phone export rejected: {err}")))?;

    // v1 is single-phone: the export must reconcile against exactly one
    // pairing, whose key verifies every signature.
    let store = conveyance_core::storage::pairings::PairingsDb::open(&paths.pairings_db)
        .map_err(|e| CliError::fail(e.to_string()))?;
    let pairings = store.list().map_err(|e| CliError::fail(e.to_string()))?;
    let pairing = match pairings.len() {
        0 => {
            return Err(CliError::fail(
                "no paired phone: nothing to verify the export against",
            ));
        }
        1 => &pairings[0],
        n => {
            return Err(CliError::fail(format!(
                "{n} phones paired -- multi-phone diff needs a --phone selector (phase 11)"
            )));
        }
    };
    let phone_pub = IdentityPublicKey::from_bytes(&pairing.id_pub)
        .map_err(|e| CliError::fail(format!("stored pairing malformed: {e}")))?;

    // Wrong-signature rows are refused outright too: they are forged or
    // corrupted input, not a reconciliation category.
    let bad: Vec<String> = phone_rows
        .iter()
        .enumerate()
        .filter(|(_, r)| !r.verify_signature(&phone_pub))
        .map(|(i, r)| {
            format!(
                "line {}: signature verification failed (req_id {}, {})",
                i + 1,
                ReqId(r.req_id).hex(),
                r.event_type
            )
        })
        .collect();
    if !bad.is_empty() {
        return Err(CliError::fail(format!(
            "phone export contains entries that fail signature verification:\n{}",
            bad.join("\n")
        )));
    }

    let db = open_log(&paths.executions_db)?;
    let pc_events: Vec<PcEvent> = db
        .events()
        .map_err(|e| CliError::fail(e.to_string()))?
        .into_iter()
        .map(|ev| PcEvent {
            req_id: ev.req_id,
            event_type: ev.event_type,
            payload_json: ev.payload_json,
            timestamp: ev.timestamp,
        })
        .collect();

    let report = logdiff::diff_logs(&pc_events, &phone_rows, &phone_pub);

    println!("matched approvals/executions: {}", report.matched.len());
    for id in &report.matched {
        println!("  ok      {}", ReqId(*id).hex());
    }
    if !report.missing_execution.is_empty() {
        println!(
            "approved but never executed (may be benign): {}",
            report.missing_execution.len()
        );
        for id in &report.missing_execution {
            println!("  missing {}", ReqId(*id).hex());
        }
    }
    if !report.open_requests.is_empty() {
        println!(
            "requests with no decision recorded: {}",
            report.open_requests.len()
        );
        for id in &report.open_requests {
            println!("  open    {}", ReqId(*id).hex());
        }
    }
    if !report.execution_without_approval.is_empty() {
        println!(
            "SECURITY EVENT -- executions without approval: {}",
            report.execution_without_approval.len()
        );
        for id in &report.execution_without_approval {
            println!("  UNAPPROVED {}", ReqId(*id).hex());
        }
    }
    if !report.signature_failures.is_empty() {
        println!("signature failures: {}", report.signature_failures.len());
        for f in &report.signature_failures {
            let SigFailure {
                side,
                req_id,
                event_type,
            } = f;
            println!("  badsig  {:?} {} {event_type}", side, ReqId(*req_id).hex());
        }
    }
    if !report.timestamp_anomalies.is_empty() {
        println!(
            "timestamp anomalies (executed before approved): {}",
            report.timestamp_anomalies.len()
        );
        for a in &report.timestamp_anomalies {
            println!(
                "  clock?  {} executed_at={} approved_at={}",
                ReqId(a.req_id).hex(),
                a.executed_at,
                a.approved_at
            );
        }
    }

    if report.clean() {
        Ok(())
    } else {
        Err(CliError::fail(
            "reconciliation found security-relevant mismatches (see above)",
        ))
    }
}
