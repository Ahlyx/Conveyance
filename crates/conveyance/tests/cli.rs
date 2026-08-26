//! CLI integration tests driving the REAL binary via assert_cmd.
//!
//! Every test owns a temp data dir passed through --data-dir, so runs
//! never touch platform storage and can be seeded deterministically
//! through the same storage APIs the daemon uses.

use assert_cmd::Command;
use conveyance_core::crypto::dh::DhSecret;
use conveyance_core::crypto::hashchain::LogEvent;
use conveyance_core::crypto::sign::IdentitySecretKey;
use conveyance_core::crypto::{OsEntropy, hex_encode};
use conveyance_core::storage::logdb::LogDb;
use conveyance_core::storage::logdiff;
use conveyance_core::storage::pairings::PairingsDb;

use predicates::prelude::*;

fn bin() -> Command {
    // Not Command::cargo_bin (deprecated in favor of build-dir
    // independence); the env var is set by cargo for integration tests.
    Command::new(env!("CARGO_BIN_EXE_conveyance"))
}

fn temp_dir(tag: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("cvy-cli-{tag}-"))
        .tempdir()
        .unwrap()
}

fn seed_event(db: &LogDb, n: u8, event_type: &str, payload_json: &str, ts: i64) {
    let mut req_id = [0u8; 16];
    req_id[0] = n;
    db.append(&LogEvent {
        req_id,
        event_type: event_type.into(),
        payload_json: payload_json.into(),
        timestamp: ts,
    })
    .unwrap();
}

/// Seed a realistic mixed log: one clean request for github, one failed
/// execute for aws, one timeout, plus session lifecycle rows.
fn seed_mixed_log(dir: &std::path::Path) -> LogDb {
    let db = LogDb::open(&dir.join("executions.db")).unwrap();
    let base = unix_now_for_tests() - 3600; // an hour ago
    seed_event(
        &db,
        0,
        "session_start",
        r#"{"reason":"user_started"}"#,
        base,
    );
    seed_event(
        &db,
        1,
        "approval_request",
        r#"{"op_type":"authenticated_request","service":"github","method":"POST","endpoint":"/v1/deploy"}"#,
        base + 10,
    );
    seed_event(
        &db,
        1,
        "approval_granted",
        r#"{"decision":"approved","service":"github","method":"POST","endpoint":"/v1/deploy"}"#,
        base + 20,
    );
    seed_event(
        &db,
        1,
        "execute_sent",
        r#"{"service":"github","method":"POST","endpoint":"/v1/deploy"}"#,
        base + 21,
    );
    seed_event(
        &db,
        1,
        "execute_result",
        r#"{"status":"ok","http_status":200,"body":{"sha":"abc"},"executed_at":9}"#,
        base + 22,
    );
    seed_event(
        &db,
        2,
        "approval_request",
        r#"{"op_type":"authenticated_request","service":"aws","method":"GET","endpoint":"/list"}"#,
        base + 30,
    );
    seed_event(
        &db,
        2,
        "approval_granted",
        r#"{"decision":"approved","service":"aws","method":"GET","endpoint":"/list"}"#,
        base + 40,
    );
    seed_event(
        &db,
        2,
        "execute_sent",
        r#"{"service":"aws","method":"GET","endpoint":"/list"}"#,
        base + 41,
    );
    seed_event(
        &db,
        2,
        "execute_result",
        r#"{"status":"error","http_status":500,"body":{"boom":true},"executed_at":10}"#,
        base + 42,
    );
    seed_event(
        &db,
        3,
        "request_timeout",
        r#"{"reason":"timeout","op":"authenticated_request","service":"slowsvc","endpoint":"/x"}"#,
        base + 50,
    );
    seed_event(
        &db,
        0,
        "session_end",
        r#"{"reason":"idle_timeout"}"#,
        base + 60,
    );
    db
}

fn unix_now_for_tests() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---- verify exit codes ---------------------------------------------------------

#[test]
fn verify_intact_is_exit_zero() {
    let dir = temp_dir("verify-ok");
    seed_mixed_log(dir.path());

    bin()
        .args(["log", "verify", "--data-dir"])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("chain intact"));
}

#[test]
fn tampered_chain_is_exit_one() {
    let dir = temp_dir("verify-tamper");
    let db = seed_mixed_log(dir.path());
    let _ = db;
    drop(LogDb::open(&dir.path().join("executions.db")).unwrap());

    // Tamper as an attacker with file access would.
    let raw = rusqlite_conn(&dir.path().join("executions.db"));
    raw.execute(
        "UPDATE entries SET payload_json = '{\"evil\":true}' WHERE id = 2",
        [],
    )
    .unwrap();

    bin()
        .args(["log", "verify", "--data-dir"])
        .arg(dir.path())
        .assert()
        .code(1);
}

#[test]
fn stale_metadata_is_exit_two_and_repair_restores_zero() {
    let dir = temp_dir("verify-stale");
    seed_mixed_log(dir.path());
    drop(LogDb::open(&dir.path().join("executions.db")).unwrap());

    let raw = rusqlite_conn(&dir.path().join("executions.db"));
    raw.execute(
        "UPDATE chain_meta SET value = 'f00d' WHERE key = 'head_hash'",
        [],
    )
    .unwrap();

    // Without --repair: exit 2, message names both heads.
    bin()
        .args(["log", "verify", "--data-dir"])
        .arg(dir.path())
        .assert()
        .code(2)
        .stderr(predicates::str::contains("--repair"));

    // Dry run (--repair without --yes): still exit 2, nothing changed.
    bin()
        .args(["log", "verify", "--repair", "--data-dir"])
        .arg(dir.path())
        .assert()
        .code(2)
        .stdout(predicates::str::contains("dry run"));

    // Applied repair: back to exit 0.
    bin()
        .args(["log", "verify", "--repair", "--yes", "--data-dir"])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("repaired"));
    bin()
        .args(["log", "verify", "--data-dir"])
        .arg(dir.path())
        .assert()
        .success();
}

fn rusqlite_conn(path: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).unwrap()
}

#[test]
fn broken_chain_blocks_repair_even_when_requested() {
    let dir = temp_dir("verify-block");
    seed_mixed_log(dir.path());
    drop(LogDb::open(&dir.path().join("executions.db")).unwrap());

    let raw = rusqlite_conn(&dir.path().join("executions.db"));
    raw.execute("DELETE FROM entries WHERE id = 3", []).unwrap();
    // Also make metadata stale so --repair has something it WOULD want
    // to fix if the chain were intact.
    raw.execute(
        "UPDATE chain_meta SET value = 'f00d' WHERE key = 'head_hash'",
        [],
    )
    .unwrap();

    bin()
        .args(["log", "verify", "--repair", "--yes", "--data-dir"])
        .arg(dir.path())
        .assert()
        .code(1)
        .stderr(predicates::str::contains("CHAIN VERIFICATION FAILED"));
}

// ---- query filters ----------------------------------------------------------------

#[test]
fn query_tool_filter_selects_only_that_service() {
    let dir = temp_dir("query-tool");
    seed_mixed_log(dir.path());

    bin()
        .args(["log", "query", "--tool", "github", "--data-dir"])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("github").and(predicates::str::contains("aws").not()));
}

#[test]
fn query_status_error_selects_failed_executions() {
    let dir = temp_dir("query-status");
    seed_mixed_log(dir.path());

    bin()
        .args(["log", "query", "--status", "error", "--data-dir"])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("status=error"));
}

#[test]
fn query_anomalous_selects_timeouts_and_failures_not_clean_rows() {
    let dir = temp_dir("query-anom");
    seed_mixed_log(dir.path());

    let out = bin()
        .args(["log", "query", "--anomalous", "--data-dir"])
        .arg(dir.path())
        .assert()
        .success()
        .to_string();
    assert!(out.contains("request_timeout"), "{out}");
    assert!(out.contains("status=error"), "{out}");
    assert!(!out.contains("session_start"), "{out}");
}

#[test]
fn query_since_requires_a_unit_suffix() {
    let dir = temp_dir("query-since");
    seed_mixed_log(dir.path());

    bin()
        .args(["log", "query", "--since", "30", "--data-dir"])
        .arg(dir.path())
        .assert()
        .failure()
        .stderr(predicates::str::contains("unit suffix"));

    // And a well-formed unit works.
    bin()
        .args(["log", "query", "--since", "2h", "--data-dir"])
        .arg(dir.path())
        .assert()
        .success();
}

#[test]
fn query_verbose_prints_full_payloads() {
    let dir = temp_dir("query-verbose");
    seed_mixed_log(dir.path());

    bin()
        .args([
            "log",
            "query",
            "--verbose",
            "--status",
            "error",
            "--data-dir",
        ])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("\"body\"").and(predicates::str::contains("boom")));
}

// ---- export -----------------------------------------------------------------------

#[test]
fn export_writes_valid_jsonl_with_chain_columns() {
    let dir = temp_dir("export");
    seed_mixed_log(dir.path());
    let out_path = dir.path().join("export.jsonl");

    bin()
        .args(["log", "export", "--format", "jsonl", "--output"])
        .arg(&out_path)
        .arg("--data-dir")
        .arg(dir.path())
        .assert()
        .success();

    let text = std::fs::read_to_string(&out_path).unwrap();
    let mut saw_hash = false;
    for line in text.lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("valid JSONL line");
        assert!(v.get("req_id").is_some());
        assert!(v.get("hash").is_some());
        saw_hash |= v["hash"].as_str().map(|h| h.len() == 64).unwrap_or(false);
    }
    assert!(saw_hash, "chain columns must ride along");

    // Unknown format is refused loudly rather than silently producing
    // whatever the default is.
    bin()
        .args(["log", "export", "--format", "csv", "--output"])
        .arg(&out_path)
        .arg("--data-dir")
        .arg(dir.path())
        .assert()
        .failure();
}

// ---- unpair ------------------------------------------------------------------------

fn seed_pairing(dir: &std::path::Path) -> String {
    let store = PairingsDb::open(&dir.join("pairings.db")).unwrap();
    let key = IdentitySecretKey::generate(&OsEntropy).unwrap();
    let dh = DhSecret::generate(&OsEntropy).unwrap();
    let rec = store
        .record(
            key.public_key().to_bytes(),
            dh.public_key().to_bytes(),
            12345,
        )
        .unwrap();
    rec.phone_id
}

#[test]
fn unpair_with_yes_removes_then_reports_unknown() {
    let dir = temp_dir("unpair-yes");
    let phone_id = seed_pairing(dir.path());

    bin()
        .args(["unpair", &phone_id, "--yes", "--data-dir"])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("removed"));

    // Second removal: explicit nonzero, not silent success.
    bin()
        .args(["unpair", &phone_id, "--yes", "--data-dir"])
        .arg(dir.path())
        .assert()
        .failure();
}

#[test]
fn unpair_without_yes_refuses_non_interactively() {
    let dir = temp_dir("unpair-noyes");
    let phone_id = seed_pairing(dir.path());

    // Empty stdin: confirmation cannot be given, command aborts.
    bin()
        .args(["unpair", &phone_id, "--data-dir"])
        .arg(dir.path())
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicates::str::contains("--yes").or(predicates::str::contains("aborted")));

    // Explicit denial aborts too.
    bin()
        .args(["unpair", &phone_id, "--data-dir"])
        .arg(dir.path())
        .write_stdin("n\n")
        .assert()
        .failure();

    // The pairing survived both refusals.
    let out = bin()
        .args(["unpair", &phone_id, "--yes", "--data-dir"])
        .arg(dir.path())
        .assert()
        .success();
    let _ = out;
}

// ---- diff --------------------------------------------------------------------------

struct DiffFixture {
    phone_key: IdentitySecretKey,
}

impl DiffFixture {
    fn new(dir: &std::path::Path) -> Self {
        let store = PairingsDb::open(&dir.join("pairings.db")).unwrap();
        let key = IdentitySecretKey::generate(&OsEntropy).unwrap();
        let dh = DhSecret::generate(&OsEntropy).unwrap();
        store
            .record(key.public_key().to_bytes(), dh.public_key().to_bytes(), 1)
            .unwrap();
        Self { phone_key: key }
    }

    /// Write a signed phone export granting `ids`.
    fn write_phone_export(&self, path: &std::path::Path, grants: &[(u8, i64)]) {
        let rows: Vec<logdiff::PhoneLogRow> = grants
            .iter()
            .flat_map(|(n, ts)| {
                let mut rid = [0u8; 16];
                rid[0] = *n;
                vec![
                    logdiff::signed_row(&self.phone_key, rid, "approval_request", "{}", *ts),
                    logdiff::signed_row(&self.phone_key, rid, "approval_granted", "{}", ts + 5),
                ]
            })
            .collect();
        std::fs::write(path, logdiff::render_phone_export(&rows)).unwrap();
    }
}

#[test]
fn diff_clean_session_exits_zero() {
    let dir = temp_dir("diff-clean");
    let fx = DiffFixture::new(dir.path());
    let export = dir.path().join("phone.jsonl");
    fx.write_phone_export(&export, &[(1, unix_now_for_tests() - 100)]);

    // PC executed exactly that request, after approval.
    let db = LogDb::open(&dir.path().join("executions.db")).unwrap();
    let mut rid = [0u8; 16];
    rid[0] = 1;
    db.append(&LogEvent {
        req_id: rid,
        event_type: "execute_sent".into(),
        payload_json: r#"{"service":"github"}"#.into(),
        timestamp: unix_now_for_tests() - 90,
    })
    .unwrap();
    db.append(&LogEvent {
        req_id: rid,
        event_type: "execute_result".into(),
        payload_json: r#"{"status":"ok","executed_at":9}"#.into(),
        timestamp: unix_now_for_tests() - 80,
    })
    .unwrap();

    bin()
        .args(["log", "diff"])
        .arg(&export)
        .arg("--data-dir")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("matched approvals/executions: 1"));
}

#[test]
fn diff_flags_execution_without_approval_as_security_event() {
    let dir = temp_dir("diff-security");
    let fx = DiffFixture::new(dir.path());
    let export = dir.path().join("phone.jsonl");
    fx.write_phone_export(&export, &[]); // phone approved NOTHING

    let db = LogDb::open(&dir.path().join("executions.db")).unwrap();
    let mut rid = [0u8; 16];
    rid[0] = 7;
    db.append(&LogEvent {
        req_id: rid,
        event_type: "execute_result".into(),
        payload_json: r#"{"status":"ok","executed_at":9}"#.into(),
        timestamp: unix_now_for_tests(),
    })
    .unwrap();

    bin()
        .args(["log", "diff"])
        .arg(&export)
        .arg("--data-dir")
        .arg(dir.path())
        .assert()
        .failure()
        .stderr(predicates::str::contains("security-relevant"))
        .stdout(predicates::str::contains("SECURITY EVENT"));
}

#[test]
fn diff_flags_missing_execution_without_failing() {
    let dir = temp_dir("diff-missing");
    let fx = DiffFixture::new(dir.path());
    let export = dir.path().join("phone.jsonl");
    fx.write_phone_export(&export, &[(4, unix_now_for_tests() - 50)]);

    // No PC execution at all: benign per spec, exit stays zero.
    bin()
        .args(["log", "diff"])
        .arg(&export)
        .arg("--data-dir")
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicates::str::contains("never executed"));
}

#[test]
fn diff_refuses_unsigned_export_naming_the_line() {
    let dir = temp_dir("diff-unsigned");
    let fx = DiffFixture::new(dir.path());
    let export = dir.path().join("phone.jsonl");

    // One properly signed row followed by an unsigned forgery.
    let good = logdiff::signed_row(
        &fx.phone_key,
        [1u8; 16],
        "approval_granted",
        "{}",
        unix_now_for_tests(),
    );
    let mut lines = vec![logdiff::render_phone_export(std::slice::from_ref(&good))];
    lines.push(format!(
        "{{\"req_id\":\"{}\",\"event_type\":\"approval_granted\",\"payload_json\":\"{{}}\",\"timestamp\":1,\"signature\":\"{}\"}}",
        hex_encode(&[2u8; 16]),
        hex_encode(&[0u8; 64]),
    ));
    std::fs::write(&export, lines.concat()).unwrap();

    bin()
        .args(["log", "diff"])
        .arg(&export)
        .arg("--data-dir")
        .arg(dir.path())
        .assert()
        .failure()
        .stderr(predicates::str::contains("signature verification failed"));
}
