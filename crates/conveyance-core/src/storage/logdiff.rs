//! Log reconciliation: the phone's approval log against the PC's
//! execution log, per the spec's "Diff tool" section.
//!
//! The two logs are independent by design; reconciliation by `req_id`
//! is what makes mismatches visible. Five report categories, verbatim
//! from the spec:
//!
//! * **Matched** -- approval granted on the phone, execution recorded
//!   on the PC. The healthy case.
//! * **Missing execution** -- approved but never executed on the PC.
//!   "May be benign" (crash, network); volume is the tell.
//! * **Execution without approval** -- SECURITY EVENT. Under correct
//!   operation this is impossible; its presence means a bug or an
//!   attack and it must never be smoothed over.
//! * **Signature verification failures** -- on either side.
//! * **Timestamp anomalies** -- execution recorded before its approval.
//!
//! Hard rules from the spec shape the interface: the diff MUST NOT
//! modify either log (pure function over parsed rows), and MUST NOT
//! accept unsigned phone entries ([`parse_phone_export`] hard-fails
//! naming the offending lines rather than skipping them).
//!
//! Phone-export wire format (the contract Android implements in phase
//! 10), one JSON object per line:
//!
//! ```json
//! {"req_id":"<32 hex>","event_type":"approval_request",
//!  "payload_json":"{\"decision\":...}","timestamp":1700000000,
//!  "signature":"<128 hex>"}
//! ```
//!
//! `signature` is Ed25519 by the phone's identity key over
//! `"conveyance-phone-log-v1" || canonical_json({event_type,
//! payload_json, timestamp, req_id})` -- the same context-prefix +
//! canonical-JSON-minus-signature construction the wire protocol uses,
//! so one verification code path serves both.

use serde::Deserialize;

use crate::crypto::OsEntropy;
use crate::crypto::canonical_json::canonicalize;
use crate::crypto::sign::{IdentityPublicKey, IdentitySecretKey};

/// Context tag prepended to every signed phone-log row.
pub const PHONE_LOG_CONTEXT: &[u8] = b"conveyance-phone-log-v1";

// ---- phone export model -------------------------------------------------------

/// One exported phone log row, after strict parsing.
#[derive(Clone, Debug, PartialEq)]
pub struct PhoneLogRow {
    pub req_id: [u8; 16],
    pub event_type: String,
    /// Canonical JSON text exactly as the phone hashed it -- kept as a
    /// string so signature verification sees the original bytes' content.
    pub payload_json: String,
    pub timestamp: i64,
    pub signature: [u8; 64],
}

#[derive(Debug)]
struct RawPhoneRow {
    req_id: String,
    event_type: String,
    payload_json: String,
    timestamp: i64,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPhoneRowDe {
    req_id: String,
    event_type: String,
    payload_json: String,
    timestamp: i64,
    signature: String,
}

impl RawPhoneRow {
    fn from_de(d: RawPhoneRowDe) -> Self {
        Self {
            req_id: d.req_id,
            event_type: d.event_type,
            payload_json: d.payload_json,
            timestamp: d.timestamp,
            signature: d.signature,
        }
    }
}

fn hex_to_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    if !s.len().is_multiple_of(2) || s.len() != N * 2 {
        return None;
    }
    // Lowercase hex only: exports are byte-stable artifacts, and
    // accepting mixed case here would make two renders of one row
    // compare unequal everywhere else.
    let mut out = [0u8; N];
    for (i, byte) in s.as_bytes().chunks(2).enumerate() {
        let hi = match byte[0] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            _ => return None,
        };
        let lo = match byte[1] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            _ => return None,
        };
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// What [`parse_phone_export`] rejects, with the 1-based line number --
/// a diff tool that skips bad rows silently would produce a
/// reconciliation report that looks complete but isn't.
#[derive(Debug, Clone, PartialEq)]
pub struct ExportParseError {
    pub line: usize,
    pub reason: String,
}

impl std::fmt::Display for ExportParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.reason)
    }
}

/// Strictly parse a phone export. ANY malformed or unsigned row fails
/// the whole parse: the spec's "MUST NOT accept unsigned phone entries"
/// is implemented as refusal, not as a warning category.
pub fn parse_phone_export(text: &str) -> Result<Vec<PhoneLogRow>, ExportParseError> {
    let mut rows = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let raw: RawPhoneRowDe = serde_json::from_str(line).map_err(|e| ExportParseError {
            line: line_no,
            reason: format!("invalid JSON row: {e}"),
        })?;
        let raw = RawPhoneRow::from_de(raw);

        let req_id = hex_to_fixed::<16>(&raw.req_id).ok_or_else(|| ExportParseError {
            line: line_no,
            reason: "req_id must be 32 lowercase hex chars".into(),
        })?;
        // Signatures arrive hex-encoded in JSON (no byte-array type);
        // uppercase is rejected so exports are byte-stable artifacts.
        let signature = hex_to_fixed::<64>(&raw.signature).ok_or_else(|| ExportParseError {
            line: line_no,
            reason: "signature must be 128 hex chars".into(),
        })?;
        if raw.event_type.is_empty() {
            return Err(ExportParseError {
                line: line_no,
                reason: "event_type must not be empty".into(),
            });
        }

        rows.push(PhoneLogRow {
            req_id,
            event_type: raw.event_type,
            payload_json: raw.payload_json,
            timestamp: raw.timestamp,
            signature,
        });
    }
    Ok(rows)
}

/// The canonical bytes a phone-log signature covers:
/// `"conveyance-phone-log-v1" || canonical_json(minus signature)`.
fn phone_row_signing_payload(row: &PhoneLogRow) -> Result<Vec<u8>, String> {
    let value = serde_json::json!({
        "req_id": lower_hex(&row.req_id),
        "event_type": row.event_type,
        "payload_json": row.payload_json,
        "timestamp": row.timestamp,
    });
    let canonical = canonicalize(&value).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(PHONE_LOG_CONTEXT.len() + canonical.len());
    out.extend_from_slice(PHONE_LOG_CONTEXT);
    out.extend_from_slice(canonical.as_bytes());
    Ok(out)
}

impl PhoneLogRow {
    pub fn verify_signature(&self, phone_public: &IdentityPublicKey) -> bool {
        match phone_row_signing_payload(self) {
            Ok(payload) => phone_public.verify(&payload, &self.signature).is_ok(),
            Err(_) => false,
        }
    }

    /// Sign a row -- test/producer side (phase 10's Android app is the
    /// real producer).
    pub fn sign(mut self, key: &IdentitySecretKey) -> Self {
        let payload = phone_row_signing_payload(&self).expect("own row serializes");
        self.signature = key.sign(&payload);
        self
    }
}

/// Build one correctly signed row (tests and fixtures).
pub fn signed_row(
    key: &IdentitySecretKey,
    req_id: [u8; 16],
    event_type: &str,
    payload_json: &str,
    timestamp: i64,
) -> PhoneLogRow {
    PhoneLogRow {
        req_id,
        event_type: event_type.into(),
        payload_json: payload_json.into(),
        timestamp,
        signature: [0u8; 64],
    }
    .sign(key)
}

/// Serialize rows back to export form (roundtrip helper for tests and
/// tooling that synthesizes exports).
pub fn render_phone_export(rows: &[PhoneLogRow]) -> String {
    let mut out = String::new();
    for r in rows {
        let line = serde_json::json!({
            "req_id": lower_hex(&r.req_id),
            "event_type": r.event_type,
            "payload_json": r.payload_json,
            "timestamp": r.timestamp,
            "signature": lower_hex(&r.signature),
        });
        out.push_str(&line.to_string());
        out.push('\n');
    }
    out
}

/// Fresh key for fixtures.
#[allow(dead_code)]
pub(crate) fn fixture_key() -> IdentitySecretKey {
    IdentitySecretKey::generate(&OsEntropy).expect("OS entropy available")
}

// ---- diff engine ---------------------------------------------------------------

/// One PC-side event as the diff sees it: the subset of `ChainRow`
/// content the reconciliation needs. Decoupled from rusqlite types so
/// the engine is pure.
#[derive(Clone, Debug, PartialEq)]
pub struct PcEvent {
    pub req_id: [u8; 16],
    pub event_type: String,
    pub payload_json: String,
    pub timestamp: i64,
}

/// A fully categorized reconciliation report.
#[derive(Debug, Default, PartialEq)]
pub struct DiffReport {
    /// Granted approvals whose execution exists on the PC. Healthy.
    pub matched: Vec<[u8; 16]>,
    /// Granted approvals with NO execution on the PC ("may be benign").
    pub missing_execution: Vec<[u8; 16]>,
    /// SECURITY EVENT: PC executions with no granted approval behind
    /// them. Impossible under correct operation.
    pub execution_without_approval: Vec<[u8; 16]>,
    /// Rows (either side) whose signature failed verification. Present
    /// only when callers opt into lenient mode -- see [`diff_logs`].
    pub signature_failures: Vec<SigFailure>,
    /// Execution recorded BEFORE its approval decision.
    pub timestamp_anomalies: Vec<TimestampAnomaly>,
    /// Approval requests the phone received with no decision recorded.
    /// Informational (session cut short mid-prompt).
    pub open_requests: Vec<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SigSide {
    Phone,
    Pc,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SigFailure {
    pub side: SigSide,
    pub req_id: [u8; 16],
    pub event_type: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TimestampAnomaly {
    pub req_id: [u8; 16],
    pub executed_at: i64,
    pub approved_at: i64,
}

impl DiffReport {
    /// True when nothing security-relevant was found. Missing
    /// executions and open requests are explicitly NOT
    /// security-relevant (spec: "may be benign"); anything else is.
    pub fn clean(&self) -> bool {
        self.execution_without_approval.is_empty()
            && self.signature_failures.is_empty()
            && self.timestamp_anomalies.is_empty()
    }
}

/// Reconcile phone rows against PC events.
///
/// Signature policy: phone rows are verified here and failures land in
/// `signature_failures` while the ROW IS EXCLUDED from matching --
/// a failed signature must never silently pass as matched data.
/// (`parse_phone_export` already hard-fails on structurally invalid or
/// absent signatures; this second check catches WRONG signatures, which
/// are evidence, not input errors.) PC-side execute_result rows carry
/// their response signature inside the payload (`signature` field, hex)
/// when produced by phase-9+ daemons; older payloads without it are
/// noted as unverifiable rather than failed -- absence of a field is
/// not evidence of forgery.
///
/// Timestamp rule per spec: execution timestamped before its APPROVAL
/// DECISION is anomalous. Comparison is against `approval_granted`
/// (the moment consent existed), not the earlier request.
pub fn diff_logs(
    pc_events: &[PcEvent],
    phone_rows: &[PhoneLogRow],
    phone_pub: &IdentityPublicKey,
) -> DiffReport {
    let mut report = DiffReport::default();

    // ---- phone-side signature verification ---------------------------------
    let mut trusted_phone: Vec<&PhoneLogRow> = Vec::with_capacity(phone_rows.len());
    for row in phone_rows {
        if row.verify_signature(phone_pub) {
            trusted_phone.push(row);
        } else {
            report.signature_failures.push(SigFailure {
                side: SigSide::Phone,
                req_id: row.req_id,
                event_type: row.event_type.clone(),
            });
        }
    }

    // ---- indexes by req_id --------------------------------------------------
    use std::collections::HashMap;
    let mut pc_executed: HashMap<[u8; 16], &PcEvent> = HashMap::new();
    for ev in pc_events {
        match ev.event_type.as_str() {
            "execute_sent" => {
                pc_executed.entry(ev.req_id).or_insert(ev);
            }
            "execute_result" => {
                pc_executed.insert(ev.req_id, ev);
            }
            _ => {}
        }
    }

    let mut granted: HashMap<[u8; 16], i64> = HashMap::new();
    let mut requested: Vec<[u8; 16]> = Vec::new();
    for row in &trusted_phone {
        match row.event_type.as_str() {
            "approval_request" => requested.push(row.req_id),
            "approval_granted" => {
                granted.entry(row.req_id).or_insert(row.timestamp);
            }
            _ => {}
        }
    }

    // ---- PC-side signature verification (embedded ExecuteResponse sigs) ----
    for ev in pc_events {
        if ev.event_type != "execute_result" {
            continue;
        }
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(&ev.payload_json) else {
            continue;
        };
        let Some(sig_hex) = payload.get("signature").and_then(|s| s.as_str()) else {
            continue; // pre-phase-9 row: unverifiable, not untrusted
        };
        let Some(sig) = hex_to_fixed::<64>(sig_hex) else {
            report.signature_failures.push(SigFailure {
                side: SigSide::Pc,
                req_id: ev.req_id,
                event_type: ev.event_type.clone(),
            });
            continue;
        };
        // Rebuild the ExecuteResponse signing view: everything the wire
        // signature covered except the signature itself. Absent
        // optionals must be OMITTED, not null (spec amendment).
        let mut unsigned = payload.clone();
        if let Some(obj) = unsigned.as_object_mut() {
            obj.remove("signature");
        }
        let mut signing_view = serde_json::json!({
            "req_id": lower_hex(&ev.req_id),
            "status": unsigned.get("status").cloned().unwrap_or(serde_json::Value::Null),
            "http_status": unsigned.get("http_status").cloned().unwrap_or(serde_json::Value::Null),
            "body": unsigned.get("body").cloned().unwrap_or(serde_json::Value::Null),
            "executed_at": unsigned.get("executed_at").cloned().unwrap_or(serde_json::Value::Null),
        });
        if let Some(obj) = signing_view.as_object_mut() {
            obj.retain(|_, v| !v.is_null());
        }
        let Ok(canonical) = canonicalize(&signing_view) else {
            report.signature_failures.push(SigFailure {
                side: SigSide::Pc,
                req_id: ev.req_id,
                event_type: ev.event_type.clone(),
            });
            continue;
        };
        let mut covered = Vec::with_capacity(wire_execute_context().len() + canonical.len());
        covered.extend_from_slice(wire_execute_context());
        covered.extend_from_slice(canonical.as_bytes());

        if phone_pub.verify(&covered, &sig).is_err() {
            report.signature_failures.push(SigFailure {
                side: SigSide::Pc,
                req_id: ev.req_id,
                event_type: ev.event_type.clone(),
            });
        }
    }

    // ---- category assignment ------------------------------------------------
    let mut seen_missing: Vec<[u8; 16]> = Vec::new();
    for (req_id, approved_at) in &granted {
        match pc_executed.get(req_id) {
            None => seen_missing.push(*req_id),
            Some(exec) => {
                report.matched.push(*req_id);
                if exec.timestamp < *approved_at {
                    report.timestamp_anomalies.push(TimestampAnomaly {
                        req_id: *req_id,
                        executed_at: exec.timestamp,
                        approved_at: *approved_at,
                    });
                }
            }
        }
    }
    report.missing_execution = seen_missing;

    for req_id in pc_executed.keys() {
        if !granted.contains_key(req_id) {
            report.execution_without_approval.push(*req_id);
        }
    }

    // Open requests: requested but never decided AND not executed.
    for req_id in requested {
        if !granted.contains_key(&req_id) && !pc_executed.contains_key(&req_id) {
            report.open_requests.push(req_id);
        }
    }

    // Deterministic output ordering everywhere.
    report.matched.sort_unstable();
    report.missing_execution.sort_unstable();
    report.execution_without_approval.sort_unstable();
    report.open_requests.sort_unstable();
    report.timestamp_anomalies.sort_by_key(|a| a.executed_at);
    report
        .signature_failures
        .sort_by(|a, b| a.side.cmp(&b.side).then(a.req_id.cmp(&b.req_id)));
    report
}

fn wire_execute_context() -> &'static [u8] {
    crate::wire::message::EXECUTE_CONTEXT
}

// ---- tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sign::IdentitySecretKey;

    fn key() -> IdentitySecretKey {
        IdentitySecretKey::generate(&OsEntropy).unwrap()
    }

    fn rid(n: u8) -> [u8; 16] {
        let mut id = [0u8; 16];
        id[0] = n;
        id
    }

    fn phone_row(
        k: &IdentitySecretKey,
        req_id: [u8; 16],
        event_type: &str,
        ts: i64,
    ) -> PhoneLogRow {
        signed_row(k, req_id, event_type, r#""{}""#, ts)
    }

    fn pc_event(req_id: [u8; 16], event_type: &str, ts: i64) -> PcEvent {
        PcEvent {
            req_id,
            event_type: event_type.into(),
            payload_json: "{}".into(),
            timestamp: ts,
        }
    }

    #[test]
    fn parse_and_signature_roundtrip() {
        let k = key();
        let rows = vec![
            phone_row(&k, rid(1), "approval_request", 100),
            phone_row(&k, rid(1), "approval_granted", 105),
        ];
        let text = render_phone_export(&rows);
        let parsed = parse_phone_export(&text).unwrap();
        assert_eq!(parsed, rows);
        for row in &parsed {
            assert!(row.verify_signature(&k.public_key()));
        }
    }

    #[test]
    fn tampered_row_fails_verification() {
        let k = key();
        let mut row = phone_row(&k, rid(2), "approval_granted", 200);
        // Flip one payload byte after signing.
        row.payload_json = r#""{evil}""#.into();
        assert!(!row.verify_signature(&k.public_key()));

        // Wrong verifier key fails too.
        let stranger = key();
        let honest = phone_row(&k, rid(3), "approval_granted", 300);
        assert!(!honest.verify_signature(&stranger.public_key()));
    }

    #[test]
    fn parse_rejects_unsigned_malformed_and_uppercase() {
        // Missing signature field entirely.
        let err = parse_phone_export(
            r#"{"req_id":"aa","event_type":"x","payload_json":"{}","timestamp":1}"#,
        )
        .unwrap_err();
        assert_eq!(err.line, 1);

        let k = key();
        let mut good = phone_row(&k, rid(9), "approval_granted", 5);
        good.signature = [0xAB; 64];
        // Uppercase ONLY the hex payloads; field names stay lowercase so
        // the JSON itself parses and the hex rule is what fires.
        let line = render_phone_export(std::slice::from_ref(&good));
        let uppered = line.replace(
            &lower_hex(&[0xAB; 64]),
            &lower_hex(&[0xAB; 64]).to_uppercase(),
        );
        let err = parse_phone_export(&uppered).unwrap_err();
        assert!(
            err.reason.contains("hex"),
            "uppercase hex must be refused: {err}"
        );

        // Wrong-length hex likewise.
        let short = render_phone_export(std::slice::from_ref(&good))
            .replace(&lower_hex(&good.req_id), &format!("{:016x}", 1u128));
        let err = parse_phone_export(&short).unwrap_err();
        assert!(err.reason.contains("32 lowercase hex"), "{err}");

        let err = parse_phone_export("{not json").unwrap_err();
        assert_eq!(err.line, 1);
    }

    /// The spec's core reconciliation: granted+executed matches,
    /// granted-without-execution is missing (benign), executed without
    /// grant is a SECURITY EVENT.
    #[test]
    fn all_three_primary_categories() {
        let k = key();
        let matched = rid(10);
        let missing = rid(11);
        let security = rid(12);

        let phone = vec![
            phone_row(&k, matched, "approval_request", 100),
            phone_row(&k, matched, "approval_granted", 110),
            phone_row(&k, missing, "approval_request", 200),
            phone_row(&k, missing, "approval_granted", 210),
        ];
        let pc = vec![
            pc_event(matched, "execute_sent", 120),
            pc_event(matched, "execute_result", 130),
            pc_event(security, "execute_sent", 300),
            pc_event(security, "execute_result", 310),
        ];

        let report = diff_logs(&pc, &phone, &k.public_key());
        assert_eq!(report.matched, vec![matched]);
        assert_eq!(report.missing_execution, vec![missing]);
        assert_eq!(report.execution_without_approval, vec![security]);
        assert!(
            report.signature_failures.is_empty(),
            "sig failures: {:?}",
            report.signature_failures
        );
        assert!(
            report.timestamp_anomalies.is_empty(),
            "ts anomalies: {:?}",
            report.timestamp_anomalies
        );
        // The fixture deliberately CONTAINS a security event, so
        // clean() must be false here -- that is the point of category.
        assert!(!report.clean());
    }

    /// A fully healthy session reconciles clean end to end.
    #[test]
    fn fully_matched_session_is_clean() {
        let k = key();
        let a = rid(60);
        let b = rid(61);
        let phone = vec![
            phone_row(&k, a, "approval_request", 10),
            phone_row(&k, a, "approval_granted", 20),
            phone_row(&k, b, "approval_request", 30),
            phone_row(&k, b, "approval_denied", 35),
            phone_row(&k, b, "session_end", 40),
        ];
        let pc = vec![
            pc_event(a, "execute_sent", 25),
            pc_event(a, "execute_result", 26),
        ];
        let report = diff_logs(&pc, &phone, &k.public_key());
        assert_eq!(report.matched, vec![a]);
        // Denied requests are decisions, not missing executions.
        assert!(report.missing_execution.is_empty());
        assert!(report.clean(), "{report:?}");
    }

    #[test]
    fn execution_before_approval_is_a_timestamp_anomaly() {
        let k = key();
        let weird = rid(20);
        let phone = vec![phone_row(&k, weird, "approval_granted", 500)];
        let pc = vec![pc_event(weird, "execute_result", 400)];

        let report = diff_logs(&pc, &phone, &k.public_key());
        assert_eq!(report.matched, vec![weird], "still matched, but flagged");
        assert_eq!(
            report.timestamp_anomalies,
            vec![TimestampAnomaly {
                req_id: weird,
                executed_at: 400,
                approved_at: 500
            }]
        );
        assert!(!report.clean());
    }

    #[test]
    fn bad_phone_signature_excludes_row_and_reports() {
        let k = key();
        let stranger = key();
        let ok_id = rid(30);
        let forged_id = rid(31);

        let mut phone = vec![
            phone_row(&k, ok_id, "approval_granted", 100),
            phone_row(&stranger, forged_id, "approval_granted", 100),
        ];
        // Re-sign the first with the right key only.
        phone[0] = phone[0].clone().sign(&k);

        let pc = vec![pc_event(ok_id, "execute_result", 110)];
        let report = diff_logs(&pc, &phone, &k.public_key());

        assert_eq!(report.matched, vec![ok_id]);
        assert_eq!(
            report.signature_failures,
            vec![SigFailure {
                side: SigSide::Phone,
                req_id: forged_id,
                event_type: "approval_granted".into(),
            }]
        );
        // The forged grant must NOT have suppressed the matched pair or
        // created phantom categories.
        assert!(!report.execution_without_approval.contains(&forged_id));
        assert!(!report.clean());
    }

    /// Undecided requests are informational, not failures.
    #[test]
    fn open_requests_are_reported_informationally() {
        let k = key();
        let pending = rid(40);
        let phone = vec![phone_row(&k, pending, "approval_request", 100)];
        let report = diff_logs(&[], &phone, &k.public_key());
        assert_eq!(report.open_requests, vec![pending]);
        assert!(report.clean());
    }

    /// PC-side verification of the embedded ExecuteResponse signature:
    /// the exact shape phase-9 daemons write into execute_result
    /// payloads. Absent signature (older rows) is unverifiable-not-
    /// untrusted; wrong signature IS reported.
    #[test]
    fn pc_embedded_execute_signatures_verify_or_fail() {
        use crate::wire::message::{ExecuteResponse, Status};

        let phone_key = key();
        let exec_id = rid(50);

        let resp = ExecuteResponse::new(
            crate::wire::message::ReqId(exec_id),
            Status::Ok,
            Some(200),
            serde_json::json!({"ok": true}),
            777,
        )
        .unwrap()
        .sign(&phone_key);

        let sig_hex = lower_hex(&resp.signature);
        let payload = serde_json::json!({
            "status": "ok",
            "http_status": 200,
            "body": {"ok": true},
            "executed_at": 777,
            "signature": sig_hex,
        });
        let mut pc = vec![PcEvent {
            req_id: exec_id,
            event_type: "execute_result".into(),
            payload_json: payload.to_string(),
            timestamp: 778,
        }];

        let report = diff_logs(&pc, &[], &phone_key.public_key());
        assert!(
            report.signature_failures.is_empty(),
            "correctly signed execute_result must verify: {report:?}"
        );

        // Tamper the stored body: the embedded signature no longer
        // covers it, and diff must say so.
        let mut forged = payload.as_object().unwrap().clone();
        forged.insert("body".into(), serde_json::json!({"evil": true}));
        pc[0].payload_json = serde_json::Value::Object(forged).to_string();

        let report = diff_logs(&pc, &[], &phone_key.public_key());
        assert_eq!(
            report.signature_failures,
            vec![SigFailure {
                side: SigSide::Pc,
                req_id: exec_id,
                event_type: "execute_result".into(),
            }]
        );
        assert!(!report.clean());
    }
}
