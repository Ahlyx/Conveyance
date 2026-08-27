//! Approval-execute binding: the anti-TOCTOU check.
//!
//! The spec's rule: an ExecuteRequest MUST reference a previously
//! approved req_id and MUST match the approved fields byte-for-byte after
//! canonical JSON serialization. This tracker is the enforcement point:
//!
//! * `record_approval` stores the canonical JSON of the approved request.
//! * `validate_execute` compares the incoming ExecuteRequest against it
//!   and CONSUMES the approval on success (spec amendment: approvals do
//!   not survive their first execution).
//!
//! All rejections carry distinct [`MismatchCause`] values for local
//! logging while surfacing the same `conveyance/approval_mismatch` code
//! to clients -- an attack signal either way. Consumed ids leave a
//! tombstone so replays are distinguishable from unknown ids; tombstones
//! outlive their entry by one TTL window, then age out (memory bound:
//! one small struct per approval, pruned lazily).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::ProtocolError;
use super::message::{ApprovalRequest, ApprovalResponse, ExecuteRequest};
use crate::crypto::canonical_json::to_canonical_string;

/// Spec: at most 5 minutes between approval and execution.
pub const DEFAULT_APPROVAL_TTL: Duration = Duration::from_secs(300);

#[derive(Debug)]
struct Entry {
    approved_json: String,
    approved_at: Instant,
}

#[derive(Debug)]
pub struct ApprovedRequestTracker {
    ttl: Duration,
    pending: HashMap<String, Entry>,
    consumed: HashMap<String, Instant>,
}

impl Default for ApprovedRequestTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ApprovedRequestTracker {
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_APPROVAL_TTL)
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            pending: HashMap::new(),
            consumed: HashMap::new(),
        }
    }

    /// Record an approval for later execution. The canonical JSON of the
    /// request is frozen HERE -- later mutation of any caller-held copy
    /// cannot affect what execute is compared against.
    ///
    /// The caller is responsible for having verified `response`'s
    /// signature before calling this; this type checks consistency
    /// (response answers request), not authenticity.
    pub fn record_approval(
        &mut self,
        request: &ApprovalRequest,
        response: &ApprovalResponse,
    ) -> Result<(), ProtocolError> {
        if request.req_id != response.req_id {
            return Err(ProtocolError::ApprovalMismatch {
                cause: super::MismatchCause::PayloadDiffers,
            });
        }
        // Re-approval of a still-pending id replaces the old approval
        // (fresh timestamps, fresh user intent). Tombstone state is only
        // relevant after consumption.
        let json = to_canonical_string(request)?;
        let id = request.req_id.hex();
        self.pending.insert(
            id,
            Entry {
                approved_json: json,
                approved_at: Instant::now(),
            },
        );
        Ok(())
    }

    /// Validate an incoming ExecuteRequest against its recorded approval.
    /// On success the approval is consumed: the same req_id can never be
    /// executed again without fresh approval.
    pub fn validate_execute(&mut self, exec: &ExecuteRequest) -> Result<(), ProtocolError> {
        let id = exec.req_id.hex();
        self.prune();

        // Replay tombstones outrank everything else: an id we consumed is
        // definitionally a replay attempt, even though a same-shaped
        // unknown id would read as "never seen".
        if self
            .consumed
            .get(&id)
            .is_some_and(|consumed_at| consumed_at.elapsed() <= self.ttl * 2)
        {
            return Err(ProtocolError::ApprovalMismatch {
                cause: super::MismatchCause::ReplayedReqId,
            });
        }

        match self.pending.remove(&id) {
            None => Err(ProtocolError::ApprovalMismatch {
                cause: super::MismatchCause::UnknownReqId,
            }),
            Some(entry) => {
                if entry.approved_at.elapsed() > self.ttl {
                    return Err(ProtocolError::ApprovalMismatch {
                        cause: super::MismatchCause::ExpiredReqId,
                    });
                }

                let exec_json = to_canonical_string(exec)?;
                if exec_json == entry.approved_json {
                    self.consumed.insert(id, Instant::now());
                    Ok(())
                } else {
                    // Payload differs from what was approved: the stored
                    // approval is now ambiguous evidence. Consume it too --
                    // forcing re-approval is always the safe direction.
                    self.consumed.insert(id, Instant::now());
                    Err(ProtocolError::ApprovalMismatch {
                        cause: super::MismatchCause::PayloadDiffers,
                    })
                }
            }
        }
    }

    /// Drop tombstones older than twice the TTL (long enough that any
    /// legitimate retry conversation has long since resolved loudly).
    fn prune(&mut self) {
        self.consumed
            .retain(|_, consumed_at| consumed_at.elapsed() <= self.ttl * 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sign::IdentitySecretKey;
    use crate::crypto::test_support::CounterEntropy;
    use crate::wire::message::{Decision, OpType};

    fn key() -> IdentitySecretKey {
        IdentitySecretKey::generate(&CounterEntropy).unwrap()
    }

    fn request(id_seed: u8, endpoint: &str, params: serde_json::Value) -> ApprovalRequest {
        ApprovalRequest::new(
            crate::wire::message::ReqId([id_seed; 16]),
            OpType::AuthenticatedRequest,
            "github".into(),
            "POST".into(),
            endpoint.into(),
            params,
            Some("claude-code".into()),
            1_700_000_000,
        )
        .unwrap()
    }

    fn matching_execute(req: &ApprovalRequest) -> ExecuteRequest {
        ExecuteRequest::new(
            req.req_id,
            req.op_type,
            req.service.clone(),
            req.method.clone(),
            req.endpoint.clone(),
            req.params.clone(),
            req.requested_by.clone(),
            req.timestamp,
        )
        .unwrap()
    }

    #[test]
    fn happy_path_approve_then_execute_consumes() {
        let mut tracker = ApprovedRequestTracker::new();
        let req = request(1, "/v1/deploy", serde_json::json!({"env": "prod"}));
        let resp =
            ApprovalResponse::approved_or_denied(req.req_id, Decision::Approved, None, &key());

        tracker.record_approval(&req, &resp).unwrap();
        assert!(tracker.validate_execute(&matching_execute(&req)).is_ok());

        // Consumed: identical replay is now a loud failure...
        match tracker.validate_execute(&matching_execute(&req)) {
            Err(ProtocolError::ApprovalMismatch {
                cause: super::super::MismatchCause::ReplayedReqId,
            }) => {}
            other => panic!("expected ReplayedReqId, got {other:?}"),
        }
    }

    #[test]
    fn every_field_mismatch_is_detected_individually() {
        type Mutation = Box<dyn Fn(&mut ApprovalRequest)>;
        // One mutation per field; each must fail with PayloadDiffers.
        let cases: Vec<Mutation> = vec![
            Box::new(|r: &mut ApprovalRequest| r.op_type = OpType::SessionEnd),
            Box::new(|r| r.service = "aws".into()),
            Box::new(|r| r.method = "DELETE".into()),
            Box::new(|r| r.endpoint = "/v1/other".into()),
            Box::new(|r| r.params = serde_json::json!({"env": "staging"})),
            Box::new(|r| r.requested_by = Some("someone-else".into())),
            Box::new(|r| r.requested_by = None),
            Box::new(|r| r.timestamp += 1),
        ];

        for (i, mutate) in cases.iter().enumerate() {
            let mut tracker = ApprovedRequestTracker::new();
            let mut approved = request(
                (i + 10) as u8,
                "/v1/deploy",
                serde_json::json!({"env": "prod"}),
            );
            let resp = ApprovalResponse::approved_or_denied(
                approved.req_id,
                Decision::Approved,
                None,
                &key(),
            );
            tracker.record_approval(&approved, &resp).unwrap();

            mutate(&mut approved);
            let exec = matching_execute(&approved);
            match tracker.validate_execute(&exec) {
                Err(ProtocolError::ApprovalMismatch {
                    cause: super::super::MismatchCause::PayloadDiffers,
                }) => {}
                other => panic!("case {i}: expected PayloadDiffers, got {other:?}"),
            }
        }
    }

    #[test]
    fn unknown_req_id_is_distinct_from_replay() {
        let mut tracker = ApprovedRequestTracker::new();
        let never_seen = request(50, "/x", serde_json::json!({}));
        match tracker.validate_execute(&matching_execute(&never_seen)) {
            Err(ProtocolError::ApprovalMismatch {
                cause: super::super::MismatchCause::UnknownReqId,
            }) => {}
            other => panic!("expected UnknownReqId, got {other:?}"),
        }
    }

    #[test]
    fn expired_approval_is_rejected_as_expired() {
        let mut tracker = ApprovedRequestTracker::with_ttl(std::time::Duration::from_millis(20));
        let req = request(60, "/x", serde_json::json!({}));
        let resp =
            ApprovalResponse::approved_or_denied(req.req_id, Decision::Approved, None, &key());
        tracker.record_approval(&req, &resp).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(40));

        match tracker.validate_execute(&matching_execute(&req)) {
            Err(ProtocolError::ApprovalMismatch {
                cause: super::super::MismatchCause::ExpiredReqId,
            }) => {}
            other => panic!("expected ExpiredReqId, got {other:?}"),
        }

        // And expiry consumes too: no zombie approval remains to replay.
        match tracker.validate_execute(&matching_execute(&req)) {
            Err(ProtocolError::ApprovalMismatch {
                cause:
                    super::super::MismatchCause::ReplayedReqId
                    | super::super::MismatchCause::UnknownReqId,
            }) => {}
            other => panic!("post-expiry attempt must not resurrect approval, got {other:?}"),
        }
    }

    #[test]
    fn payload_mismatch_also_consumes_the_approval() {
        let mut tracker = ApprovedRequestTracker::new();
        let honest = request(70, "/v1/a", serde_json::json!({"n": 1}));
        let resp =
            ApprovalResponse::approved_or_denied(honest.req_id, Decision::Approved, None, &key());
        tracker.record_approval(&honest, &resp).unwrap();

        // Attacker substitutes different fields.
        let mut forged = honest.clone();
        forged.endpoint = "/v1/admin".into();
        let exec = matching_execute(&forged);
        assert!(matches!(
            tracker.validate_execute(&exec),
            Err(ProtocolError::ApprovalMismatch {
                cause: super::super::MismatchCause::PayloadDiffers
            })
        ));

        // Now even the HONEST payload is dead: after a substitution
        // attempt, ambiguity is resolved in favor of re-approval.
        assert!(matches!(
            tracker.validate_execute(&matching_execute(&honest)),
            Err(ProtocolError::ApprovalMismatch {
                cause: super::super::MismatchCause::ReplayedReqId
            })
        ));
    }

    #[test]
    fn re_approval_of_same_id_replaces_pending_approval() {
        let mut tracker = ApprovedRequestTracker::new();
        let first = request(80, "/v1/one", serde_json::json!({}));
        let resp1 =
            ApprovalResponse::approved_or_denied(first.req_id, Decision::Approved, None, &key());
        tracker.record_approval(&first, &resp1).unwrap();

        // Same phone, same id? No: new approval means NEW req_id in real
        // flows. But a duplicate record (retry path) must replace cleanly
        // rather than erroring.
        let resp_dup =
            ApprovalResponse::approved_or_denied(first.req_id, Decision::Denied, None, &key());
        tracker.record_approval(&first, &resp_dup).unwrap();
        // Latest wins; execution validates against latest regardless of
        // decision content here (decisions gate execution upstream).
        assert!(tracker.validate_execute(&matching_execute(&first)).is_ok());
    }

    #[test]
    fn response_for_wrong_request_id_is_caught_at_record_time() {
        let mut tracker = ApprovedRequestTracker::new();
        let req = request(90, "/x", serde_json::json!({}));
        let other_id_req = request(91, "/x", serde_json::json!({}));
        let resp = ApprovalResponse::approved_or_denied(
            other_id_req.req_id,
            Decision::Approved,
            None,
            &key(),
        );
        assert!(matches!(
            tracker.record_approval(&req, &resp),
            Err(ProtocolError::ApprovalMismatch {
                cause: super::super::MismatchCause::PayloadDiffers
            })
        ));
    }
}
