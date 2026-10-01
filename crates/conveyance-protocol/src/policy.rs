//! Phone-side approval tier policy.
//!
//! The daemon supplies requests, never the phone's required tier. This
//! module owns the built-in escalation rules and parses only phone-owned
//! `policy.toml` rules. A configured rule can raise the default Tier 2
//! requirement to Tier 3; it cannot lower the per-operation approval floor.

use serde::Deserialize;

use crate::message::ApprovalRequest;

pub const DESTINATION_HISTORY_LIMIT: usize = 30;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighRiskRule {
    pub match_service: Option<String>,
    pub match_method: Option<String>,
    pub match_endpoint: Option<String>,
    pub required_tier: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneApprovalPolicy {
    #[serde(default)]
    pub high_risk: Vec<HighRiskRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedDestination {
    pub service: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier3Reason {
    DeleteMethod,
    NovelDestination,
    ConfiguredRule,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalTierDecision {
    /// Tier 2 is the floor for each incoming authenticated request. Tier 3
    /// requires fresh authentication using the selected Tier 1 method.
    pub tier: u8,
    pub reasons: Vec<Tier3Reason>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid phone approval policy TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid high-risk policy rule")]
    InvalidRule,
}

impl PhoneApprovalPolicy {
    /// Parse a private phone policy snapshot. An empty file means built-in
    /// rules only; unknown keys and malformed rules fail closed.
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        let policy: Self = toml::from_str(text)?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        for rule in &self.high_risk {
            if !(1..=3).contains(&rule.required_tier)
                || (rule.match_service.is_none()
                    && rule.match_method.is_none()
                    && rule.match_endpoint.is_none())
            {
                return Err(PolicyError::InvalidRule);
            }
        }
        Ok(())
    }

    /// Apply built-in and phone-owned rules using exact protocol strings.
    /// `recent_approvals` must contain successful approvals newest first;
    /// only its first 30 rows participate in novelty classification.
    pub fn evaluate(
        &self,
        request: &ApprovalRequest,
        recent_approvals: &[ApprovedDestination],
    ) -> ApprovalTierDecision {
        let mut reasons = Vec::new();
        if request.method == "DELETE" {
            reasons.push(Tier3Reason::DeleteMethod);
        }

        let seen = recent_approvals
            .iter()
            .take(DESTINATION_HISTORY_LIMIT)
            .any(|entry| entry.service == request.service && entry.endpoint == request.endpoint);
        if !seen {
            reasons.push(Tier3Reason::NovelDestination);
        }

        if self
            .high_risk
            .iter()
            .any(|rule| rule.matches(request) && rule.required_tier == 3)
        {
            reasons.push(Tier3Reason::ConfiguredRule);
        }

        ApprovalTierDecision {
            tier: if reasons.is_empty() { 2 } else { 3 },
            reasons,
        }
    }
}

impl HighRiskRule {
    fn matches(&self, request: &ApprovalRequest) -> bool {
        self.match_service
            .as_deref()
            .is_none_or(|pattern| glob_matches(pattern, &request.service))
            && self
                .match_method
                .as_deref()
                .is_none_or(|pattern| glob_matches(pattern, &request.method))
            && self
                .match_endpoint
                .as_deref()
                .is_none_or(|pattern| glob_matches(pattern, &request.endpoint))
    }
}

/// Case-sensitive glob with `*` matching any sequence, including empty.
/// Every other Unicode scalar must match exactly. Linear backtracking keeps
/// locally configured patterns safe without regex compilation.
fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let (mut p, mut v) = (0, 0);
    let (mut star, mut retry) = (None, 0);

    while v < value.len() {
        if p < pattern.len() && (pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if let Some(star_at) = star {
            retry += 1;
            v = retry;
            p = star_at + 1;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{OpType, ReqId};

    fn request(service: &str, method: &str, endpoint: &str) -> ApprovalRequest {
        ApprovalRequest::new(
            ReqId([0x51; 16]),
            OpType::AuthenticatedRequest,
            service.into(),
            method.into(),
            endpoint.into(),
            serde_json::json!({"x":1}),
            None,
            1_700_000_000,
        )
        .unwrap()
    }

    fn dest(service: &str, endpoint: &str) -> ApprovedDestination {
        ApprovedDestination {
            service: service.into(),
            endpoint: endpoint.into(),
        }
    }

    #[test]
    fn policy_toml_is_strict_and_empty_policy_is_valid() {
        assert_eq!(
            PhoneApprovalPolicy::parse("").unwrap(),
            PhoneApprovalPolicy::default()
        );
        assert!(PhoneApprovalPolicy::parse("[[high_risk]]\nrequired_tier=3").is_err());
        assert!(
            PhoneApprovalPolicy::parse("[[high_risk]]\nmatch_service='aws'\nrequired_tier=4")
                .is_err()
        );
        assert!(PhoneApprovalPolicy::parse("unexpected=true").is_err());
    }

    #[test]
    fn delete_and_unseen_exact_destination_require_tier_three() {
        let policy = PhoneApprovalPolicy::default();
        let ordinary = request("svc", "GET", "/known");
        let history = [dest("svc", "/known")];
        assert_eq!(policy.evaluate(&ordinary, &history).tier, 2);
        assert_eq!(
            policy
                .evaluate(&request("svc", "DELETE", "/known"), &history)
                .tier,
            3
        );
        assert_eq!(
            policy
                .evaluate(&request("svc", "GET", "/new"), &history)
                .tier,
            3
        );
    }

    #[test]
    fn destination_pair_is_exact_and_history_uses_only_30_recent_grants() {
        let policy = PhoneApprovalPolicy::default();
        let req = request("svc", "GET", "/same/");
        assert_eq!(policy.evaluate(&req, &[dest("svc", "/same")]).tier, 3);
        assert_eq!(policy.evaluate(&req, &[dest("other", "/same/")]).tier, 3);

        let mut older_match = vec![dest("other", "/x"); DESTINATION_HISTORY_LIMIT];
        older_match.push(dest("svc", "/same/"));
        assert_eq!(policy.evaluate(&req, &older_match).tier, 3);
        assert_eq!(policy.evaluate(&req, &[dest("svc", "/same/")]).tier, 2);
    }

    #[test]
    fn configured_matchers_are_case_sensitive_and_combine_with_and() {
        let policy = PhoneApprovalPolicy::parse(
            "[[high_risk]]\nmatch_service='aws'\nmatch_endpoint='*prod*'\nrequired_tier=3",
        )
        .unwrap();
        let known = [dest("aws", "/v1/prod")];
        assert_eq!(
            policy
                .evaluate(&request("aws", "POST", "/v1/prod"), &known)
                .tier,
            3
        );
        assert_eq!(
            policy
                .evaluate(
                    &request("AWS", "POST", "/v1/prod"),
                    &[dest("AWS", "/v1/prod")],
                )
                .tier,
            2
        );
        assert_eq!(
            policy
                .evaluate(
                    &request("aws", "POST", "/v1/Prod"),
                    &[dest("aws", "/v1/Prod")],
                )
                .tier,
            2
        );
    }

    #[test]
    fn configured_lower_tiers_never_lower_the_per_operation_floor() {
        let policy =
            PhoneApprovalPolicy::parse("[[high_risk]]\nmatch_method='GET'\nrequired_tier=1")
                .unwrap();
        let history = [dest("svc", "/known")];
        assert_eq!(
            policy
                .evaluate(&request("svc", "GET", "/known"), &history)
                .tier,
            2
        );
    }
}
