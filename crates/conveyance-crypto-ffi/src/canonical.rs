//! RFC 8785 canonical JSON, Conveyance domain-restricted.
//!
//! Input crosses the boundary as a JSON **string**. This bridge parses it
//! with `serde_json::from_str` and then canonicalizes — the same
//! parse-then-canonicalize path the PC side takes when it canonicalizes a
//! value it decoded rather than one it built from a typed struct. Number
//! handling therefore matches: `serde_json` without `arbitrary_precision`
//! stores integers as i64/u64 and everything else as f64, and
//! `conveyance_crypto`'s canonicalizer rejects the f64 case
//! ([`CryptoFfiError::OutsideCanonicalDomain`]) — so a float literal, or
//! an integer past ±u64, fails identically on both sides.
//!
//! Unparseable input is [`CryptoFfiError::InvalidJson`], distinct from a
//! well-formed value that carries a float.

use crate::{CryptoFfiError, map_core_err};

/// Canonicalize a JSON document to its RFC 8785 form under the Conveyance
/// domain (integers, strings, booleans, null, arrays, objects). Floats and
/// out-of-range integers are rejected, not formatted.
#[uniffi::export]
pub fn canonical_json(json_text: String) -> Result<String, CryptoFfiError> {
    let value: serde_json::Value =
        serde_json::from_str(&json_text).map_err(|_| CryptoFfiError::InvalidJson)?;
    conveyance_crypto::canonical_json::canonicalize(&value).map_err(map_core_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_keys_and_strips_insignificant_whitespace() {
        let got = canonical_json(r#"{ "b": 1, "a": [ 3, 2 ] }"#.to_string()).unwrap();
        assert_eq!(got, r#"{"a":[3,2],"b":1}"#);
    }

    /// The spec's omission rule is the caller's job (build the object
    /// without the key); this only proves canonicalization treats an
    /// absent optional field and a present one as the distinct inputs
    /// they are — the property the ApprovalResponse fixture cross-checks.
    #[test]
    fn absent_vs_present_optional_field() {
        let without =
            canonical_json(r#"{"decision":"approved","req_id":"aa"}"#.to_string()).unwrap();
        let with = canonical_json(
            r#"{"decision":"approved","reason":"user_tap","req_id":"aa"}"#.to_string(),
        )
        .unwrap();
        assert_eq!(without, r#"{"decision":"approved","req_id":"aa"}"#);
        assert_eq!(
            with,
            r#"{"decision":"approved","reason":"user_tap","req_id":"aa"}"#
        );
    }

    #[test]
    fn large_integers_survive_exactly() {
        let got = canonical_json(r#"{"n":9007199254740993}"#.to_string()).unwrap();
        assert_eq!(got, r#"{"n":9007199254740993}"#);
    }

    #[test]
    fn floats_are_outside_the_domain() {
        assert!(matches!(
            canonical_json(r#"{"x":1.5}"#.to_string()),
            Err(CryptoFfiError::OutsideCanonicalDomain)
        ));
        // Integer past u64 degrades to f64 on parse, so it lands in the
        // same rejection — both sides agree.
        assert!(matches!(
            canonical_json(r#"{"x":99999999999999999999999}"#.to_string()),
            Err(CryptoFfiError::OutsideCanonicalDomain)
        ));
    }

    #[test]
    fn unparseable_input_is_invalid_json_not_domain() {
        assert!(matches!(
            canonical_json("{not json".to_string()),
            Err(CryptoFfiError::InvalidJson)
        ));
    }
}
