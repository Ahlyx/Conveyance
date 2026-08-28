//! The `context || canonical_json(body)` signing-payload construction.
//!
//! Delegates verbatim to [`conveyance_crypto::signing::signing_payload`],
//! whose docs explain why this join is a primitive rather than a
//! hand-written concatenation on each side. The phone builds `body` (its
//! message serialized, `signature` field removed, canonicalized) and then
//! signs `signing_payload(context, body)`; the PC verifies over the same
//! bytes. A fixture pins the exact concatenation so a stray separator or
//! encoding slip on the Kotlin side fails in CI, not in production.

/// `context || canonical_body`, as raw bytes — plain concatenation, no
/// separator. `context` is the domain tag (e.g. `b"conveyance-approve-v1"`);
/// `canonical_body` is already-canonicalized JSON text.
#[uniffi::export]
pub fn signing_payload(context: Vec<u8>, canonical_body: String) -> Vec<u8> {
    conveyance_crypto::signing::signing_payload(&context, &canonical_body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_context_then_body_verbatim() {
        let got = signing_payload(
            b"conveyance-approve-v1".to_vec(),
            r#"{"decision":"approved","req_id":"00"}"#.to_string(),
        );
        assert_eq!(
            got,
            b"conveyance-approve-v1{\"decision\":\"approved\",\"req_id\":\"00\"}".to_vec()
        );
    }

    #[test]
    fn empty_inputs() {
        assert_eq!(signing_payload(vec![], String::new()), Vec::<u8>::new());
    }
}
