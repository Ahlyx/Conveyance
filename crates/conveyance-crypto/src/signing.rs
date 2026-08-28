//! The signed-payload construction: `context || canonical_json(body)`.
//!
//! Several spec messages are Ed25519-signed not over their raw bytes but
//! over a domain-separated preimage: a fixed ASCII context string
//! concatenated with the RFC 8785 canonical JSON of the message with its
//! `signature` field removed. The spec spells three of these out
//! ("conveyance-approve-v1", "conveyance-execute-v1", and the phone log
//! row signature); more may follow.
//!
//! Why this lives here, as a primitive, rather than only inside
//! `conveyance-core::wire`: the Android side (via `conveyance-crypto-ffi`)
//! must build the *exact same bytes* before it signs, and a second
//! hand-written concatenation is precisely the kind of near-invisible
//! divergence — a stray separator, a newline, UTF-8 vs UTF-16 for the
//! context — that produces signatures which verify on neither side and
//! fail silently until an unusual message shows up. One definition, one
//! set of vectors, both sides call it.
//!
//! Scope: this function is only the final `context || body` join. Turning
//! a typed message into `body` — `serde_json` -> remove `signature` ->
//! [`canonical_json::canonicalize`] — stays with the caller that owns the
//! message type. The pairing payload (`"conveyance-pair-v1" || raw field
//! concatenation`, *not* canonical JSON) is a different construction and
//! is deliberately not modelled here; it belongs with pairing (phase
//! 10.5).

/// `context || canonical_body`, as raw bytes.
///
/// `context` is the domain-separation tag (e.g. `b"conveyance-approve-v1"`)
/// and `canonical_body` is already-canonicalised JSON text. The join is a
/// plain byte concatenation with no separator: `context` bytes verbatim,
/// then the UTF-8 bytes of `canonical_body`. This mirrors, byte for byte,
/// the inline concatenation in `conveyance-core::wire::message`
/// (asserted by a parity test there).
pub fn signing_payload(context: &[u8], canonical_body: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(context.len() + canonical_body.len());
    out.extend_from_slice(context);
    out.extend_from_slice(canonical_body.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concatenates_context_then_body_with_no_separator() {
        let got = signing_payload(b"conveyance-approve-v1", r#"{"req_id":"00"}"#);
        assert_eq!(got, b"conveyance-approve-v1{\"req_id\":\"00\"}");
    }

    #[test]
    fn empty_context_and_body_are_handled() {
        assert_eq!(signing_payload(b"", ""), Vec::<u8>::new());
        assert_eq!(signing_payload(b"", "x"), b"x");
        assert_eq!(signing_payload(b"ctx", ""), b"ctx");
    }

    /// The body is joined as UTF-8; a multi-byte character in the
    /// canonical JSON must not be re-encoded or escaped by this step.
    #[test]
    fn body_is_joined_as_utf8_bytes() {
        let got = signing_payload(b"c", "\"€\"");
        let mut want = b"c\"".to_vec();
        want.extend_from_slice("€".as_bytes());
        want.push(b'"');
        assert_eq!(got, want);
    }
}
