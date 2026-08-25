//! RFC 8785 (JSON Canonicalization Scheme) serialization, Conveyance
//! domain-restricted.
//!
//! Why hand-written when `serde_jcs` exists: JCS requires object keys
//! sorted by UTF-16 code units (§3.2.3), and `serde_jcs` delegates key
//! iteration to `serde_json`'s map flavor -- which is a `BTreeMap`
//! ordered by UTF-8 bytes, i.e. Unicode code point order. Those two
//! orders disagree whenever one key contains an astral-plane character
//! and another contains U+E000..U+FFFF (the RFC's own example pairs 😀
//! with € precisely to catch this). Signatures over divergent orderings
//! do not verify across implementations; that failure mode is silent
//! until an unusual value shows up. This module therefore performs the
//! UTF-16 sort itself and does not trust any map's iteration order.
//!
//! Domain restriction (spec amendment): values may be integers, strings,
//! booleans, null, arrays, objects. Floats are REJECTED loudly rather
//! than formatted, because ECMAScript number formatting is a known
//! cross-implementation trap and nothing in Conveyance's hashed content
//! legitimately carries fractional values. One deliberate divergence
//! from stock JCS falls out of this: integers beyond ±2^53 are emitted
//! exactly instead of degrading to doubles. The Android side MUST apply
//! the same rules; see CONVEYANCE_SPEC.md "Cryptographic primitives".

use serde_json::Value;

use super::CryptoError;

/// Serialize a JSON value to its canonical form under the Conveyance
/// domain. Floats fail with [`CryptoError::OutsideCanonicalDomain`].
pub fn canonicalize(value: &Value) -> Result<String, CryptoError> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

fn write_value(value: &Value, out: &mut String) -> Result<(), CryptoError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // §3.2.3: sort by UTF-16 code units. encode_utf16 is the only
            // correct comparator; neither Rust's str Ord nor char order
            // matches it for astral keys.
            let mut keys: Vec<&str> = map.keys().map(|k| k.as_str()).collect();
            keys.sort_by_key(|k| k.encode_utf16().collect::<Vec<u16>>());
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(&map[*key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_number(n: &serde_json::Number, out: &mut String) -> Result<(), CryptoError> {
    // Only integer-backed numbers are in-domain; serde_json stores those
    // as u64/i64 and everything else as f64.
    if let Some(u) = n.as_u64() {
        out.push_str(&u.to_string());
    } else if let Some(i) = n.as_i64() {
        out.push_str(&i.to_string());
    } else {
        return Err(CryptoError::OutsideCanonicalDomain);
    }
    Ok(())
}

/// String escaping per §3.2.2.2 (= ECMAScript `JSON.stringify`): the two
/// mandatory quotes/backslash escapes, the five short control escapes,
/// lowercase-hex `\u00xx` for remaining controls, everything else raw.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0A}' => out.push_str("\\n"),
            '\u{0C}' => out.push_str("\\f"),
            '\u{0D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The string/literal half of the composite example from RFC 8785:
    /// control-character escaping (short forms + lowercase hex), quote
    /// and backslash escaping, unescaped solidus, literal ordering, and
    /// key re-sorting all at once. (The numbers from the same RFC example
    /// are covered by `float_inputs_are_rejected_loudly` -- they are all
    /// outside the Conveyance domain by design.)
    #[test]
    fn rfc8785_strings_literals_and_key_order() {
        let input: Value = serde_json::from_str(
            r#"{
              "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"/",
              "literals": [null, true, false]
            }"#,
        )
        .unwrap();

        let expected = "{\"literals\":[null,true,false],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}";

        let actual = canonicalize(&input).expect("inside the domain");
        assert_eq!(actual, expected);
    }

    /// The property-ordering example from RFC 8785 §3.2.3. Sorting MUST
    /// be by UTF-16 code units -- which differs from code-point order
    /// exactly where this test probes it. See the order notes inline.
    #[test]
    fn rfc8785_property_ordering_is_utf16() {
        // U+0080 is a C1 control but NOT escaped by JCS (only < 0x20 is);
        // the Hebrew letter is the precomposed U+FB33, matching the input.
        // Order notes: euro (single unit 0x20AC) precedes the emoji (high
        // surrogate 0xD83D), and U+10000 ([D800,DC00]) precedes BOTH --
        // its high surrogate 0xD800 is smaller still -- while code-point
        // order would place it after every BMP character. That pair is
        // the true UTF-16 discriminator; the rest just pins escaping.
        let input = json!({
            "\u{20ac}": "Euro Sign",
            "\r": "Carriage Return",
            "\u{fb33}": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "\u{1f600}": "Emoji: Grinning Face",
            "\u{0080}": "Control",
            "\u{f6}": "Latin Small Letter O With Diaeresis",
            "\u{e000}": "Private Use",
            "\u{10000}": "Lineare B Syllable",
        });

        let expected = concat!(
            "{\"\\r\":\"Carriage Return\",",
            "\"1\":\"One\",",
            "\"\u{0080}\":\"Control\",",
            "\"ö\":\"Latin Small Letter O With Diaeresis\",",
            "\"€\":\"Euro Sign\",",
            "\"\u{10000}\":\"Lineare B Syllable\",",
            "\"😀\":\"Emoji: Grinning Face\",",
            "\"\u{e000}\":\"Private Use\",",
            "\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}",
        );

        let actual = canonicalize(&input).expect("inside the domain");
        assert_eq!(actual, expected);
    }

    /// Every float shape the RFC exercises is rejected rather than
    /// formatted: decimals, exponents, integral-valued floats parsed
    /// from decimal notation, negatives, subnormals. See module docs for
    /// why rejection beats formatting here.
    #[test]
    fn float_inputs_are_rejected_loudly() {
        for text in [
            "333333333.33333329",
            "1E30",
            "4.50",
            "2e-3",
            "0.000000000000000000000000001",
            "-0.5",
            "3.0",
        ] {
            let v: Value = serde_json::from_str(text).unwrap();
            assert!(
                matches!(canonicalize(&v), Err(CryptoError::OutsideCanonicalDomain)),
                "{text} should be outside the domain"
            );
        }
    }

    /// All five short control escapes plus the generic \\u00xx form for
    /// controls without one. \r and \n are covered by the ordering
    /// vector; these arms would otherwise sit unexercised.
    #[test]
    fn control_escape_forms() {
        assert_eq!(
            canonicalize(&json!("\u{08}\u{09}\u{0C}")).unwrap(),
            r#""\b\t\f""#
        );
        assert_eq!(canonicalize(&json!("\u{01}")).unwrap(), "\"\\u0001\"");
        assert_eq!(canonicalize(&json!("\u{1f}")).unwrap(), "\"\\u001f\"");
    }

    /// Byte-stability: canonicalizing twice, and canonicalizing a value
    /// rebuilt from its own parsed output, changes nothing. This is the
    /// property signatures actually depend on.
    #[test]
    fn canonicalization_is_idempotent_and_parse_stable() {
        let input = json!({
            "zeta": 1,
            "alpha": {"nested": [true, null, "x"], "b": -12},
            "unicode": "é😀",
        });
        let once = canonicalize(&input).unwrap();
        let reparsed: Value = serde_json::from_str(&once).unwrap();
        let twice = canonicalize(&reparsed).unwrap();
        assert_eq!(once, twice);
    }

    /// Integers round-trip exactly across the whole i64/u64 span --
    /// including beyond ±2^53, where stock JCS would degrade through
    /// double formatting. Exactness here is our documented divergence;
    /// Android must emit longs exactly too.
    #[test]
    fn integer_domain_round_trips_exactly() {
        for v in [
            json!(0),
            json!(-1),
            json!(1700000000i64),
            json!(9007199254740991i64),
            json!(-9007199254740991i64),
            json!(i64::MAX),
            json!(i64::MIN),
            json!(18446744073709551615u64),
        ] {
            let out = canonicalize(&v).expect("integers are in-domain");
            assert_eq!(out, v.to_string(), "exact digit-for-digit emission");
            assert_eq!(serde_json::from_str::<Value>(&out).unwrap(), v);
        }
    }

    /// Deep nesting must not reorder sibling arrays' contents or lose
    /// empty containers.
    #[test]
    fn nested_structures_survive() {
        let input = json!({
            "b": [[], [1, [true]], {}],
            "a": {"z": [], "y": {"k": null}},
        });
        let expected = r#"{"a":{"y":{"k":null},"z":[]},"b":[[],[1,[true]],{}]}"#;
        assert_eq!(canonicalize(&input).unwrap(), expected);
    }
}
