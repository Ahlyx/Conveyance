use crate::ProtocolError;
use crate::message::{
    MAX_WIRE_MESSAGE_BYTES, Ping, ReqId, WireMessage, decode, decode_approval_request, encode,
};
use ciborium::value::Value;

fn raw_map(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut bytes).unwrap();
    bytes
}

fn request_fields(params: Value, op_type: &str) -> Vec<(Value, Value)> {
    use Value as V;
    vec![
        (V::Text("type".into()), V::Text("approval_request".into())),
        (V::Text("req_id".into()), V::Bytes(vec![9; 16])),
        (V::Text("op_type".into()), V::Text(op_type.into())),
        (V::Text("service".into()), V::Text("svc".into())),
        (V::Text("method".into()), V::Text("POST".into())),
        (V::Text("endpoint".into()), V::Text("/v1".into())),
        (V::Text("params".into()), params),
        (V::Text("timestamp".into()), V::Integer(1.into())),
    ]
}

#[test]
fn rejects_oversize_before_parse() {
    assert!(matches!(
        decode(&vec![0; MAX_WIRE_MESSAGE_BYTES + 1]),
        Err(ProtocolError::MessageTooLarge)
    ));
}

#[test]
fn rejects_trailing_cbor_value() {
    let mut bytes = encode(&WireMessage::Ping(Ping {
        req_id: ReqId([1; 16]),
        timestamp: 1,
    }))
    .unwrap();
    bytes.push(0);
    assert!(matches!(decode(&bytes), Err(ProtocolError::TrailingData)));
}

#[test]
fn rejects_duplicate_fields_and_nested_param_keys() {
    use Value as V;
    let mut duplicate_field = request_fields(V::Map(vec![]), "authenticated_request");
    duplicate_field.push((V::Text("service".into()), V::Text("other".into())));
    assert!(matches!(
        decode(&raw_map(duplicate_field)),
        Err(ProtocolError::InvalidMap)
    ));

    let nested = V::Map(vec![
        (V::Text("x".into()), V::Integer(1.into())),
        (V::Text("x".into()), V::Integer(2.into())),
    ]);
    let params = V::Map(vec![(V::Text("nested".into()), nested)]);
    assert!(matches!(
        decode(&raw_map(request_fields(params, "authenticated_request"))),
        Err(ProtocolError::InvalidMap)
    ));
}

#[test]
fn wire_decode_reapplies_constructor_float_validation() {
    use Value as V;
    let params = V::Map(vec![(V::Text("n".into()), V::Float(1.5))]);
    assert!(matches!(
        decode(&raw_map(request_fields(params, "authenticated_request"))),
        Err(ProtocolError::UnsupportedValueType { field: "params" })
    ));
}

#[test]
fn rejects_binary_params_and_non_text_map_keys() {
    use Value as V;
    let binary_params = V::Map(vec![(V::Text("blob".into()), V::Bytes(vec![1, 2, 3]))]);
    assert!(
        decode(&raw_map(request_fields(
            binary_params,
            "authenticated_request"
        )))
        .is_err()
    );

    let mut entries = request_fields(V::Map(vec![]), "authenticated_request");
    entries[6] = (
        V::Text("params".into()),
        V::Map(vec![(V::Integer(1.into()), V::Bool(true))]),
    );
    assert!(matches!(
        decode(&raw_map(entries)),
        Err(ProtocolError::InvalidMap)
    ));
}

#[test]
fn rejects_excessive_nesting_before_serde_deserialization() {
    let mut bytes = vec![0x81; crate::message::MAX_CBOR_NESTING_DEPTH + 2];
    bytes.push(0);
    assert!(matches!(decode(&bytes), Err(ProtocolError::NestingTooDeep)));
}

#[test]
fn approval_decoder_rejects_other_op_types_and_message_kinds() {
    use Value as V;
    let bytes = raw_map(request_fields(V::Map(vec![]), "list_services"));
    assert!(matches!(
        decode_approval_request(&bytes),
        Err(ProtocolError::UnsupportedApprovalOperation)
    ));

    let ping = encode(&WireMessage::Ping(Ping {
        req_id: ReqId([2; 16]),
        timestamp: 1,
    }))
    .unwrap();
    assert!(matches!(
        decode_approval_request(&ping),
        Err(ProtocolError::UnexpectedMessageType)
    ));
}

#[test]
fn unknown_enum_value_fails_closed() {
    use Value as V;
    let mut entries = request_fields(V::Map(vec![]), "future_operation");
    entries.retain(|(key, _)| key != &V::Text("op_type".into()));
    entries.insert(
        2,
        (
            V::Text("op_type".into()),
            V::Text("future_operation".into()),
        ),
    );
    assert!(matches!(
        decode(&raw_map(entries)),
        Err(ProtocolError::UnknownEnumValue)
    ));
}
