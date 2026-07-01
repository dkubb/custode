use super::{AuditDecision, AuditEvent, AuditEventInput, AuditTarget, RequestId};

#[test]
fn new_preserves_status() {
    let target = AuditTarget::from_uri_parts("/v1/models", None);
    let input = AuditEventInput {
        request_id: RequestId::from_sequence(1),
        decision: AuditDecision::Denied,
        method: "CONNECT".to_owned(),
        target,
        upstream_origin: "https://api.openai.com".to_owned(),
        upstream_path: None,
        upstream_query: None,
        status: Some(405),
        request_bytes: 0,
        response_bytes: 0,
        request_body_blake3: None,
        response_body_blake3: None,
        error_class: Some("connect_unsupported".to_owned()),
    };

    let event = AuditEvent::new(input);
    let expected = Some(405);

    assert_eq!(event.status, expected);
}

#[test]
fn new_preserves_rejected_raw_path() {
    let target = AuditTarget::from_uri_parts("/v1/responses/%2e%2e/models", Some("limit=1"));
    let input = AuditEventInput {
        request_id: RequestId::from_sequence(1),
        decision: AuditDecision::Denied,
        method: "GET".to_owned(),
        target,
        upstream_origin: "https://api.openai.com".to_owned(),
        upstream_path: None,
        upstream_query: None,
        status: Some(400),
        request_bytes: 0,
        response_bytes: 0,
        request_body_blake3: None,
        response_body_blake3: None,
        error_class: Some("dot_segment".to_owned()),
    };

    let event = AuditEvent::new(input);

    assert_eq!(event.path, "/v1/responses/%2e%2e/models");
    assert_eq!(event.query.as_deref(), Some("limit=1"));
}
