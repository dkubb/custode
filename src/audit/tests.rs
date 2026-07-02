use super::{AuditDecision, AuditEvent, AuditEventInput, AuditTarget, RequestId};
use core::time::Duration;
use std::time::UNIX_EPOCH;

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

#[test]
fn timestamp_formatting_matches_known_boundary_instants() {
    let vectors = [
        (0, 0, "1970-01-01T00:00:00.000000000Z"),
        (1, 5, "1970-01-01T00:00:01.000000005Z"),
        (86_399, 0, "1970-01-01T23:59:59.000000000Z"),
        (951_782_400, 0, "2000-02-29T00:00:00.000000000Z"),
        (1_709_164_800, 0, "2024-02-29T00:00:00.000000000Z"),
        (0x7FFF_FFFF, 0, "2038-01-19T03:14:07.000000000Z"),
        (4_102_444_800, 0, "2100-01-01T00:00:00.000000000Z"),
    ];

    for (seconds, nanoseconds, expected) in vectors {
        let instant = UNIX_EPOCH
            .checked_add(Duration::new(seconds, nanoseconds))
            .expect("test instants fit in SystemTime");
        assert_eq!(
            humantime::format_rfc3339_nanos(instant).to_string(),
            expected
        );
    }
}
