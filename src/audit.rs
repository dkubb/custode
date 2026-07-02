//! Audit event schema and writer.

use crate::allowlist::AcceptedTarget;
use crate::config::GatewayConfig;
use serde::Serialize;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use thiserror::Error;
use tokio::fs::{File, OpenOptions, create_dir_all};
use tokio::io::AsyncWriteExt as _;
use tokio::sync::Mutex;

/// Audit decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuditDecision {
    /// Request was allowed and completed normally.
    Allowed,

    /// Request was denied before upstream I/O.
    Denied,

    /// Response streaming failed.
    ResponseError,

    /// Upstream request failed before a response completed.
    UpstreamError,
}

/// Audit log error.
#[derive(Debug, Error)]
pub(crate) enum AuditError {
    /// Audit event exceeded configured maximum.
    #[error("audit event has {bytes} bytes, maximum is {max}")]
    EventTooLarge {
        /// Serialized event bytes.
        bytes: usize,
        /// Maximum allowed bytes.
        max: usize,
    },

    /// Audit log could not be opened.
    #[error("failed to open audit path {path}: {source}")]
    Open {
        /// Path that failed.
        path: PathBuf,
        /// I/O source error.
        source: io::Error,
    },

    /// Audit event could not be serialized.
    #[error("failed to serialize audit event: {0}")]
    Serialize(serde_json::Error),

    /// Audit log write failed.
    #[error("failed to write audit event: {0}")]
    Write(io::Error),
}

/// Structured audit event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct AuditEvent {
    /// Final audit decision.
    decision: AuditDecision,
    /// Stable error class for failed decisions.
    error_class: Option<String>,
    /// Request method.
    method: String,
    /// Accepted or synthetic request path.
    path: String,
    /// Request query string without `?`.
    query: Option<String>,
    /// Request body digest.
    request_body_blake3: Option<String>,
    /// Request body bytes.
    request_bytes: u64,
    /// Request identity.
    request_id: RequestId,
    /// Response body digest.
    response_body_blake3: Option<String>,
    /// Response body bytes.
    response_bytes: u64,
    /// Response status returned to the harness, when one exists.
    status: Option<u16>,
    /// RFC 3339 UTC timestamp.
    timestamp: String,
    /// Configured upstream origin.
    upstream_origin: String,
    /// Upstream path, when an upstream request was attempted.
    upstream_path: Option<String>,
    /// Upstream query, when an upstream request was attempted.
    upstream_query: Option<String>,
    /// Audit schema version.
    version: u8,
}

/// Input used to construct an audit event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuditEventInput {
    /// Audit decision.
    pub decision: AuditDecision,
    /// Error class, when one exists.
    pub error_class: Option<String>,
    /// Request method.
    pub method: String,
    /// Request body digest.
    pub request_body_blake3: Option<String>,
    /// Request body byte count.
    pub request_bytes: u64,
    /// Request identity.
    pub request_id: RequestId,
    /// Response body digest.
    pub response_body_blake3: Option<String>,
    /// Response body byte count.
    pub response_bytes: u64,
    /// Response status, when one exists.
    pub status: Option<u16>,
    /// Accepted or raw audit target.
    pub target: AuditTarget,
    /// Configured upstream origin.
    pub upstream_origin: String,
    /// Upstream path, when an upstream request was attempted.
    pub upstream_path: Option<String>,
    /// Upstream query, when an upstream request was attempted.
    pub upstream_query: Option<String>,
}

/// Request target recorded in the audit log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuditTarget {
    /// Request path.
    path: String,
    /// Request query string without `?`.
    query: Option<String>,
}

/// Newline-delimited JSON audit writer.
#[derive(Clone, Debug)]
pub(crate) struct AuditWriter {
    /// Audit log file guarded for append writes.
    file: Arc<Mutex<File>>,
    /// Maximum serialized event bytes.
    max_event_bytes: usize,
}

/// Request identity used in audit events.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct RequestId(String);

impl AuditTarget {
    /// Creates an audit target from raw request URI parts.
    #[must_use]
    pub(crate) fn from_uri_parts(path: &str, query: Option<&str>) -> Self {
        Self {
            path: if path.is_empty() {
                "/".to_owned()
            } else {
                path.to_owned()
            },
            query: query.map(str::to_owned),
        }
    }

    /// Returns the audited path.
    #[must_use]
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    /// Returns the audited query string.
    #[must_use]
    pub(crate) fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }
}

impl From<AcceptedTarget> for AuditTarget {
    fn from(target: AcceptedTarget) -> Self {
        Self {
            path: target.path().to_owned(),
            query: target.query().map(str::to_owned),
        }
    }
}

impl AuditEvent {
    /// Creates an audit event for a request decision.
    #[must_use]
    pub(crate) fn new(input: AuditEventInput) -> Self {
        Self {
            decision: input.decision,
            error_class: input.error_class,
            method: input.method,
            path: input.target.path().to_owned(),
            query: input.target.query().map(str::to_owned),
            request_body_blake3: input.request_body_blake3,
            request_bytes: input.request_bytes,
            request_id: input.request_id,
            response_body_blake3: input.response_body_blake3,
            response_bytes: input.response_bytes,
            status: input.status,
            timestamp: rfc3339_timestamp(),
            upstream_origin: input.upstream_origin,
            upstream_path: input.upstream_path,
            upstream_query: input.upstream_query,
            version: 1,
        }
    }
}

impl AuditWriter {
    /// Opens an audit writer in append mode.
    ///
    /// # Errors
    ///
    /// Returns an error when the audit log cannot be opened.
    pub(crate) async fn open(config: &GatewayConfig) -> Result<Self, AuditError> {
        let path = config.audit_log();
        if let Some(parent) = path.parent() {
            create_dir_all(parent)
                .await
                .map_err(|source| AuditError::Open {
                    path: parent.to_owned(),
                    source,
                })?;
        }
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .await
            .map_err(|source| AuditError::Open {
                path: path.to_owned(),
                source,
            })?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
            max_event_bytes: config.max_audit_event_bytes().get(),
        })
    }

    /// Writes one required audit event.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization or writing fails.
    pub(crate) async fn write_event(&self, event: &AuditEvent) -> Result<(), AuditError> {
        // `AuditEvent` is a plain struct of strings and integers, so
        // serialization cannot fail in practice; the `Serialize` arm exists
        // to keep the audit path fail-closed if the schema ever changes.
        let mut serialized = serde_json::to_vec(event).map_err(AuditError::Serialize)?;
        if serialized.len() > self.max_event_bytes {
            return Err(AuditError::EventTooLarge {
                bytes: serialized.len(),
                max: self.max_event_bytes,
            });
        }
        serialized.push(b'\n');

        let mut file = self.file.lock().await;
        file.write_all(&serialized)
            .await
            .map_err(AuditError::Write)?;
        file.flush().await.map_err(AuditError::Write)?;
        drop(file);
        Ok(())
    }
}

impl RequestId {
    /// Creates a request identity from a run token and sequence number.
    ///
    /// The run token keeps identities unique across gateway runs that append
    /// to the same audit log.
    #[must_use]
    pub(crate) fn from_parts(run_token: &str, sequence: u64) -> Self {
        Self(format!("req-{run_token}-{sequence:016x}"))
    }
}

/// Returns the current RFC 3339 UTC timestamp for audit events.
fn rfc3339_timestamp() -> String {
    humantime::format_rfc3339_nanos(SystemTime::now()).to_string()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        AuditDecision, AuditError, AuditEvent, AuditEventInput, AuditTarget, AuditWriter,
        RequestId, rfc3339_timestamp,
    };
    use crate::allowlist::AcceptedTarget;
    use crate::config::GatewayConfig;
    use core::num::NonZeroUsize;
    use core::time::Duration;
    use pretty_assertions::assert_eq;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::UNIX_EPOCH;
    use tempfile::tempdir;

    /// Builds a denied-decision event for writer tests.
    fn denied_event() -> AuditEvent {
        AuditEvent::new(AuditEventInput {
            decision: AuditDecision::Denied,
            error_class: Some("method_denied".to_owned()),
            method: "DELETE".to_owned(),
            request_body_blake3: None,
            request_bytes: 0,
            request_id: RequestId::from_parts("run", 1),
            response_body_blake3: None,
            response_bytes: 0,
            status: Some(403),
            target: AuditTarget::from_uri_parts("/v1/models", None),
            upstream_origin: "https://api.openai.com".to_owned(),
            upstream_path: None,
            upstream_query: None,
        })
    }

    /// A roomy audit event limit for tests that should not hit the bound.
    fn roomy_event_limit() -> NonZeroUsize {
        NonZeroUsize::new(0x4000).expect("limit should be non-zero")
    }

    #[test]
    fn new_preserves_status() {
        let target = AuditTarget::from_uri_parts("/v1/models", None);
        let input = AuditEventInput {
            request_id: RequestId::from_parts("run", 1),
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
            request_id: RequestId::from_parts("run", 1),
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
    fn decisions_serialize_as_snake_case_strings() {
        let decisions = [
            (AuditDecision::Allowed, "allowed"),
            (AuditDecision::Denied, "denied"),
            (AuditDecision::ResponseError, "response_error"),
            (AuditDecision::UpstreamError, "upstream_error"),
        ];

        for (decision, expected) in decisions {
            let value = serde_json::to_value(decision).expect("decision should serialize");
            assert_eq!(value, expected);
        }
    }

    #[test]
    fn event_serializes_documented_fields_and_null_semantics() {
        let target = AuditTarget::from_uri_parts("/v1/models", None);
        let input = AuditEventInput {
            request_id: RequestId::from_parts("run", 1),
            decision: AuditDecision::Denied,
            method: "DELETE".to_owned(),
            target,
            upstream_origin: "https://api.openai.com".to_owned(),
            upstream_path: None,
            upstream_query: None,
            status: Some(403),
            request_bytes: 0,
            response_bytes: 0,
            request_body_blake3: None,
            response_body_blake3: None,
            error_class: Some("method_not_allowed".to_owned()),
        };

        let value = serde_json::to_value(AuditEvent::new(input)).expect("event should serialize");

        let object = value.as_object().expect("event should be a JSON object");
        let expected_fields = [
            "decision",
            "error_class",
            "method",
            "path",
            "query",
            "request_body_blake3",
            "request_bytes",
            "request_id",
            "response_body_blake3",
            "response_bytes",
            "status",
            "timestamp",
            "upstream_origin",
            "upstream_path",
            "upstream_query",
            "version",
        ];
        for field in expected_fields {
            assert!(object.contains_key(field), "missing field {field}");
        }
        assert_eq!(object.len(), expected_fields.len());
        assert_eq!(object["version"], 1_u64);
        assert_eq!(object["decision"], "denied");
        assert_eq!(object["request_id"], "req-run-0000000000000001");
        assert!(object["upstream_path"].is_null());
        assert!(object["upstream_query"].is_null());
        assert!(object["query"].is_null());
        assert!(object["request_body_blake3"].is_null());
        assert!(object["response_body_blake3"].is_null());
        assert_eq!(object["status"], 403_u64);
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

    #[test]
    fn rfc3339_timestamp_produces_a_parsable_instant() {
        let timestamp = rfc3339_timestamp();

        assert!(
            humantime::parse_rfc3339(&timestamp).is_ok(),
            "timestamp {timestamp:?} should parse as RFC 3339"
        );
    }

    #[test]
    fn from_uri_parts_replaces_empty_paths_with_root() {
        let target = AuditTarget::from_uri_parts("", None);

        assert_eq!(target.path(), "/");
        assert_eq!(target.query(), None);
    }

    #[test]
    fn accepted_targets_convert_losslessly() {
        let accepted = AcceptedTarget::new("/v1/models", Some("limit=1"))
            .expect("origin-form path should be accepted");

        let target = AuditTarget::from(accepted);

        assert_eq!(target.path(), "/v1/models");
        assert_eq!(target.query(), Some("limit=1"));
    }

    #[tokio::test]
    async fn open_creates_missing_parent_directories() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("nested/logs/audit.ndjson");
        let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());

        let writer = AuditWriter::open(&config)
            .await
            .expect("open should create the parent directories");

        drop(writer);
        assert!(audit_log.exists());
    }

    #[tokio::test]
    async fn open_handles_parentless_audit_paths() {
        let config = GatewayConfig::for_test(PathBuf::from("/"), roomy_event_limit());

        let result = AuditWriter::open(&config).await;

        assert!(matches!(result, Err(AuditError::Open { path, .. }) if path == Path::new("/")));
    }

    #[tokio::test]
    async fn open_fails_when_the_audit_path_is_a_directory() {
        let directory = tempdir().expect("temporary directory should be created");
        let config = GatewayConfig::for_test(directory.path().to_owned(), roomy_event_limit());

        let result = AuditWriter::open(&config).await;

        assert!(matches!(result, Err(AuditError::Open { .. })));
    }

    #[tokio::test]
    async fn open_fails_when_the_parent_is_a_file() {
        let directory = tempdir().expect("temporary directory should be created");
        let blocking_file = directory.path().join("occupied");
        fs::write(&blocking_file, b"not a directory").expect("blocking file should be written");
        let config =
            GatewayConfig::for_test(blocking_file.join("audit.ndjson"), roomy_event_limit());

        let result = AuditWriter::open(&config).await;

        assert!(matches!(result, Err(AuditError::Open { path, .. }) if path == blocking_file));
    }

    #[tokio::test]
    async fn write_event_appends_one_ndjson_line() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());
        let writer = AuditWriter::open(&config)
            .await
            .expect("audit writer should open");

        writer
            .write_event(&denied_event())
            .await
            .expect("event should be written");

        let contents = fs::read_to_string(&audit_log).expect("audit log should be readable");
        assert!(contents.ends_with('\n'));
        assert_eq!(contents.lines().count(), 1);
        let line = contents.lines().next().expect("one line should exist");
        let value: serde_json::Value =
            serde_json::from_str(line).expect("line should be valid JSON");
        let object = value.as_object().expect("event should be a JSON object");
        assert_eq!(object["decision"], "denied");
        assert_eq!(object["path"], "/v1/models");
    }

    #[tokio::test]
    async fn write_event_accepts_events_exactly_at_the_maximum() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        let event = denied_event();
        let exact_size = serde_json::to_vec(&event)
            .expect("event should serialize")
            .len();
        let config = GatewayConfig::for_test(
            audit_log.clone(),
            NonZeroUsize::new(exact_size).expect("serialized events are non-empty"),
        );
        let writer = AuditWriter::open(&config)
            .await
            .expect("audit writer should open");

        writer
            .write_event(&event)
            .await
            .expect("an event exactly at the limit should be written");

        let contents = fs::read_to_string(&audit_log).expect("audit log should be readable");
        assert_eq!(contents.lines().count(), 1);
    }

    #[tokio::test]
    async fn write_event_rejects_events_over_the_configured_maximum() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        let config = GatewayConfig::for_test(
            audit_log.clone(),
            NonZeroUsize::new(1).expect("limit should be non-zero"),
        );
        let writer = AuditWriter::open(&config)
            .await
            .expect("audit writer should open");

        let result = writer.write_event(&denied_event()).await;

        assert!(matches!(
            result,
            Err(AuditError::EventTooLarge { max: 1, .. }),
        ));
        let contents = fs::read_to_string(&audit_log).expect("audit log should be readable");
        assert_eq!(contents, "");
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod proptests {
    use super::{AuditDecision, AuditEvent, AuditEventInput, AuditTarget, RequestId};
    use crate::allowlist::AcceptedTarget;
    use core::time::Duration;
    use proptest::option;
    use proptest::prelude::*;
    use std::time::UNIX_EPOCH;

    /// Every member of the closed decision set.
    fn decision_any() -> impl Strategy<Value = AuditDecision> {
        prop_oneof![
            Just(AuditDecision::Allowed),
            Just(AuditDecision::Denied),
            Just(AuditDecision::ResponseError),
            Just(AuditDecision::UpstreamError),
        ]
    }

    /// BLAKE3 hex digest shaped strings.
    fn hex_digest() -> impl Strategy<Value = String> {
        "[0-9a-f]{64}"
    }

    /// Raw request paths: origin-form spellings biased with the empty path
    /// that `from_uri_parts` replaces with `/`.
    fn raw_path() -> impl Strategy<Value = String> {
        prop_oneof![
            4 => "/[A-Za-z0-9/_-]{0,20}",
            1 => Just(String::new()),
        ]
    }

    proptest! {
        #[test]
        fn event_serialization_preserves_option_semantics(
            decision in decision_any(),
            method in "[A-Z]{3,8}",
            path in raw_path(),
            query in option::of("[a-z]{1,5}=[a-z]{1,5}"),
            upstream in option::of((
                "/[A-Za-z0-9/_-]{0,20}",
                option::of("[a-z]{1,5}=[a-z]{1,5}"),
            )),
            status in option::of(any::<u16>()),
            request_bytes in any::<u64>(),
            response_bytes in any::<u64>(),
            request_digest in option::of(hex_digest()),
            response_digest in option::of(hex_digest()),
            error_class in option::of("[a-z_]{1,20}"),
            run_token in "[0-9a-f]{1,16}",
            sequence in any::<u64>(),
        ) {
            let (upstream_path, upstream_query) = match upstream {
                Some((upstream_path, upstream_query)) => (Some(upstream_path), upstream_query),
                None => (None, None),
            };
            let input = AuditEventInput {
                request_id: RequestId::from_parts(&run_token, sequence),
                decision,
                method,
                target: AuditTarget::from_uri_parts(&path, query.as_deref()),
                upstream_origin: "https://api.openai.com".to_owned(),
                upstream_path: upstream_path.clone(),
                upstream_query: upstream_query.clone(),
                status,
                request_bytes,
                response_bytes,
                request_body_blake3: request_digest.clone(),
                response_body_blake3: response_digest.clone(),
                error_class: error_class.clone(),
            };

            let value = serde_json::to_value(AuditEvent::new(input))
                .expect("event should serialize");
            let object = value.as_object().expect("event should be a JSON object");

            prop_assert_eq!(object.len(), 16);
            let decision_text = object["decision"]
                .as_str()
                .expect("decision should be a string");
            prop_assert!(
                ["allowed", "denied", "response_error", "upstream_error"]
                    .contains(&decision_text)
            );
            let expected_path = if path.is_empty() { "/" } else { path.as_str() };
            prop_assert_eq!(object["path"].as_str(), Some(expected_path));
            prop_assert_eq!(object["upstream_path"].is_null(), upstream_path.is_none());
            prop_assert_eq!(object["upstream_query"].is_null(), upstream_query.is_none());
            prop_assert_eq!(object["query"].is_null(), query.is_none());
            prop_assert_eq!(object["status"].is_null(), status.is_none());
            prop_assert_eq!(
                object["request_body_blake3"].is_null(),
                request_digest.is_none()
            );
            prop_assert_eq!(
                object["response_body_blake3"].is_null(),
                response_digest.is_none()
            );
            prop_assert_eq!(object["error_class"].is_null(), error_class.is_none());
            prop_assert_eq!(object["request_bytes"].as_u64(), Some(request_bytes));
            prop_assert_eq!(object["response_bytes"].as_u64(), Some(response_bytes));
        }

        #[test]
        fn accepted_targets_convert_without_loss(
            path in "/[A-Za-z0-9_-]{0,20}",
            query in option::of("[a-z]{1,5}=[a-z]{1,5}"),
        ) {
            let accepted = AcceptedTarget::new(&path, query.as_deref())
                .expect("generated paths are valid origin-form targets");

            let target = AuditTarget::from(accepted);

            prop_assert_eq!(target.path(), path.as_str());
            prop_assert_eq!(target.query(), query.as_deref());
        }

        #[test]
        fn request_id_embeds_run_token_and_padded_sequence(
            run_token in "[0-9a-f]{1,16}",
            sequence in any::<u64>(),
        ) {
            let value = serde_json::to_value(RequestId::from_parts(&run_token, sequence))
                .expect("request id should serialize");

            let expected = format!("req-{run_token}-{sequence:016x}");
            prop_assert_eq!(value.as_str(), Some(expected.as_str()));
        }

        #[test]
        fn timestamp_formatting_round_trips(
            seconds in 0_u64..=253_402_300_799,
            nanoseconds in 0_u32..1_000_000_000,
        ) {
            let instant = UNIX_EPOCH
                .checked_add(Duration::new(seconds, nanoseconds))
                .expect("generated instants fit in SystemTime");

            let formatted = humantime::format_rfc3339_nanos(instant).to_string();
            let parsed = humantime::parse_rfc3339(&formatted)
                .expect("formatted timestamps should parse");

            prop_assert_eq!(parsed, instant);
        }
    }
}
