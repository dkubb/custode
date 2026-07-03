//! Audit event schema and writer.

use crate::allowlist::AcceptedTarget;
use crate::body::BodyDigest;
use crate::config::GatewayConfig;
use core::num::NonZeroU64;
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
    /// Accepted request path, or the raw request target for denied
    /// non-origin-form requests.
    path: String,
    /// Request query string without `?`.
    query: Option<String>,
    /// Request body digest.
    request_body_blake3: Option<String>,
    /// Whether request body bytes were observed.
    request_body_observed: bool,
    /// Request body bytes.
    request_bytes: u64,
    /// Request identity.
    request_id: RequestId,
    /// Response body digest.
    response_body_blake3: Option<String>,
    /// Whether response body bytes were observed.
    response_body_observed: bool,
    /// Response body bytes.
    response_bytes: u64,
    /// Response status returned to the harness, when one exists.
    status: Option<u16>,
    /// RFC 3339 UTC timestamp.
    timestamp: AuditTimestamp,
    /// Configured upstream origin.
    upstream_origin: String,
    /// Upstream path, when an upstream request was attempted.
    upstream_path: Option<String>,
    /// Upstream query, when an upstream request was attempted.
    upstream_query: Option<String>,
    /// Audit schema version.
    version: u8,
}

/// Body accounting summary recorded in audit events.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum AuditBodySummary {
    /// Body was observed and empty.
    Empty,

    /// Body was observed and non-empty.
    NonEmpty {
        /// Body digest.
        blake3: BodyDigest,
        /// Body byte count.
        bytes: NonZeroU64,
    },

    /// Body bytes were not observed.
    NotObserved,
}

/// Input used to construct an audit event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuditEventInput {
    /// Closed audit outcome.
    outcome: AuditOutcome,
    /// Request context common to every audit event.
    request: AuditRequestInput,
}

/// Closed audit outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AuditOutcome {
    /// Request was allowed and completed normally.
    Allowed {
        /// Response body summary.
        response_body: AuditBodySummary,
        /// Response status returned to the harness.
        status: u16,
        /// Upstream target.
        upstream: AuditUpstreamTarget,
    },

    /// Request was denied before upstream I/O.
    Denied {
        /// Stable error class.
        error_class: String,
        /// Response status returned to the harness.
        status: u16,
    },

    /// Response handling failed.
    ResponseError {
        /// Stable error class.
        error_class: String,
        /// Response body summary.
        response_body: AuditBodySummary,
        /// Response status returned to the harness.
        status: u16,
        /// Upstream target.
        upstream: AuditUpstreamTarget,
    },

    /// Upstream request failed before a response completed.
    UpstreamError {
        /// Stable error class.
        error_class: String,
        /// Response status returned to the harness.
        status: u16,
        /// Upstream target.
        upstream: AuditUpstreamTarget,
    },
}

/// Request context common to every audit event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuditRequestInput {
    /// Request body summary.
    body: AuditBodySummary,
    /// Request method.
    method: String,
    /// Request identity.
    request_id: RequestId,
    /// Accepted or raw audit target.
    target: AuditTarget,
    /// Configured upstream origin.
    upstream_origin: String,
}

/// Upstream target recorded when upstream I/O was attempted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuditUpstreamTarget {
    /// Upstream request path.
    path: String,
    /// Upstream request query.
    query: Option<String>,
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

/// RFC 3339 UTC audit timestamp.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub(crate) struct AuditTimestamp(String);

impl AuditBodySummary {
    /// Creates an empty body summary.
    #[must_use]
    pub(crate) const fn empty() -> Self {
        Self::Empty
    }

    /// Consumes the summary into serialized audit body fields.
    #[must_use]
    fn into_event_fields(self) -> (Option<String>, bool, u64) {
        match self {
            Self::Empty => (None, true, 0),
            Self::NonEmpty { blake3, bytes } => (Some(blake3.to_hex_string()), true, bytes.get()),
            Self::NotObserved => (None, false, 0),
        }
    }

    /// Creates a non-empty body summary.
    #[must_use]
    pub(crate) const fn non_empty(blake3: BodyDigest, bytes: NonZeroU64) -> Self {
        Self::NonEmpty { blake3, bytes }
    }

    /// Creates an unobserved body summary.
    #[must_use]
    pub(crate) const fn not_observed() -> Self {
        Self::NotObserved
    }
}

impl AuditEventInput {
    /// Creates an audit event input from request context and outcome.
    #[must_use]
    pub(crate) const fn new(request: AuditRequestInput, outcome: AuditOutcome) -> Self {
        Self { outcome, request }
    }
}

impl AuditOutcome {
    /// Creates an allowed outcome.
    #[must_use]
    pub(crate) const fn allowed(
        response_body: AuditBodySummary,
        status: u16,
        upstream: AuditUpstreamTarget,
    ) -> Self {
        Self::Allowed {
            response_body,
            status,
            upstream,
        }
    }

    /// Creates a denied outcome.
    #[must_use]
    pub(crate) fn denied(error_class: impl Into<String>, status: u16) -> Self {
        Self::Denied {
            error_class: error_class.into(),
            status,
        }
    }

    /// Creates a response-error outcome.
    #[must_use]
    pub(crate) fn response_error(
        error_class: impl Into<String>,
        response_body: AuditBodySummary,
        status: u16,
        upstream: AuditUpstreamTarget,
    ) -> Self {
        Self::ResponseError {
            error_class: error_class.into(),
            response_body,
            status,
            upstream,
        }
    }

    /// Creates an upstream-error outcome.
    #[must_use]
    pub(crate) fn upstream_error(
        error_class: impl Into<String>,
        status: u16,
        upstream: AuditUpstreamTarget,
    ) -> Self {
        Self::UpstreamError {
            error_class: error_class.into(),
            status,
            upstream,
        }
    }
}

impl AuditRequestInput {
    /// Creates request context common to every audit event.
    #[must_use]
    pub(crate) const fn new(
        method: String,
        target: AuditTarget,
        request_id: RequestId,
        body: AuditBodySummary,
        upstream_origin: String,
    ) -> Self {
        Self {
            body,
            method,
            request_id,
            target,
            upstream_origin,
        }
    }
}

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

#[cfg(test)]
impl AuditUpstreamTarget {
    /// Creates an upstream target from forwarded path and query.
    #[must_use]
    const fn new(path: String, query: Option<String>) -> Self {
        Self { path, query }
    }
}

impl From<&AcceptedTarget> for AuditUpstreamTarget {
    fn from(target: &AcceptedTarget) -> Self {
        Self {
            path: target.path().to_owned(),
            query: target.query().map(str::to_owned),
        }
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
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new(input: AuditEventInput) -> Self {
        Self::new_at(input, AuditTimestamp::now())
    }

    /// Creates an audit event for a request decision at a supplied timestamp.
    #[must_use]
    pub(crate) fn new_at(input: AuditEventInput, timestamp: AuditTimestamp) -> Self {
        let AuditEventInput { request, outcome } = input;
        let AuditRequestInput {
            body: request_body,
            method,
            request_id,
            target,
            upstream_origin,
        } = request;
        let (decision, error_class, response_body, status, upstream) = match outcome {
            AuditOutcome::Allowed {
                response_body,
                status,
                upstream,
            } => (
                AuditDecision::Allowed,
                None,
                response_body,
                Some(status),
                Some(upstream),
            ),
            AuditOutcome::Denied {
                error_class,
                status,
            } => (
                AuditDecision::Denied,
                Some(error_class),
                AuditBodySummary::not_observed(),
                Some(status),
                None,
            ),
            AuditOutcome::ResponseError {
                error_class,
                response_body,
                status,
                upstream,
            } => (
                AuditDecision::ResponseError,
                Some(error_class),
                response_body,
                Some(status),
                Some(upstream),
            ),
            AuditOutcome::UpstreamError {
                error_class,
                status,
                upstream,
            } => (
                AuditDecision::UpstreamError,
                Some(error_class),
                AuditBodySummary::not_observed(),
                Some(status),
                Some(upstream),
            ),
        };
        let (upstream_path, upstream_query) = match upstream {
            Some(upstream_target) => (Some(upstream_target.path), upstream_target.query),
            None => (None, None),
        };
        let (request_body_blake3, request_body_observed, request_bytes) =
            request_body.into_event_fields();
        let (response_body_blake3, response_body_observed, response_bytes) =
            response_body.into_event_fields();

        Self {
            decision,
            error_class,
            method,
            path: target.path().to_owned(),
            query: target.query().map(str::to_owned),
            request_body_blake3,
            request_body_observed,
            request_bytes,
            request_id,
            response_body_blake3,
            response_body_observed,
            response_bytes,
            status,
            timestamp,
            upstream_origin,
            upstream_path,
            upstream_query,
            version: 2,
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

impl AuditTimestamp {
    /// Returns the timestamp string.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Creates a timestamp from a fixed RFC 3339 value for deterministic tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn for_test(value: &str) -> Self {
        let timestamp =
            humantime::parse_rfc3339(value).expect("test timestamp should parse as RFC 3339");
        Self(humantime::format_rfc3339_nanos(timestamp).to_string())
    }

    /// Returns the current RFC 3339 UTC timestamp for audit events.
    #[must_use]
    pub(crate) fn now() -> Self {
        Self(humantime::format_rfc3339_nanos(SystemTime::now()).to_string())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[expect(
    clippy::inline_modules,
    reason = "inline tests keep file-local coverage ownership explicit"
)]
mod tests {
    use super::{
        AuditBodySummary, AuditDecision, AuditError, AuditEvent, AuditEventInput, AuditOutcome,
        AuditRequestInput, AuditTarget, AuditTimestamp, AuditWriter, RequestId,
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

    /// Builds common request audit input for tests.
    fn request_input(
        method: &str,
        target: AuditTarget,
        body: AuditBodySummary,
    ) -> AuditRequestInput {
        AuditRequestInput::new(
            method.to_owned(),
            target,
            RequestId::from_parts("run", 1),
            body,
            "https://api.openai.com".to_owned(),
        )
    }

    /// Builds a denied audit input for tests.
    fn denied_input(
        method: &str,
        target: AuditTarget,
        error_class: &str,
        status: u16,
    ) -> AuditEventInput {
        AuditEventInput::new(
            request_input(method, target, AuditBodySummary::empty()),
            AuditOutcome::denied(error_class, status),
        )
    }

    /// Builds a denied-decision event for writer tests.
    fn denied_event() -> AuditEvent {
        AuditEvent::new(denied_input(
            "DELETE",
            AuditTarget::from_uri_parts("/v1/models", None),
            "method_denied",
            403,
        ))
    }

    /// A roomy audit event limit for tests that should not hit the bound.
    fn roomy_event_limit() -> NonZeroUsize {
        NonZeroUsize::new(0x4000).expect("limit should be non-zero")
    }

    #[test]
    fn new_preserves_status() {
        let input = denied_input(
            "CONNECT",
            AuditTarget::from_uri_parts("/v1/models", None),
            "connect_unsupported",
            405,
        );

        let event = AuditEvent::new(input);
        let expected = Some(405);

        assert_eq!(event.status, expected);
    }

    #[test]
    fn new_preserves_rejected_raw_path() {
        let target = AuditTarget::from_uri_parts("/v1/responses/%2e%2e/models", Some("limit=1"));
        let input = denied_input("GET", target, "dot_segment", 400);

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
        let input = denied_input(
            "DELETE",
            AuditTarget::from_uri_parts("/v1/models", None),
            "method_not_allowed",
            403,
        );

        let value = serde_json::to_value(AuditEvent::new(input)).expect("event should serialize");

        let object = value.as_object().expect("event should be a JSON object");
        let expected_fields = [
            "decision",
            "error_class",
            "method",
            "path",
            "query",
            "request_body_blake3",
            "request_body_observed",
            "request_bytes",
            "request_id",
            "response_body_blake3",
            "response_body_observed",
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
        assert_eq!(object["version"], 2_u64);
        assert_eq!(object["decision"], "denied");
        assert_eq!(object["request_id"], "req-run-0000000000000001");
        assert!(object["upstream_path"].is_null());
        assert!(object["upstream_query"].is_null());
        assert!(object["query"].is_null());
        assert!(object["request_body_blake3"].is_null());
        assert_eq!(object["request_body_observed"], true);
        assert!(object["response_body_blake3"].is_null());
        assert_eq!(object["response_body_observed"], false);
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
        let timestamp = AuditTimestamp::now();

        assert!(
            humantime::parse_rfc3339(timestamp.as_str()).is_ok(),
            "timestamp {:?} should parse as RFC 3339",
            timestamp.as_str()
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
#[expect(
    clippy::inline_modules,
    reason = "inline proptests keep file-local coverage ownership explicit"
)]
mod proptests {
    use super::{
        AuditBodySummary, AuditEvent, AuditEventInput, AuditOutcome, AuditRequestInput,
        AuditTarget, AuditUpstreamTarget, RequestId,
    };
    use crate::allowlist::AcceptedTarget;
    use crate::body::BodyDigest;
    use core::num::NonZeroU64;
    use core::time::Duration;
    use proptest::prelude::*;
    use proptest::{collection, option};
    use std::time::UNIX_EPOCH;

    /// Returns body length as a `u64`.
    fn body_len(bytes: &[u8]) -> u64 {
        u64::try_from(bytes.len()).expect("generated body length should fit u64")
    }

    /// Returns a non-empty audit body summary for observed bytes.
    fn body_summary(bytes: &[u8]) -> AuditBodySummary {
        AuditBodySummary::non_empty(
            BodyDigest::from_bytes(bytes),
            NonZeroU64::new(body_len(bytes)).expect("generated body should be non-empty"),
        )
    }

    /// Generates observed non-empty body bytes.
    fn non_empty_body() -> impl Strategy<Value = Vec<u8>> {
        collection::vec(any::<u8>(), 1..33)
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
        fn event_serialization_preserves_variant_semantics(
            outcome_kind in 0_u8..4,
            method in "[A-Z]{3,8}",
            path in raw_path(),
            query in option::of("[a-z]{1,5}=[a-z]{1,5}"),
            upstream_path in "/[A-Za-z0-9/_-]{0,20}",
            upstream_query in option::of("[a-z]{1,5}=[a-z]{1,5}"),
            status in any::<u16>(),
            request_body_bytes in non_empty_body(),
            response_body_bytes in non_empty_body(),
            error_class in "[a-z_]{1,20}",
            run_token in "[0-9a-f]{1,16}",
            sequence in any::<u64>(),
        ) {
            let request_body = body_summary(&request_body_bytes);
            let request_bytes = body_len(&request_body_bytes);
            let request_digest = BodyDigest::from_bytes(&request_body_bytes).to_hex_string();
            let response_body = body_summary(&response_body_bytes);
            let response_bytes = body_len(&response_body_bytes);
            let response_digest = BodyDigest::from_bytes(&response_body_bytes).to_hex_string();
            let upstream =
                AuditUpstreamTarget::new(upstream_path.clone(), upstream_query.clone());
            let (outcome, decision, expected_error, expected_response_digest, expected_response_bytes, expected_upstream) = match outcome_kind {
                0 => (
                    AuditOutcome::allowed(response_body, status, upstream),
                    "allowed",
                    None,
                    Some(response_digest.as_str()),
                    response_bytes,
                    Some((upstream_path.as_str(), upstream_query.as_deref())),
                ),
                1 => (
                    AuditOutcome::denied(error_class.clone(), status),
                    "denied",
                    Some(error_class.as_str()),
                    None,
                    0,
                    None,
                ),
                2 => (
                    AuditOutcome::response_error(
                        error_class.clone(),
                        response_body,
                        status,
                        upstream,
                    ),
                    "response_error",
                    Some(error_class.as_str()),
                    Some(response_digest.as_str()),
                    response_bytes,
                    Some((upstream_path.as_str(), upstream_query.as_deref())),
                ),
                _ => (
                    AuditOutcome::upstream_error(error_class.clone(), status, upstream),
                    "upstream_error",
                    Some(error_class.as_str()),
                    None,
                    0,
                    Some((upstream_path.as_str(), upstream_query.as_deref())),
                ),
            };
            let request = AuditRequestInput::new(
                method,
                AuditTarget::from_uri_parts(&path, query.as_deref()),
                RequestId::from_parts(&run_token, sequence),
                request_body,
                "https://api.openai.com".to_owned(),
            );
            let input = AuditEventInput::new(request, outcome);

            let value = serde_json::to_value(AuditEvent::new(input))
                .expect("event should serialize");
            let object = value.as_object().expect("event should be a JSON object");

            prop_assert_eq!(object.len(), 18);
            prop_assert_eq!(object["decision"].as_str(), Some(decision));
            let expected_path = if path.is_empty() { "/" } else { path.as_str() };
            prop_assert_eq!(object["path"].as_str(), Some(expected_path));
            if let Some((expected_upstream_path, expected_upstream_query)) = expected_upstream {
                prop_assert_eq!(object["upstream_path"].as_str(), Some(expected_upstream_path));
                prop_assert_eq!(object["upstream_query"].as_str(), expected_upstream_query);
            } else {
                prop_assert!(object["upstream_path"].is_null());
                prop_assert!(object["upstream_query"].is_null());
            }
            prop_assert_eq!(object["query"].is_null(), query.is_none());
            prop_assert_eq!(object["status"].as_u64(), Some(u64::from(status)));
            prop_assert_eq!(
                object["request_body_blake3"].as_str(),
                Some(request_digest.as_str())
            );
            prop_assert_eq!(object["request_body_observed"].as_bool(), Some(true));
            prop_assert_eq!(object["response_body_blake3"].as_str(), expected_response_digest);
            prop_assert_eq!(
                object["response_body_observed"].as_bool(),
                Some(expected_response_digest.is_some())
            );
            prop_assert_eq!(object["error_class"].as_str(), expected_error);
            prop_assert_eq!(object["request_bytes"].as_u64(), Some(request_bytes));
            prop_assert_eq!(object["response_bytes"].as_u64(), Some(expected_response_bytes));
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
