//! Request handling state machine.

use crate::allowlist::AllowedTarget;
use crate::audit::{
    AuditDenial, AuditError, AuditEvent, AuditEventInput, AuditRequestInput, AuditResponseError,
    AuditResponseHeaderError, AuditUpstreamError, ObservedAuditRequestInput, ObservedBodySummary,
    RequestId,
};
use crate::body::{AccountedBody, OversizedResponseBody, ResponseAccount};
use crate::config::GatewayConfig;
use crate::headers::HeaderError;
use crate::ports::{AuditSink, Clock, RequestIdError, RequestIdSource};
use ::http::{Error as HttpError, StatusCode};
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{Notify, OwnedRwLockReadGuard, RwLock};

/// Shared gateway state.
#[derive(Clone, Debug)]
pub(crate) struct Gateway {
    /// Audit log writer.
    audit: Arc<dyn AuditSink>,
    /// True after a required audit event failed to write.
    audit_failed: Arc<AtomicBool>,
    /// Wakes active response streams after a required audit event fails.
    audit_failure: Arc<Notify>,
    /// Audit timestamp source.
    clock: Arc<dyn Clock>,
    /// Parsed gateway configuration.
    config: Arc<GatewayConfig>,
    /// Gate that blocks new upstream forwarding when audit fails.
    forwarding_gate: Arc<RwLock<()>>,
    /// Request identity source.
    request_ids: Arc<dyn RequestIdSource>,
}

/// Gateway runtime error.
#[derive(Debug, Error)]
pub(crate) enum GatewayError {
    /// Audit log failed.
    #[error("{0}")]
    Audit(#[from] AuditError),

    /// Audit log is unavailable after a previous required audit failure.
    #[error("audit is unavailable after a previous required audit failure")]
    AuditUnavailable,

    /// Header filtering failed.
    #[error("{0}")]
    Header(#[from] HeaderError),

    /// Request identity allocation failed.
    #[error("{0}")]
    RequestId(#[from] RequestIdError),

    /// Gateway response could not be built.
    #[error("failed to build response: {0}")]
    ResponseBuild(HttpError),
}

/// Permit proving upstream forwarding started before audit closed.
#[derive(Debug)]
pub(crate) struct ForwardingPermit {
    /// Read guard held until upstream dispatch completes.
    _guard: OwnedRwLockReadGuard<()>,
}

/// Input for response audit events.
#[derive(Debug)]
pub(crate) struct ResponseAuditInput<'request> {
    /// Closed response audit outcome.
    outcome: ResponseAuditOutcome,
    /// Accounted request body.
    request_body: &'request AccountedBody,
    /// Request identity.
    request_id: RequestId,
    /// Allowlist witness for the accepted method and target.
    target: &'request AllowedTarget,
}

/// Closed response audit outcome.
#[derive(Debug)]
pub(crate) struct ResponseAuditOutcome {
    /// Internal response audit outcome.
    kind: ResponseAuditOutcomeKind,
}

/// Closed response audit outcome variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseAuditOutcomeKind {
    /// Request was allowed and completed normally.
    Allowed {
        /// Response body summary.
        response_body: ObservedBodySummary,
        /// Response status returned to the harness.
        status: StatusCode,
    },

    /// Downstream closed before the response completed.
    DownstreamClosed {
        /// Response body summary.
        response_body: ObservedBodySummary,
        /// Response status returned to the harness.
        status: StatusCode,
    },

    /// Response body exceeded the configured limit.
    ResponseBodyTooLarge {
        /// Observed oversized response body.
        response_body: OversizedResponseBody,
        /// Response status returned to the harness.
        status: StatusCode,
    },

    /// Response headers failed before response body bytes were observed.
    ResponseHeaderError {
        /// Response header error.
        error: AuditResponseHeaderError,
    },

    /// Response streaming exceeded the configured gateway deadline.
    ResponseStreamTimeout {
        /// Response body summary.
        response_body: ObservedBodySummary,
        /// Response status returned to the harness.
        status: StatusCode,
    },

    /// Upstream request failed before a response completed.
    UpstreamError {
        /// Upstream request error.
        error: AuditUpstreamError,
    },

    /// Upstream response stream failed after upstream I/O started.
    UpstreamResponseStreamFailed {
        /// Response body summary.
        response_body: ObservedBodySummary,
        /// Response status returned to the harness.
        status: StatusCode,
    },

    /// Upstream response stream timed out after upstream I/O started.
    UpstreamResponseTimeout {
        /// Response body summary.
        response_body: ObservedBodySummary,
        /// Response status returned to the harness.
        status: StatusCode,
    },
}

impl ResponseAuditOutcome {
    /// Creates an allowed response outcome.
    #[must_use]
    pub(crate) fn allowed(response_account: &ResponseAccount, status: StatusCode) -> Self {
        Self {
            kind: ResponseAuditOutcomeKind::Allowed {
                response_body: ObservedBodySummary::from_response_account(response_account),
                status,
            },
        }
    }

    /// Creates a downstream-closed response outcome.
    #[must_use]
    pub(crate) fn downstream_closed(
        response_account: &ResponseAccount,
        status: StatusCode,
    ) -> Self {
        Self {
            kind: ResponseAuditOutcomeKind::DownstreamClosed {
                response_body: ObservedBodySummary::from_response_account(response_account),
                status,
            },
        }
    }

    /// Consumes the outcome into its internal variant.
    #[must_use]
    const fn into_kind(self) -> ResponseAuditOutcomeKind {
        self.kind
    }

    /// Creates a response-body-too-large outcome.
    #[must_use]
    pub(crate) const fn response_body_too_large(
        response_body: OversizedResponseBody,
        status: StatusCode,
    ) -> Self {
        Self {
            kind: ResponseAuditOutcomeKind::ResponseBodyTooLarge {
                response_body,
                status,
            },
        }
    }

    /// Creates a response-header-error outcome.
    #[must_use]
    pub(crate) const fn response_header_error(error: AuditResponseHeaderError) -> Self {
        Self {
            kind: ResponseAuditOutcomeKind::ResponseHeaderError { error },
        }
    }

    /// Creates a response-stream-timeout outcome.
    #[must_use]
    pub(crate) fn response_stream_timeout(
        response_account: &ResponseAccount,
        status: StatusCode,
    ) -> Self {
        Self {
            kind: ResponseAuditOutcomeKind::ResponseStreamTimeout {
                response_body: ObservedBodySummary::from_response_account(response_account),
                status,
            },
        }
    }

    /// Creates an upstream-error outcome.
    #[must_use]
    pub(crate) const fn upstream_error(error: AuditUpstreamError) -> Self {
        Self {
            kind: ResponseAuditOutcomeKind::UpstreamError { error },
        }
    }

    /// Creates an upstream-response-stream-failed outcome.
    #[must_use]
    pub(crate) fn upstream_response_stream_failed(
        response_account: &ResponseAccount,
        status: StatusCode,
    ) -> Self {
        Self {
            kind: ResponseAuditOutcomeKind::UpstreamResponseStreamFailed {
                response_body: ObservedBodySummary::from_response_account(response_account),
                status,
            },
        }
    }

    /// Creates an upstream-response-timeout outcome.
    #[must_use]
    pub(crate) fn upstream_response_timeout(
        response_account: &ResponseAccount,
        status: StatusCode,
    ) -> Self {
        Self {
            kind: ResponseAuditOutcomeKind::UpstreamResponseTimeout {
                response_body: ObservedBodySummary::from_response_account(response_account),
                status,
            },
        }
    }
}

impl<'request> ResponseAuditInput<'request> {
    /// Creates response audit input from an accepted method-target witness.
    #[must_use]
    pub(crate) const fn new(
        target: &'request AllowedTarget,
        outcome: ResponseAuditOutcome,
        request_body: &'request AccountedBody,
        request_id: RequestId,
    ) -> Self {
        Self {
            outcome,
            request_body,
            request_id,
            target,
        }
    }
}

impl Gateway {
    /// Writes one required audit event and records permanent audit failure.
    async fn append_required_audit_event(&self, event: &AuditEvent) -> Result<(), GatewayError> {
        if let Err(error) = self.audit.append_event(event).await {
            self.close_forwarding().await;
            Err(GatewayError::Audit(error))
        } else {
            Ok(())
        }
    }

    /// Writes an audit event for a denied request.
    ///
    /// # Errors
    ///
    /// Returns an error when writing the audit event fails.
    pub(crate) async fn audit_denial(
        &self,
        request_id: RequestId,
        denial: AuditDenial,
        request_body: Option<&AccountedBody>,
    ) -> Result<(), GatewayError> {
        let request = AuditRequestInput::for_denial(
            denial,
            request_id,
            request_body,
            self.config.upstream_origin().clone(),
        );
        let event = AuditEvent::new_at(AuditEventInput::denied(request), self.clock.now());
        self.append_required_audit_event(&event).await
    }

    /// Writes an audit event for a completed upstream response.
    ///
    /// # Errors
    ///
    /// Returns an error when writing the audit event fails.
    pub(crate) async fn audit_response(
        &self,
        input: ResponseAuditInput<'_>,
    ) -> Result<(), GatewayError> {
        let request =
            ObservedAuditRequestInput::new(input.target, input.request_id, input.request_body);
        let event_input = match input.outcome.into_kind() {
            ResponseAuditOutcomeKind::Allowed {
                response_body,
                status,
            } => AuditEventInput::allowed(request, response_body, status),
            ResponseAuditOutcomeKind::DownstreamClosed {
                response_body,
                status,
            } => {
                let error = AuditResponseError::downstream_closed(response_body, status);
                AuditEventInput::response_error(request, error)
            }
            ResponseAuditOutcomeKind::ResponseBodyTooLarge {
                response_body,
                status,
            } => {
                let error = AuditResponseError::response_body_too_large(response_body, status);
                AuditEventInput::response_error(request, error)
            }
            ResponseAuditOutcomeKind::ResponseHeaderError { error } => {
                let response_error = AuditResponseError::response_header(error);
                AuditEventInput::response_error(request, response_error)
            }
            ResponseAuditOutcomeKind::ResponseStreamTimeout {
                response_body,
                status,
            } => {
                let error = AuditResponseError::response_stream_timeout(response_body, status);
                AuditEventInput::response_error(request, error)
            }
            ResponseAuditOutcomeKind::UpstreamResponseStreamFailed {
                response_body,
                status,
            } => {
                let error =
                    AuditResponseError::upstream_response_stream_failed(response_body, status);
                AuditEventInput::response_error(request, error)
            }
            ResponseAuditOutcomeKind::UpstreamResponseTimeout {
                response_body,
                status,
            } => {
                let error = AuditResponseError::upstream_response_timeout(response_body, status);
                AuditEventInput::response_error(request, error)
            }
            ResponseAuditOutcomeKind::UpstreamError { error } => {
                AuditEventInput::upstream_error(request, error)
            }
        };
        let event = AuditEvent::new_at(event_input, self.clock.now());
        self.append_required_audit_event(&event).await
    }

    /// Starts upstream forwarding unless audit has already failed.
    pub(crate) async fn begin_forwarding(&self) -> Result<ForwardingPermit, GatewayError> {
        let guard = Arc::clone(&self.forwarding_gate).read_owned().await;
        self.require_audit_available()?;
        Ok(ForwardingPermit { _guard: guard })
    }

    /// Closes future upstream forwarding after a required audit failure.
    async fn close_forwarding(&self) {
        self.audit_failed.store(true, Ordering::SeqCst);
        self.audit_failure.notify_waiters();
        let _guard = self.forwarding_gate.write().await;
    }

    /// Returns the parsed configuration.
    #[must_use]
    pub(crate) fn config(&self) -> &GatewayConfig {
        &self.config
    }

    /// Builds a gateway from parsed configuration and explicit runtime ports.
    #[must_use]
    pub(crate) fn from_ports(
        config: GatewayConfig,
        audit: impl AuditSink + 'static,
        clock: impl Clock + 'static,
        request_ids: impl RequestIdSource + 'static,
    ) -> Self {
        Self {
            audit: Arc::new(audit),
            audit_failed: Arc::new(AtomicBool::new(false)),
            audit_failure: Arc::new(Notify::new()),
            clock: Arc::new(clock),
            config: Arc::new(config),
            forwarding_gate: Arc::new(RwLock::new(())),
            request_ids: Arc::new(request_ids),
        }
    }

    /// Allocates a request identity unique within this gateway run.
    ///
    /// The sequence is unique within a run; the per-run random token makes
    /// cross-run collisions negligible under the OS RNG assumption.
    pub(crate) fn next_request_id(&self) -> Result<RequestId, RequestIdError> {
        self.request_ids.next_request_id()
    }

    /// Returns an error when a previous required audit event failed.
    pub(crate) fn require_audit_available(&self) -> Result<(), GatewayError> {
        if self.audit_failed.load(Ordering::SeqCst) {
            Err(GatewayError::AuditUnavailable)
        } else {
            Ok(())
        }
    }

    /// Waits until a required audit event fails.
    pub(crate) async fn wait_for_audit_failure(&self) {
        loop {
            let notified = self.audit_failure.notified();
            if self.audit_failed.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[expect(
    clippy::inline_modules,
    reason = "inline tests keep file-local coverage ownership explicit"
)]
mod tests {
    use super::{Gateway, GatewayError, ResponseAuditInput, ResponseAuditOutcome};
    use crate::adapters::{SequentialRequestIds, SystemClock};
    use crate::allowlist::{AcceptedTarget, AllowedTarget, RejectedAllowedTarget, allow_target};
    use crate::audit::{
        AuditDenial, AuditError, AuditWriter, PreparsedAuditTarget, RequestId, RunToken,
    };
    use crate::body::{AccountedBody, ResponseAccount};
    use crate::config::{GatewayConfig, RequestBodyBytes};
    use crate::sim::{FixedClock, MemoryAuditSink};
    use ::http::{Method, StatusCode, Uri};
    use axum::body::Body;
    use core::num::{NonZeroU64, NonZeroUsize};
    use pretty_assertions::{assert_eq, assert_ne};
    use serde_json::{Map, Value};
    use std::path::Path;
    use tempfile::tempdir;
    use tokio::fs::read_to_string;

    /// Builds a gateway writing audit events into the supplied directory.
    async fn runtime_gateway(directory: &Path) -> Gateway {
        let config = GatewayConfig::for_runtime_test(
            directory.join("audit.ndjson"),
            "https://api.openai.com",
        );
        production_gateway(config)
            .await
            .expect("gateway should initialize")
    }

    /// Builds a gateway from production adapters.
    async fn production_gateway(config: GatewayConfig) -> Result<Gateway, GatewayError> {
        let audit = AuditWriter::open(&config).await?;
        Ok(Gateway::from_ports(
            config,
            audit,
            SystemClock,
            SequentialRequestIds::production().expect("request id source should initialize"),
        ))
    }

    /// Reads the single audit event written to the supplied directory.
    async fn single_audit_event(directory: &Path) -> serde_json::Value {
        let contents = read_to_string(directory.join("audit.ndjson"))
            .await
            .expect("audit log should be readable");
        let mut lines = contents.lines();
        let line = lines.next().expect("audit log should hold one event");
        assert_eq!(
            lines.next(),
            None,
            "audit log should hold exactly one event"
        );
        serde_json::from_str(line).expect("audit event should be JSON")
    }

    /// Reads a request body for audit input construction.
    async fn accounted_body(body: Body) -> AccountedBody {
        AccountedBody::read_request(body, request_body_limit(1_024))
            .await
            .expect("request body should be accounted")
    }

    /// Builds a request body byte limit for tests.
    fn request_body_limit(value: usize) -> RequestBodyBytes {
        RequestBodyBytes::for_test(NonZeroUsize::new(value).expect("limit should be non-zero"))
    }

    /// Builds an allowlist witness for response audit tests.
    fn allowed_target(gateway: &Gateway, path: &str, query: Option<&str>) -> AllowedTarget {
        let target = AcceptedTarget::new(path, query).expect("target should parse");
        allow_target(gateway.config(), &Method::GET, target).expect("target should be allowed")
    }

    /// Builds an allowlist rejection witness for audit tests.
    fn rejected_allowed_target(
        config: &GatewayConfig,
        method: &Method,
        path: &str,
    ) -> RejectedAllowedTarget {
        let target = AcceptedTarget::new(path, None).expect("target should parse");
        allow_target(config, method, target).expect_err("target should be rejected")
    }

    /// Asserts that a required audit failure makes the gateway unavailable.
    async fn assert_failed_audit_marks_gateway_unavailable() {
        let config = GatewayConfig::for_runtime_test(
            Path::new("unused-audit.ndjson").to_owned(),
            "https://api.openai.com",
        );
        let (audit, _audit_recorder) =
            MemoryAuditSink::failing_on(NonZeroUsize::new(1).expect("literal should be non-zero"));
        let gateway = Gateway::from_ports(
            config,
            audit,
            FixedClock,
            SequentialRequestIds::new(RunToken::for_test("000000000000000a-000000000000000b")),
        );

        let permit = gateway
            .begin_forwarding()
            .await
            .expect("forwarding should start before audit failure");
        drop(permit);
        gateway
            .require_audit_available()
            .expect("audit should start available");

        let result = gateway
            .audit_denial(
                RequestId::from_parts(
                    &RunToken::for_test("000000000000000a-000000000000000b"),
                    NonZeroU64::new(1).expect("sequence should be non-zero"),
                ),
                AuditDenial::connect_unsupported(PreparsedAuditTarget::from_request_uri(
                    &Uri::from_static("/"),
                )),
                None,
            )
            .await;

        assert!(matches!(
            result,
            Err(GatewayError::Audit(AuditError::Write(_)))
        ));
        assert!(matches!(
            gateway.require_audit_available(),
            Err(GatewayError::AuditUnavailable)
        ));
        assert!(matches!(
            gateway.begin_forwarding().await,
            Err(GatewayError::AuditUnavailable)
        ));
    }

    /// Expected serialized empty body summary.
    fn empty_body_value() -> Value {
        Value::Object(Map::from_iter([(
            "state".to_owned(),
            Value::String("empty".to_owned()),
        )]))
    }

    /// Expected serialized non-empty body summary.
    fn non_empty_body_value(body: &[u8]) -> Value {
        Value::Object(Map::from_iter([
            (
                "blake3".to_owned(),
                Value::String(blake3::hash(body).to_hex().to_string()),
            ),
            (
                "bytes".to_owned(),
                Value::from(u64::try_from(body.len()).expect("test body length should fit u64")),
            ),
            ("state".to_owned(), Value::String("non_empty".to_owned())),
        ]))
    }

    /// Expected serialized unobserved body summary.
    fn not_observed_body_value() -> Value {
        Value::Object(Map::from_iter([(
            "state".to_owned(),
            Value::String("not_observed".to_owned()),
        )]))
    }

    #[tokio::test]
    async fn next_request_id_is_unique_per_request() {
        let directory = tempdir().expect("temporary directory should be created");
        let gateway = runtime_gateway(directory.path()).await;

        let first = gateway
            .next_request_id()
            .expect("first request id should allocate");
        let second = gateway
            .next_request_id()
            .expect("second request id should allocate");

        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn audit_denial_writes_a_denied_event() {
        let directory = tempdir().expect("temporary directory should be created");
        let gateway = runtime_gateway(directory.path()).await;

        gateway
            .audit_denial(
                RequestId::from_parts(
                    &RunToken::for_test("000000000000000a-000000000000000b"),
                    NonZeroU64::new(1).expect("sequence should be non-zero"),
                ),
                AuditDenial::connect_unsupported(PreparsedAuditTarget::from_request_uri(
                    &Uri::from_static("/"),
                )),
                None,
            )
            .await
            .expect("denial audit should be written");

        let event = &single_audit_event(directory.path()).await;
        assert_eq!(event["decision"], "denied");
        assert_eq!(event["error_class"], "connect_unsupported");
        assert_eq!(event["method"], "CONNECT");
        assert_eq!(event["path"], "/");
        assert_eq!(event["status"], 405_u16);
        assert_eq!(event["request_body"], not_observed_body_value());
    }

    #[tokio::test]
    async fn audit_denial_records_observed_empty_request_bodies() {
        let directory = tempdir().expect("temporary directory should be created");
        let gateway = runtime_gateway(directory.path()).await;
        let request_body = accounted_body(Body::empty()).await;

        gateway
            .audit_denial(
                RequestId::from_parts(
                    &RunToken::for_test("000000000000000a-000000000000000b"),
                    NonZeroU64::new(1).expect("sequence should be non-zero"),
                ),
                AuditDenial::allowlist_rejected(rejected_allowed_target(
                    gateway.config(),
                    &Method::DELETE,
                    "/v1/models",
                )),
                Some(&request_body),
            )
            .await
            .expect("denial audit should be written");

        let event = &single_audit_event(directory.path()).await;
        assert_eq!(event["request_body"], empty_body_value());
    }

    #[tokio::test]
    async fn audit_denial_records_the_request_body_digest() {
        let directory = tempdir().expect("temporary directory should be created");
        let gateway = runtime_gateway(directory.path()).await;
        let request_body = accounted_body(Body::from("hello")).await;

        gateway
            .audit_denial(
                RequestId::from_parts(
                    &RunToken::for_test("000000000000000a-000000000000000b"),
                    NonZeroU64::new(1).expect("sequence should be non-zero"),
                ),
                AuditDenial::allowlist_rejected(rejected_allowed_target(
                    gateway.config(),
                    &Method::POST,
                    "/v1/other",
                )),
                Some(&request_body),
            )
            .await
            .expect("denial audit should be written");

        let event = &single_audit_event(directory.path()).await;
        assert_eq!(event["request_body"], non_empty_body_value(b"hello"));
    }

    #[tokio::test]
    async fn audit_response_records_observed_empty_response_bodies() {
        let directory = tempdir().expect("temporary directory should be created");
        let gateway = runtime_gateway(directory.path()).await;
        let request_body = accounted_body(Body::empty()).await;
        let response_account = ResponseAccount::new(gateway.config().max_response_bytes());
        let target = allowed_target(&gateway, "/v1/models", None);
        let input = ResponseAuditInput::new(
            &target,
            ResponseAuditOutcome::allowed(&response_account, StatusCode::OK),
            &request_body,
            RequestId::from_parts(
                &RunToken::for_test("000000000000000a-000000000000000b"),
                NonZeroU64::new(1).expect("sequence should be non-zero"),
            ),
        );

        gateway
            .audit_response(input)
            .await
            .expect("response audit should be written");

        let event = &single_audit_event(directory.path()).await;
        assert_eq!(event["decision"], "allowed");
        assert_eq!(event["request_body"], empty_body_value());
        assert_eq!(event["response_body"], empty_body_value());
    }

    #[tokio::test]
    async fn audit_response_writes_an_allowed_event() {
        let directory = tempdir().expect("temporary directory should be created");
        let gateway = runtime_gateway(directory.path()).await;
        let request_body = accounted_body(Body::empty()).await;
        let mut response_account = ResponseAccount::new(gateway.config().max_response_bytes());
        response_account
            .add_chunk(b"world")
            .expect("response chunk should be accounted");
        let target = allowed_target(&gateway, "/v1/models", Some("q='"));
        let input = ResponseAuditInput::new(
            &target,
            ResponseAuditOutcome::allowed(&response_account, StatusCode::OK),
            &request_body,
            RequestId::from_parts(
                &RunToken::for_test("000000000000000a-000000000000000b"),
                NonZeroU64::new(1).expect("sequence should be non-zero"),
            ),
        );

        gateway
            .audit_response(input)
            .await
            .expect("response audit should be written");

        let event = &single_audit_event(directory.path()).await;
        assert_eq!(event["decision"], "allowed");
        assert_eq!(event["status"], 200_u16);
        assert_eq!(event["query"], "q='");
        assert_eq!(event["upstream_path"], "/v1/models");
        assert_eq!(event["upstream_query"], "q=%27");
        assert_eq!(event["request_body"], empty_body_value());
        assert_eq!(event["response_body"], non_empty_body_value(b"world"));
    }

    #[tokio::test]
    async fn config_returns_the_parsed_configuration() {
        let directory = tempdir().expect("temporary directory should be created");
        let gateway = runtime_gateway(directory.path()).await;

        let config = gateway.config();

        assert_eq!(config.upstream_origin().as_str(), "https://api.openai.com");
    }

    #[tokio::test]
    async fn failed_audit_marks_gateway_unavailable() {
        assert_failed_audit_marks_gateway_unavailable().await;
    }

    #[tokio::test]
    async fn proptests_failed_audit_marks_gateway_unavailable() {
        assert_failed_audit_marks_gateway_unavailable().await;
    }

    #[tokio::test]
    async fn production_gateway_fails_when_audit_log_is_a_directory() {
        let directory = tempdir().expect("temporary directory should be created");
        let config = GatewayConfig::for_runtime_test(
            directory.path().to_path_buf(),
            "https://api.openai.com",
        );

        let result = production_gateway(config).await;

        assert!(
            matches!(result, Err(GatewayError::Audit(AuditError::Open { .. }))),
            "a directory audit log should fail to open"
        );
    }
}
