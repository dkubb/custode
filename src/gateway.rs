//! Request handling state machine.

use crate::allowlist::AcceptedTarget;
use crate::audit::{
    AuditDenialReason, AuditError, AuditEvent, AuditEventInput, AuditRequestInput, AuditTarget,
    AuditUpstreamTarget, ObservedAuditRequestInput, ObservedBodySummary, RequestId,
};
use crate::body::{AccountedBody, BodyError, ResponseAccount};
use crate::config::GatewayConfig;
use crate::headers::HeaderError;
use crate::ports::{AuditSink, Clock, RequestIdSource};
use ::http::{Error as HttpError, Method, StatusCode};
use std::sync::Arc;
use thiserror::Error;

/// Shared gateway state.
#[derive(Clone, Debug)]
pub(crate) struct Gateway {
    /// Audit log writer.
    audit: Arc<dyn AuditSink>,
    /// Audit timestamp source.
    clock: Arc<dyn Clock>,
    /// Parsed gateway configuration.
    config: Arc<GatewayConfig>,
    /// Request identity source.
    request_ids: Arc<dyn RequestIdSource>,
}

/// Gateway runtime error.
#[derive(Debug, Error)]
pub(crate) enum GatewayError {
    /// Audit log failed.
    #[error("{0}")]
    Audit(#[from] AuditError),

    /// Body accounting failed.
    #[error("{0}")]
    Body(#[from] BodyError),

    /// Header filtering failed.
    #[error("{0}")]
    Header(#[from] HeaderError),

    /// Gateway response could not be built.
    #[error("failed to build response: {0}")]
    ResponseBuild(HttpError),
}

/// Input for response audit events.
#[derive(Debug)]
pub(crate) struct ResponseAuditInput {
    /// Method.
    pub method: String,
    /// Closed response audit outcome.
    pub outcome: ResponseAuditOutcome,
    /// Accounted request body.
    pub request_body: AccountedBody,
    /// Request identity.
    pub request_id: RequestId,
    /// Accepted target.
    pub target: AcceptedTarget,
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
        /// Response body summary.
        response_body: ObservedBodySummary,
        /// Response status returned to the harness.
        status: StatusCode,
    },

    /// Response headers failed before response body bytes were observed.
    ResponseHeaderError {
        /// Stable error class.
        error_class: &'static str,
        /// Response status returned to the harness.
        status: StatusCode,
    },

    /// Upstream request failed before a response completed.
    UpstreamError {
        /// Stable error class.
        error_class: &'static str,
        /// Response status returned to the harness.
        status: StatusCode,
    },

    /// Upstream response stream failed after upstream I/O started.
    UpstreamResponseStreamFailed {
        /// Response body summary.
        response_body: ObservedBodySummary,
        /// Response status returned to the harness.
        status: StatusCode,
    },
}

impl ResponseAuditOutcome {
    /// Creates an allowed response outcome.
    #[must_use]
    pub(crate) fn allowed(response_account: ResponseAccount, status: StatusCode) -> Self {
        Self {
            kind: ResponseAuditOutcomeKind::Allowed {
                response_body: ObservedBodySummary::from_response_account(response_account),
                status,
            },
        }
    }

    /// Creates a downstream-closed response outcome.
    #[must_use]
    pub(crate) fn downstream_closed(response_account: ResponseAccount, status: StatusCode) -> Self {
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
    pub(crate) fn response_body_too_large(
        response_account: ResponseAccount,
        status: StatusCode,
    ) -> Self {
        Self {
            kind: ResponseAuditOutcomeKind::ResponseBodyTooLarge {
                response_body: ObservedBodySummary::from_response_account(response_account),
                status,
            },
        }
    }

    /// Creates a response-header-error outcome.
    #[must_use]
    pub(crate) const fn response_header_error(
        error_class: &'static str,
        status: StatusCode,
    ) -> Self {
        Self {
            kind: ResponseAuditOutcomeKind::ResponseHeaderError {
                error_class,
                status,
            },
        }
    }

    /// Creates an upstream-error outcome.
    #[must_use]
    pub(crate) const fn upstream_error(error_class: &'static str, status: StatusCode) -> Self {
        Self {
            kind: ResponseAuditOutcomeKind::UpstreamError {
                error_class,
                status,
            },
        }
    }

    /// Creates an upstream-response-stream-failed outcome.
    #[must_use]
    pub(crate) fn upstream_response_stream_failed(
        response_account: ResponseAccount,
        status: StatusCode,
    ) -> Self {
        Self {
            kind: ResponseAuditOutcomeKind::UpstreamResponseStreamFailed {
                response_body: ObservedBodySummary::from_response_account(response_account),
                status,
            },
        }
    }
}

impl Gateway {
    /// Writes an audit event for a denied request.
    ///
    /// # Errors
    ///
    /// Returns an error when writing the audit event fails.
    pub(crate) async fn audit_denial(
        &self,
        request_id: RequestId,
        method: &Method,
        target: AuditTarget,
        request_body: Option<&AccountedBody>,
        reason: AuditDenialReason,
    ) -> Result<(), GatewayError> {
        let request = AuditRequestInput::for_denial(
            method.to_string(),
            target,
            request_id,
            request_body,
            self.config.upstream_origin().as_str().to_owned(),
        );
        let event = AuditEvent::new_at(AuditEventInput::denied(request, reason), self.clock.now());
        self.audit.append_event(&event).await?;
        Ok(())
    }

    /// Writes an audit event for a completed upstream response.
    ///
    /// # Errors
    ///
    /// Returns an error when writing the audit event fails.
    pub(crate) async fn audit_response(
        &self,
        input: ResponseAuditInput,
    ) -> Result<(), GatewayError> {
        let upstream = AuditUpstreamTarget::from(&input.target);
        let request = ObservedAuditRequestInput::new(
            input.method,
            input.target.into(),
            input.request_id,
            &input.request_body,
            self.config.upstream_origin().as_str().to_owned(),
        );
        let event_input = match input.outcome.into_kind() {
            ResponseAuditOutcomeKind::Allowed {
                response_body,
                status,
            } => AuditEventInput::allowed(request, response_body, status, upstream),
            ResponseAuditOutcomeKind::DownstreamClosed {
                response_body,
                status,
            } => AuditEventInput::response_error(
                request,
                "downstream_closed",
                response_body,
                status,
                upstream,
            ),
            ResponseAuditOutcomeKind::ResponseBodyTooLarge {
                response_body,
                status,
            } => AuditEventInput::response_error(
                request,
                "response_body_too_large",
                response_body,
                status,
                upstream,
            ),
            ResponseAuditOutcomeKind::ResponseHeaderError {
                error_class,
                status,
            } => {
                AuditEventInput::response_error_without_body(request, error_class, status, upstream)
            }
            ResponseAuditOutcomeKind::UpstreamResponseStreamFailed {
                response_body,
                status,
            } => AuditEventInput::response_error(
                request,
                "upstream_response_stream_failed",
                response_body,
                status,
                upstream,
            ),
            ResponseAuditOutcomeKind::UpstreamError {
                error_class,
                status,
            } => AuditEventInput::upstream_error(request, error_class, status, upstream),
        };
        let event = AuditEvent::new_at(event_input, self.clock.now());
        self.audit.append_event(&event).await?;
        Ok(())
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
            clock: Arc::new(clock),
            config: Arc::new(config),
            request_ids: Arc::new(request_ids),
        }
    }

    /// Allocates a request identity unique within the audit log.
    ///
    /// The identity embeds a per-process run token so identities from
    /// different gateway runs appended to the same audit log do not collide.
    #[must_use]
    pub(crate) fn next_request_id(&self) -> RequestId {
        self.request_ids.next_request_id()
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
    use crate::allowlist::AcceptedTarget;
    use crate::audit::{AuditDenialReason, AuditError, AuditTarget, AuditWriter, RequestId};
    use crate::body::{AccountedBody, ResponseAccount};
    use crate::config::GatewayConfig;
    use ::http::{Method, StatusCode};
    use axum::body::Body;
    use core::num::NonZeroUsize;
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
            SequentialRequestIds::production(),
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
        AccountedBody::read_request(
            body,
            NonZeroUsize::new(1_024).expect("limit should be non-zero"),
        )
        .await
        .expect("request body should be accounted")
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

        let first = gateway.next_request_id();
        let second = gateway.next_request_id();

        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn audit_denial_writes_a_denied_event() {
        let directory = tempdir().expect("temporary directory should be created");
        let gateway = runtime_gateway(directory.path()).await;

        gateway
            .audit_denial(
                RequestId::from_parts("run", 1),
                &Method::CONNECT,
                AuditTarget::from_uri_parts("/", None),
                None,
                AuditDenialReason::ConnectUnsupported,
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
                RequestId::from_parts("run", 1),
                &Method::DELETE,
                AuditTarget::from_uri_parts("/v1/models", None),
                Some(&request_body),
                AuditDenialReason::MethodDenied,
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
                RequestId::from_parts("run", 1),
                &Method::POST,
                AuditTarget::from_uri_parts("/v1/other", None),
                Some(&request_body),
                AuditDenialReason::PathDenied,
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
        let input = ResponseAuditInput {
            method: "GET".to_owned(),
            outcome: ResponseAuditOutcome::allowed(response_account, StatusCode::OK),
            request_body,
            request_id: RequestId::from_parts("run", 1),
            target: AcceptedTarget::new("/v1/models", None).expect("target should parse"),
        };

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
        let input = ResponseAuditInput {
            method: "GET".to_owned(),
            outcome: ResponseAuditOutcome::allowed(response_account, StatusCode::OK),
            request_body,
            request_id: RequestId::from_parts("run", 1),
            target: AcceptedTarget::new("/v1/models", Some("limit=1"))
                .expect("target should parse"),
        };

        gateway
            .audit_response(input)
            .await
            .expect("response audit should be written");

        let event = &single_audit_event(directory.path()).await;
        assert_eq!(event["decision"], "allowed");
        assert_eq!(event["status"], 200_u16);
        assert_eq!(event["upstream_path"], "/v1/models");
        assert_eq!(event["upstream_query"], "limit=1");
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
