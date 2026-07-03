//! Audit event schema and writer.

use crate::allowlist::AcceptedTarget;
use crate::body::{AccountedBody, BodyDigest, ResponseAccount};
use crate::config::{GatewayConfig, UpstreamOrigin};
use ::http::{Method, StatusCode};
use core::num::{NonZeroU64, NonZeroUsize};
use serde::Serialize;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use thiserror::Error;
use tokio::fs::{File, OpenOptions, create_dir_all};
use tokio::io::{AsyncWrite, AsyncWriteExt as _};
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

/// Closed reason for a denied request audit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuditDenialReason {
    /// Request target included a scheme or authority.
    AbsoluteFormUnsupported,

    /// `CONNECT` is never accepted.
    ConnectUnsupported,

    /// Path contained a literal or percent-encoded dot segment.
    DotSegment,

    /// Path contained invalid percent-encoding.
    InvalidPercentEncoding,

    /// Request had an invalid `Connection` header.
    InvalidRequestConnectionHeader,

    /// Method was not in the allowlist.
    MethodDenied,

    /// Target was not an origin-form path.
    NonOriginForm,

    /// Path was not in the allowlist.
    PathDenied,

    /// Request body could not be read.
    RequestBodyReadFailed,

    /// Request body was not received before the configured timeout.
    RequestBodyTimeout,

    /// Request body exceeded the configured limit.
    RequestBodyTooLarge,

    /// Request headers exceeded the configured limit.
    RequestHeadersTooLarge,

    /// Gateway request concurrency was exhausted.
    TooManyRequests,
}

/// Closed response-error audit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuditResponseError {
    /// Closed response-error kind.
    kind: AuditResponseErrorKind,
}

/// Closed response-error audit event variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditResponseErrorKind {
    /// Downstream closed before the response completed.
    DownstreamClosed {
        /// Response body summary.
        response_body: ObservedBodySummary,
        /// Response status returned to the harness.
        status: StatusCode,
    },

    /// Response body exceeded the configured byte limit.
    ResponseBodyTooLarge {
        /// Accepted response body prefix.
        response_body: ResponseBodyPrefix,
        /// Response status returned to the harness.
        status: StatusCode,
    },

    /// Response headers failed before response body bytes were observed.
    ResponseHeader {
        /// Header failure class.
        error: AuditResponseHeaderError,
    },

    /// Upstream response stream failed after upstream I/O started.
    UpstreamResponseStreamFailed {
        /// Response body summary.
        response_body: ObservedBodySummary,
        /// Response status returned to the harness.
        status: StatusCode,
    },
}

/// Closed response-header audit error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuditResponseHeaderError {
    /// Response `Connection` header contained an invalid dynamic header name.
    InvalidConnectionHeader,

    /// Response headers exceeded the configured byte limit.
    TooLarge,
}

/// Closed upstream request audit error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuditUpstreamError {
    /// Gateway could not connect to the upstream.
    Connect,

    /// Upstream request failed after connection setup.
    Request,

    /// Upstream request timed out.
    Timeout,
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
    /// Request body summary.
    request_body: AuditBodySummary,
    /// Request identity.
    request_id: RequestId,
    /// Response body summary.
    response_body: AuditBodySummary,
    /// Response status returned to the harness.
    status: u16,
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
#[serde(transparent)]
struct AuditBodySummary {
    /// Closed body-summary state.
    kind: AuditBodySummaryKind,
}

/// Closed body accounting summary recorded in audit events.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum AuditBodySummaryKind {
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

/// Observed body summary recorded in audit events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ObservedBodySummary {
    /// Observed body summary.
    summary: AuditBodySummary,
}

/// Accepted response prefix for oversized response-body failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseBodyPrefix {
    /// A non-empty response prefix was accepted before the limit failure.
    Accepted(ObservedBodySummary),

    /// No response bytes were accepted before the limit failure.
    NoneAccepted,
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
struct AuditOutcome {
    /// Closed audit outcome kind.
    kind: AuditOutcomeKind,
}

/// Closed audit outcome variants.
#[derive(Clone, Debug, Eq, PartialEq)]
enum AuditOutcomeKind {
    /// Request was allowed and completed normally.
    Allowed {
        /// Response body summary.
        response_body: ObservedBodySummary,
        /// Response status returned to the harness.
        status: StatusCode,
        /// Upstream target.
        upstream: AuditUpstreamTarget,
    },

    /// Request was denied before upstream I/O.
    Denied {
        /// Denial reason.
        reason: AuditDenialReason,
    },

    /// Response handling failed.
    ResponseError {
        /// Response error.
        error: AuditResponseError,
        /// Upstream target.
        upstream: AuditUpstreamTarget,
    },

    /// Upstream request failed before a response completed.
    UpstreamError {
        /// Upstream error.
        error: AuditUpstreamError,
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
    method: Method,
    /// Request identity.
    request_id: RequestId,
    /// Accepted or raw audit target.
    target: AuditTarget,
    /// Configured upstream origin.
    upstream_origin: UpstreamOrigin,
}

/// Request context for an audit event after the request body was observed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedAuditRequestInput {
    /// Request context common to every audit event.
    request: AuditRequestInput,
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
    max_event_bytes: NonZeroUsize,
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
    const fn empty() -> Self {
        Self {
            kind: AuditBodySummaryKind::Empty,
        }
    }

    /// Creates an observed body summary from a request body.
    #[must_use]
    fn from_request_body(request_body: &AccountedBody) -> Self {
        request_body.digest().map_or_else(Self::empty, |digest| {
            Self::non_empty(
                digest,
                NonZeroU64::new(request_body.byte_count())
                    .expect("request body digest requires non-zero bytes"),
            )
        })
    }

    /// Creates a non-empty body summary.
    #[must_use]
    const fn non_empty(blake3: BodyDigest, bytes: NonZeroU64) -> Self {
        Self {
            kind: AuditBodySummaryKind::NonEmpty { blake3, bytes },
        }
    }

    /// Creates an unobserved body summary.
    #[must_use]
    const fn not_observed() -> Self {
        Self {
            kind: AuditBodySummaryKind::NotObserved,
        }
    }
}

impl ObservedBodySummary {
    /// Creates an observed body summary from a response body account.
    #[must_use]
    pub(crate) fn from_response_account(response_account: ResponseAccount) -> Self {
        let (byte_count, response_digest) = response_account.into_digest_parts();
        let summary = response_digest.map_or_else(AuditBodySummary::empty, |digest| {
            AuditBodySummary::non_empty(
                digest,
                NonZeroU64::new(byte_count).expect("response body digest requires non-zero bytes"),
            )
        });
        Self { summary }
    }

    /// Returns the underlying audit body summary.
    #[must_use]
    const fn into_summary(self) -> AuditBodySummary {
        self.summary
    }
}

impl ResponseBodyPrefix {
    /// Creates a prefix summary from accepted response bytes.
    #[must_use]
    pub(crate) fn from_response_account(response_account: ResponseAccount) -> Self {
        let (byte_count, response_digest) = response_account.into_digest_parts();
        response_digest.map_or(Self::NoneAccepted, |digest| {
            Self::Accepted(ObservedBodySummary {
                summary: AuditBodySummary::non_empty(
                    digest,
                    NonZeroU64::new(byte_count)
                        .expect("response body digest requires non-zero bytes"),
                ),
            })
        })
    }

    /// Consumes the prefix into its audit body summary.
    #[must_use]
    const fn into_summary(self) -> AuditBodySummary {
        match self {
            Self::NoneAccepted => AuditBodySummary::not_observed(),
            Self::Accepted(summary) => summary.into_summary(),
        }
    }
}

impl AuditDenialReason {
    /// Returns the stable audit error class.
    #[must_use]
    const fn error_class(self) -> &'static str {
        match self {
            Self::AbsoluteFormUnsupported => "absolute_form_unsupported",
            Self::ConnectUnsupported => "connect_unsupported",
            Self::DotSegment => "dot_segment",
            Self::InvalidPercentEncoding => "invalid_percent_encoding",
            Self::InvalidRequestConnectionHeader => "invalid_request_connection_header",
            Self::MethodDenied => "method_denied",
            Self::NonOriginForm => "non_origin_form",
            Self::PathDenied => "path_denied",
            Self::RequestBodyReadFailed => "request_body_read_failed",
            Self::RequestBodyTimeout => "request_body_timeout",
            Self::RequestBodyTooLarge => "request_body_too_large",
            Self::RequestHeadersTooLarge => "request_headers_too_large",
            Self::TooManyRequests => "too_many_requests",
        }
    }

    /// Returns the response status for this denial.
    #[must_use]
    pub(crate) const fn status(self) -> StatusCode {
        match self {
            Self::AbsoluteFormUnsupported
            | Self::DotSegment
            | Self::InvalidPercentEncoding
            | Self::InvalidRequestConnectionHeader
            | Self::NonOriginForm
            | Self::RequestBodyReadFailed => StatusCode::BAD_REQUEST,
            Self::ConnectUnsupported => StatusCode::METHOD_NOT_ALLOWED,
            Self::MethodDenied | Self::PathDenied => StatusCode::FORBIDDEN,
            Self::RequestBodyTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::RequestBodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RequestHeadersTooLarge => StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
        }
    }
}

impl AuditResponseError {
    /// Creates a downstream-closed response error.
    #[must_use]
    pub(crate) const fn downstream_closed(
        response_body: ObservedBodySummary,
        status: StatusCode,
    ) -> Self {
        Self {
            kind: AuditResponseErrorKind::DownstreamClosed {
                response_body,
                status,
            },
        }
    }

    /// Consumes the response error into serialized audit parts.
    #[must_use]
    const fn into_parts(self) -> (&'static str, AuditBodySummary, StatusCode) {
        match self.kind {
            AuditResponseErrorKind::DownstreamClosed {
                response_body,
                status,
            } => ("downstream_closed", response_body.into_summary(), status),
            AuditResponseErrorKind::ResponseBodyTooLarge {
                response_body,
                status,
            } => (
                "response_body_too_large",
                response_body.into_summary(),
                status,
            ),
            AuditResponseErrorKind::ResponseHeader { error } => (
                error.error_class(),
                AuditBodySummary::not_observed(),
                error.status(),
            ),
            AuditResponseErrorKind::UpstreamResponseStreamFailed {
                response_body,
                status,
            } => (
                "upstream_response_stream_failed",
                response_body.into_summary(),
                status,
            ),
        }
    }

    /// Creates a response-body-too-large response error.
    #[must_use]
    pub(crate) const fn response_body_too_large(
        response_body: ResponseBodyPrefix,
        status: StatusCode,
    ) -> Self {
        Self {
            kind: AuditResponseErrorKind::ResponseBodyTooLarge {
                response_body,
                status,
            },
        }
    }

    /// Creates a response-header response error.
    #[must_use]
    pub(crate) const fn response_header(error: AuditResponseHeaderError) -> Self {
        Self {
            kind: AuditResponseErrorKind::ResponseHeader { error },
        }
    }

    /// Creates an upstream-response-stream-failed response error.
    #[must_use]
    pub(crate) const fn upstream_response_stream_failed(
        response_body: ObservedBodySummary,
        status: StatusCode,
    ) -> Self {
        Self {
            kind: AuditResponseErrorKind::UpstreamResponseStreamFailed {
                response_body,
                status,
            },
        }
    }
}

impl AuditResponseHeaderError {
    /// Returns the stable audit error class.
    #[must_use]
    const fn error_class(self) -> &'static str {
        match self {
            Self::InvalidConnectionHeader => "invalid_response_connection_header",
            Self::TooLarge => "response_headers_too_large",
        }
    }

    /// Returns the response status for this response-header failure.
    #[must_use]
    pub(crate) const fn status(self) -> StatusCode {
        match self {
            Self::InvalidConnectionHeader | Self::TooLarge => StatusCode::BAD_GATEWAY,
        }
    }
}

impl AuditUpstreamError {
    /// Returns the stable audit error class.
    #[must_use]
    const fn error_class(self) -> &'static str {
        match self {
            Self::Connect => "upstream_connect_failed",
            Self::Request => "upstream_request_failed",
            Self::Timeout => "upstream_timeout",
        }
    }

    /// Returns the response status for this upstream failure.
    #[must_use]
    pub(crate) const fn status(self) -> StatusCode {
        match self {
            Self::Connect | Self::Request => StatusCode::BAD_GATEWAY,
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }
}

impl AuditEventInput {
    /// Creates an allowed audit event input.
    #[must_use]
    pub(crate) fn allowed(
        request: ObservedAuditRequestInput,
        response_body: ObservedBodySummary,
        status: StatusCode,
        upstream: AuditUpstreamTarget,
    ) -> Self {
        let outcome = AuditOutcome::allowed(response_body, status, upstream);
        Self {
            outcome,
            request: request.into_request(),
        }
    }

    /// Creates a denied audit event input.
    #[must_use]
    pub(crate) const fn denied(request: AuditRequestInput, reason: AuditDenialReason) -> Self {
        let outcome = AuditOutcome::denied(reason);
        Self { outcome, request }
    }

    /// Creates an audit event input from request context and outcome.
    #[cfg(test)]
    #[must_use]
    const fn new(request: AuditRequestInput, outcome: AuditOutcome) -> Self {
        Self { outcome, request }
    }

    /// Creates a response-error audit event input.
    #[must_use]
    pub(crate) fn response_error(
        request: ObservedAuditRequestInput,
        error: AuditResponseError,
        upstream: AuditUpstreamTarget,
    ) -> Self {
        let outcome = AuditOutcome::response_error(error, upstream);
        Self {
            outcome,
            request: request.into_request(),
        }
    }

    /// Creates an upstream-error audit event input.
    #[must_use]
    pub(crate) fn upstream_error(
        request: ObservedAuditRequestInput,
        error: AuditUpstreamError,
        upstream: AuditUpstreamTarget,
    ) -> Self {
        let outcome = AuditOutcome::upstream_error(error, upstream);
        Self {
            outcome,
            request: request.into_request(),
        }
    }
}

impl AuditOutcome {
    /// Creates an allowed outcome.
    #[must_use]
    const fn allowed(
        response_body: ObservedBodySummary,
        status: StatusCode,
        upstream: AuditUpstreamTarget,
    ) -> Self {
        Self {
            kind: AuditOutcomeKind::Allowed {
                response_body,
                status,
                upstream,
            },
        }
    }

    /// Creates a denied outcome.
    #[must_use]
    const fn denied(reason: AuditDenialReason) -> Self {
        Self {
            kind: AuditOutcomeKind::Denied { reason },
        }
    }

    /// Consumes the outcome into its closed variant.
    #[must_use]
    fn into_kind(self) -> AuditOutcomeKind {
        self.kind
    }

    /// Creates a response-error outcome.
    #[must_use]
    const fn response_error(error: AuditResponseError, upstream: AuditUpstreamTarget) -> Self {
        Self {
            kind: AuditOutcomeKind::ResponseError { error, upstream },
        }
    }

    /// Creates an upstream-error outcome.
    #[must_use]
    const fn upstream_error(error: AuditUpstreamError, upstream: AuditUpstreamTarget) -> Self {
        Self {
            kind: AuditOutcomeKind::UpstreamError { error, upstream },
        }
    }
}

impl AuditRequestInput {
    /// Creates request context for denial events.
    #[must_use]
    pub(crate) fn for_denial(
        method: Method,
        target: AuditTarget,
        request_id: RequestId,
        body: Option<&AccountedBody>,
        upstream_origin: UpstreamOrigin,
    ) -> Self {
        Self::new(
            method,
            target,
            request_id,
            body.map_or_else(
                AuditBodySummary::not_observed,
                AuditBodySummary::from_request_body,
            ),
            upstream_origin,
        )
    }

    /// Creates request context common to every audit event.
    #[must_use]
    const fn new(
        method: Method,
        target: AuditTarget,
        request_id: RequestId,
        body: AuditBodySummary,
        upstream_origin: UpstreamOrigin,
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

impl ObservedAuditRequestInput {
    /// Consumes the observed wrapper into generic request context.
    #[must_use]
    fn into_request(self) -> AuditRequestInput {
        self.request
    }

    /// Creates request context after the request body was observed.
    #[must_use]
    pub(crate) fn new(
        method: Method,
        target: AuditTarget,
        request_id: RequestId,
        body: &AccountedBody,
        upstream_origin: UpstreamOrigin,
    ) -> Self {
        let request = AuditRequestInput::new(
            method,
            target,
            request_id,
            AuditBodySummary::from_request_body(body),
            upstream_origin,
        );
        Self { request }
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

impl From<&AcceptedTarget> for AuditTarget {
    fn from(target: &AcceptedTarget) -> Self {
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
        let (decision, error_class, response_body, status, upstream) = match outcome.into_kind() {
            AuditOutcomeKind::Allowed {
                response_body,
                status,
                upstream,
            } => (
                AuditDecision::Allowed,
                None,
                response_body.into_summary(),
                status.as_u16(),
                Some(upstream),
            ),
            AuditOutcomeKind::Denied { reason } => (
                AuditDecision::Denied,
                Some(reason.error_class().to_owned()),
                AuditBodySummary::not_observed(),
                reason.status().as_u16(),
                None,
            ),
            AuditOutcomeKind::ResponseError { error, upstream } => {
                let (error_class, response_body, status) = error.into_parts();
                (
                    AuditDecision::ResponseError,
                    Some(error_class.to_owned()),
                    response_body,
                    status.as_u16(),
                    Some(upstream),
                )
            }
            AuditOutcomeKind::UpstreamError { error, upstream } => (
                AuditDecision::UpstreamError,
                Some(error.error_class().to_owned()),
                AuditBodySummary::not_observed(),
                error.status().as_u16(),
                Some(upstream),
            ),
        };
        let (upstream_path, upstream_query) = match upstream {
            Some(upstream_target) => (Some(upstream_target.path), upstream_target.query),
            None => (None, None),
        };
        Self {
            decision,
            error_class,
            method: method.to_string(),
            path: target.path().to_owned(),
            query: target.query().map(str::to_owned),
            request_body,
            request_id,
            response_body,
            status,
            timestamp,
            upstream_origin: upstream_origin.as_str().to_owned(),
            upstream_path,
            upstream_query,
            version: 3,
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
            max_event_bytes: config.max_audit_event_bytes(),
        })
    }

    /// Writes one required audit event.
    ///
    /// # Errors
    ///
    /// Returns an error when the event exceeds the byte limit or writing fails.
    pub(crate) async fn write_event(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let serialized = serialize_event(event, self.max_event_bytes)?;

        let mut file = self.file.lock().await;
        let result = write_serialized_event(&mut *file, &serialized).await;
        drop(file);
        result
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

/// Serializes one bounded audit event as NDJSON bytes.
fn serialize_event(
    event: &AuditEvent,
    max_event_bytes: NonZeroUsize,
) -> Result<Vec<u8>, AuditError> {
    let mut serialized = serialize_json_event(event);
    let max = max_event_bytes.get();
    if serialized.len() > max {
        return Err(AuditError::EventTooLarge {
            bytes: serialized.len(),
            max,
        });
    }
    serialized.push(b'\n');
    Ok(serialized)
}

/// Serializes the current audit event schema.
fn serialize_json_event(event: &AuditEvent) -> Vec<u8> {
    serde_json::to_vec(event).expect("audit events contain only infallible JSON values")
}

/// Writes serialized audit bytes to the supplied writer.
async fn write_serialized_event<W>(writer: &mut W, serialized: &[u8]) -> Result<(), AuditError>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(serialized)
        .await
        .map_err(AuditError::Write)?;
    writer.flush().await.map_err(AuditError::Write)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[expect(
    clippy::inline_modules,
    reason = "inline tests keep file-local coverage ownership explicit"
)]
mod tests {
    use super::{
        AuditBodySummary, AuditDecision, AuditDenialReason, AuditError, AuditEvent,
        AuditEventInput, AuditOutcome, AuditRequestInput, AuditTarget, AuditTimestamp, AuditWriter,
        ObservedBodySummary, RequestId, ResponseBodyPrefix, write_serialized_event,
    };
    use crate::allowlist::AcceptedTarget;
    use crate::body::{BodyDigest, ResponseAccount};
    use crate::config::{GatewayConfig, UpstreamOrigin};
    use ::http::Method;
    use core::num::{NonZeroU64, NonZeroUsize};
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use core::time::Duration;
    use pretty_assertions::assert_eq;
    use serde_json::{Map, Value};
    use std::path::{Path, PathBuf};
    use std::time::UNIX_EPOCH;
    use std::{fs, io};
    use tempfile::tempdir;
    use tokio::io::AsyncWrite;

    /// Test writer that fails one write operation class.
    #[derive(Debug)]
    struct FailingWriter {
        /// Operation that should fail.
        failure: WriterFailure,
    }

    /// Test writer failure mode.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum WriterFailure {
        /// Fail flushes.
        Flush,

        /// Fail writes.
        Write,
    }

    impl AsyncWrite for FailingWriter {
        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.failure {
                WriterFailure::Flush => Poll::Ready(Err(io::Error::other("flush failed"))),
                WriterFailure::Write => Poll::Ready(Ok(())),
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.failure {
                WriterFailure::Flush => Poll::Ready(Ok(buf.len())),
                WriterFailure::Write => Poll::Ready(Err(io::Error::other("write failed"))),
            }
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            match self.failure {
                WriterFailure::Flush => {
                    let bytes = bufs.iter().map(|buf| buf.len()).sum();
                    Poll::Ready(Ok(bytes))
                }
                WriterFailure::Write => Poll::Ready(Err(io::Error::other("write failed"))),
            }
        }
    }

    /// Builds common request audit input for tests.
    fn request_input(
        method: &str,
        target: AuditTarget,
        body: AuditBodySummary,
    ) -> AuditRequestInput {
        AuditRequestInput::new(
            Method::from_bytes(method.as_bytes()).expect("test method should parse"),
            target,
            RequestId::from_parts("run", 1),
            body,
            UpstreamOrigin::parse("https://api.openai.com").expect("origin should parse"),
        )
    }

    /// Builds a denied audit input for tests.
    fn denied_input(
        method: &str,
        target: AuditTarget,
        reason: AuditDenialReason,
    ) -> AuditEventInput {
        AuditEventInput::new(
            request_input(method, target, AuditBodySummary::empty()),
            AuditOutcome::denied(reason),
        )
    }

    /// Builds a denied-decision event for writer tests.
    fn denied_event() -> AuditEvent {
        AuditEvent::new(denied_input(
            "DELETE",
            AuditTarget::from_uri_parts("/v1/models", None),
            AuditDenialReason::MethodDenied,
        ))
    }

    /// Expected serialized empty body summary.
    fn empty_body_value() -> Value {
        Value::Object(Map::from_iter([(
            "state".to_owned(),
            Value::String("empty".to_owned()),
        )]))
    }

    /// Expected serialized unobserved body summary.
    fn not_observed_body_value() -> Value {
        Value::Object(Map::from_iter([(
            "state".to_owned(),
            Value::String("not_observed".to_owned()),
        )]))
    }

    /// A roomy audit event limit for tests that should not hit the bound.
    fn roomy_event_limit() -> NonZeroUsize {
        NonZeroUsize::new(0x4000).expect("limit should be non-zero")
    }

    #[test]
    fn response_body_prefix_records_accepted_bytes() {
        let mut account =
            ResponseAccount::new(NonZeroU64::new(16).expect("limit should be non-zero"));
        account
            .add_chunk(b"accepted")
            .expect("chunk should fit under the limit");

        let prefix = ResponseBodyPrefix::from_response_account(account);

        assert_eq!(
            prefix,
            ResponseBodyPrefix::Accepted(ObservedBodySummary {
                summary: AuditBodySummary::non_empty(
                    BodyDigest::from_bytes(b"accepted"),
                    NonZeroU64::new(8).expect("accepted body should be non-empty"),
                ),
            }),
        );
    }

    #[test]
    fn new_preserves_status() {
        let input = denied_input(
            "CONNECT",
            AuditTarget::from_uri_parts("/v1/models", None),
            AuditDenialReason::ConnectUnsupported,
        );

        let event = AuditEvent::new(input);
        let expected = 405;

        assert_eq!(event.status, expected);
    }

    #[test]
    fn new_preserves_rejected_raw_path() {
        let target = AuditTarget::from_uri_parts("/v1/responses/%2e%2e/models", Some("limit=1"));
        let input = denied_input("GET", target, AuditDenialReason::DotSegment);

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
            AuditDenialReason::MethodDenied,
        );

        let value = serde_json::to_value(AuditEvent::new(input)).expect("event should serialize");

        let object = value.as_object().expect("event should be a JSON object");
        let expected_fields = [
            "decision",
            "error_class",
            "method",
            "path",
            "query",
            "request_body",
            "request_id",
            "response_body",
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
        assert_eq!(object["version"], 3_u64);
        assert_eq!(object["decision"], "denied");
        assert_eq!(object["request_id"], "req-run-0000000000000001");
        assert!(object["upstream_path"].is_null());
        assert!(object["upstream_query"].is_null());
        assert!(object["query"].is_null());
        assert_eq!(object["request_body"], empty_body_value());
        assert_eq!(object["response_body"], not_observed_body_value());
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

    #[tokio::test]
    async fn write_serialized_event_reports_write_failures() {
        let mut writer = FailingWriter {
            failure: WriterFailure::Write,
        };

        let result = write_serialized_event(&mut writer, b"{\"version\":3}\n").await;

        assert!(matches!(result, Err(AuditError::Write(_))));
    }

    #[tokio::test]
    async fn write_serialized_event_reports_flush_failures() {
        let mut writer = FailingWriter {
            failure: WriterFailure::Flush,
        };

        let result = write_serialized_event(&mut writer, b"{\"version\":3}\n").await;

        assert!(matches!(result, Err(AuditError::Write(_))));
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
        AuditBodySummary, AuditDenialReason, AuditEvent, AuditEventInput, AuditOutcome,
        AuditRequestInput, AuditResponseError, AuditResponseHeaderError, AuditTarget,
        AuditUpstreamError, AuditUpstreamTarget, ObservedBodySummary, RequestId,
        ResponseBodyPrefix,
    };
    use crate::allowlist::AcceptedTarget;
    use crate::body::BodyDigest;
    use crate::config::UpstreamOrigin;
    use ::http::Method;
    use ::http::StatusCode;
    use core::num::NonZeroU64;
    use core::time::Duration;
    use proptest::prelude::*;
    use proptest::{collection, option};
    use serde_json::{Map, Value};
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

    /// Returns an observed body summary for observed bytes.
    fn observed_body_summary(bytes: &[u8]) -> ObservedBodySummary {
        ObservedBodySummary {
            summary: body_summary(bytes),
        }
    }

    /// Returns the serialized non-empty body summary for observed bytes.
    fn body_value(bytes: u64, digest: &str) -> Value {
        Value::Object(Map::from_iter([
            ("blake3".to_owned(), Value::String(digest.to_owned())),
            ("bytes".to_owned(), Value::from(bytes)),
            ("state".to_owned(), Value::String("non_empty".to_owned())),
        ]))
    }

    /// Generates observed non-empty body bytes.
    fn non_empty_body() -> impl Strategy<Value = Vec<u8>> {
        collection::vec(any::<u8>(), 1..33)
    }

    /// Returns a parsed method from generated method text.
    fn method_value(method: &str) -> Method {
        Method::from_bytes(method.as_bytes()).expect("generated method should parse")
    }

    /// Returns one closed denial reason from a generated index.
    const fn denial_reason(index: u8) -> AuditDenialReason {
        match index {
            0 => AuditDenialReason::AbsoluteFormUnsupported,
            1 => AuditDenialReason::ConnectUnsupported,
            2 => AuditDenialReason::DotSegment,
            3 => AuditDenialReason::InvalidPercentEncoding,
            4 => AuditDenialReason::InvalidRequestConnectionHeader,
            5 => AuditDenialReason::MethodDenied,
            6 => AuditDenialReason::NonOriginForm,
            7 => AuditDenialReason::PathDenied,
            8 => AuditDenialReason::RequestBodyReadFailed,
            9 => AuditDenialReason::RequestBodyTimeout,
            10 => AuditDenialReason::RequestBodyTooLarge,
            11 => AuditDenialReason::RequestHeadersTooLarge,
            _ => AuditDenialReason::TooManyRequests,
        }
    }

    /// Returns one closed response-header error from a generated index.
    const fn response_header_error(index: u8) -> AuditResponseHeaderError {
        match index {
            0 => AuditResponseHeaderError::InvalidConnectionHeader,
            _ => AuditResponseHeaderError::TooLarge,
        }
    }

    /// Returns one closed upstream error from a generated index.
    const fn upstream_error(index: u8) -> AuditUpstreamError {
        match index {
            0 => AuditUpstreamError::Timeout,
            1 => AuditUpstreamError::Connect,
            _ => AuditUpstreamError::Request,
        }
    }

    /// Returns the serialized audit body summary for unobserved body bytes.
    fn not_observed_body_value() -> Value {
        Value::Object(Map::from_iter([(
            "state".to_owned(),
            Value::String("not_observed".to_owned()),
        )]))
    }

    /// Raw request paths: origin-form spellings biased with the empty path
    /// that `from_uri_parts` replaces with `/`.
    fn raw_path() -> impl Strategy<Value = String> {
        prop_oneof![
            4 => "/[A-Za-z0-9/_-]{0,20}",
            1 => Just(String::new()),
        ]
    }

    /// Returns a valid HTTP status code from a generated code.
    fn status_code(code: u16) -> StatusCode {
        StatusCode::from_u16(code).expect("generated status code should be valid")
    }

    /// Returns the fixed upstream origin used by serialization proptests.
    fn upstream_origin() -> UpstreamOrigin {
        UpstreamOrigin::parse("https://api.openai.com").expect("origin should parse")
    }

    proptest! {
        #[test]
        fn event_serialization_preserves_variant_semantics(
            outcome_kind in 0_u8..4,
            denial_kind in 0_u8..13,
            response_error_kind in 0_u8..5,
            upstream_error_kind in 0_u8..3,
            method in "[A-Z]{3,8}",
            path in raw_path(),
            query in option::of("[a-z]{1,5}=[a-z]{1,5}"),
            upstream_path in "/[A-Za-z0-9/_-]{0,20}",
            upstream_query in option::of("[a-z]{1,5}=[a-z]{1,5}"),
            status_code_value in 100_u16..600,
            request_body_bytes in non_empty_body(),
            response_body_bytes in non_empty_body(),
            run_token in "[0-9a-f]{1,16}",
            sequence in any::<u64>(),
        ) {
            let status = status_code(status_code_value);
            let request_body = body_summary(&request_body_bytes);
            let request_bytes = body_len(&request_body_bytes);
            let request_digest = BodyDigest::from_bytes(&request_body_bytes).to_hex_string();
            let observed_response_body = observed_body_summary(&response_body_bytes);
            let response_bytes = body_len(&response_body_bytes);
            let response_digest = BodyDigest::from_bytes(&response_body_bytes).to_hex_string();
            let upstream =
                AuditUpstreamTarget::new(upstream_path.clone(), upstream_query.clone());
            let (
                outcome,
                decision,
                expected_error,
                expected_response_body,
                expected_status,
                expected_upstream,
            ) = match outcome_kind {
                0 => (
                    AuditOutcome::allowed(observed_response_body, status, upstream),
                    "allowed",
                    None,
                    body_value(response_bytes, &response_digest),
                    status.as_u16(),
                    Some((upstream_path.as_str(), upstream_query.as_deref())),
                ),
                1 => {
                    let reason = denial_reason(denial_kind);
                    (
                        AuditOutcome::denied(reason),
                        "denied",
                        Some(reason.error_class()),
                        not_observed_body_value(),
                        reason.status().as_u16(),
                        None,
                    )
                }
                2 => {
                    let (error, expected_body) = match response_error_kind {
                        0 => (
                            AuditResponseError::downstream_closed(
                                observed_response_body,
                                status,
                            ),
                            body_value(response_bytes, &response_digest),
                        ),
                        1 => (
                            AuditResponseError::response_body_too_large(
                                ResponseBodyPrefix::Accepted(observed_response_body),
                                status,
                            ),
                            body_value(response_bytes, &response_digest),
                        ),
                        2 => (
                            AuditResponseError::response_header(response_header_error(0)),
                            not_observed_body_value(),
                        ),
                        3 => (
                            AuditResponseError::response_header(response_header_error(1)),
                            not_observed_body_value(),
                        ),
                        _ => (
                            AuditResponseError::upstream_response_stream_failed(
                                observed_response_body,
                                status,
                            ),
                            body_value(response_bytes, &response_digest),
                        ),
                    };
                    let (expected_error, _, expected_status) = error.into_parts();
                    (
                        AuditOutcome::response_error(error, upstream),
                        "response_error",
                        Some(expected_error),
                        expected_body,
                        expected_status.as_u16(),
                        Some((upstream_path.as_str(), upstream_query.as_deref())),
                    )
                }
                _ => {
                    let error = upstream_error(upstream_error_kind);
                    (
                        AuditOutcome::upstream_error(error, upstream),
                        "upstream_error",
                        Some(error.error_class()),
                        not_observed_body_value(),
                        error.status().as_u16(),
                        Some((upstream_path.as_str(), upstream_query.as_deref())),
                    )
                }
            };
            let request = AuditRequestInput::new(
                method_value(&method),
                AuditTarget::from_uri_parts(&path, query.as_deref()),
                RequestId::from_parts(&run_token, sequence),
                request_body,
                upstream_origin(),
            );
            let input = AuditEventInput::new(request, outcome);

            let value = serde_json::to_value(AuditEvent::new(input))
                .expect("event should serialize");
            let object = value.as_object().expect("event should be a JSON object");

            prop_assert_eq!(object.len(), 14);
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
            prop_assert_eq!(object["status"].as_u64(), Some(u64::from(expected_status)));
            prop_assert_eq!(
                &object["request_body"],
                &body_value(request_bytes, &request_digest)
            );
            prop_assert_eq!(&object["response_body"], &expected_response_body);
            prop_assert_eq!(object["error_class"].as_str(), expected_error);
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
