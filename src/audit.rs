//! Audit event schema and writer.

use crate::allowlist::{
    AcceptedTarget, AllowedTarget, AllowlistRejectionReason, TargetRejectionReason,
};
use crate::body::{
    AccountedBody, BodyDigest, BodyObservation, NonEmptyBodyObservation, OversizedResponseBody,
    ResponseAccount,
};
use crate::config::{AuditEventBytes, GatewayConfig, MAX_ALLOWED_METHOD_BYTES, UpstreamOrigin};
use crate::target::{
    MAX_ORIGIN_FORM_PATH_BYTES, MAX_ORIGIN_FORM_QUERY_BYTES, OriginFormPath, OriginFormQuery,
};
use ::http::{Method, StatusCode, Uri};
use core::fmt;
use core::num::NonZeroU64;
use serde::de::{Error as SerdeError, Unexpected};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashSet;
use std::io;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use thiserror::Error;
use tokio::fs::{OpenOptions, create_dir_all};
use tokio::io::{
    AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncSeek, AsyncSeekExt as _, AsyncWrite,
    AsyncWriteExt as _, BufReader,
};
use tokio::sync::Mutex;
use url::Url;

/// Suffix added when audit target text is truncated.
const AUDIT_TRUNCATION_PREFIX: &str = "...[truncated original_bytes=";

/// Suffix terminator added when audit target text is truncated.
const AUDIT_TRUNCATION_SUFFIX: &str = "]";

/// Maximum audited request path bytes.
const MAX_AUDIT_TARGET_PATH_BYTES: usize = MAX_ORIGIN_FORM_PATH_BYTES;

/// Maximum audited request query bytes.
const MAX_AUDIT_TARGET_QUERY_BYTES: usize = MAX_ORIGIN_FORM_QUERY_BYTES;

/// Hex bytes in one half of a per-run token.
#[cfg(test)]
const RUN_TOKEN_HEX_HALF_BYTES: usize = 16;

/// Random bytes in a per-run token.
pub(crate) const RUN_TOKEN_RANDOM_BYTES: usize = 16;

/// Exact per-run token bytes.
#[cfg(test)]
const RUN_TOKEN_BYTES: usize = RUN_TOKEN_HEX_HALF_BYTES * 2 + 1;

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

    /// Path contained a percent-encoded path separator.
    EncodedSeparator,

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

    /// Path exceeded the supported byte limit.
    PathTooLong,

    /// Query exceeded the supported byte limit.
    QueryTooLong,

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

/// Closed denied request audit input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuditDenial {
    /// Closed denial variant.
    kind: AuditDenialKind,
}

/// Closed denied request audit variant.
#[derive(Clone, Debug, Eq, PartialEq)]
enum AuditDenialKind {
    /// Request target included a scheme or authority.
    AbsoluteFormUnsupported {
        /// Request method.
        method: Method,
        /// Raw audit target.
        target: AuditTarget,
    },

    /// `CONNECT` is never accepted.
    ConnectUnsupported {
        /// Raw audit target.
        target: AuditTarget,
    },

    /// Path contained a literal or percent-encoded dot segment.
    DotSegment {
        /// Request method.
        method: Method,
        /// Raw audit target.
        target: AuditTarget,
    },

    /// Path contained a percent-encoded path separator.
    EncodedSeparator {
        /// Request method.
        method: Method,
        /// Raw audit target.
        target: AuditTarget,
    },

    /// Path contained invalid percent-encoding.
    InvalidPercentEncoding {
        /// Request method.
        method: Method,
        /// Raw audit target.
        target: AuditTarget,
    },

    /// Request had an invalid `Connection` header.
    InvalidRequestConnectionHeader {
        /// Request method.
        method: Method,
        /// Accepted audit target.
        target: AuditTarget,
    },

    /// Method was not in the allowlist.
    MethodDenied {
        /// Request method.
        method: Method,
        /// Accepted audit target.
        target: AuditTarget,
    },

    /// Target was not an origin-form path.
    NonOriginForm {
        /// Request method.
        method: Method,
        /// Raw audit target.
        target: AuditTarget,
    },

    /// Path was not in the allowlist.
    PathDenied {
        /// Request method.
        method: Method,
        /// Accepted audit target.
        target: AuditTarget,
    },

    /// Path exceeded the supported byte limit.
    PathTooLong {
        /// Request method.
        method: Method,
        /// Truncated raw audit target.
        target: AuditTarget,
    },

    /// Query exceeded the supported byte limit.
    QueryTooLong {
        /// Request method.
        method: Method,
        /// Truncated raw audit target.
        target: AuditTarget,
    },

    /// Request body could not be read.
    RequestBodyReadFailed {
        /// Request method.
        method: Method,
        /// Accepted audit target.
        target: AuditTarget,
    },

    /// Request body was not received before the configured timeout.
    RequestBodyTimeout {
        /// Request method.
        method: Method,
        /// Accepted audit target.
        target: AuditTarget,
    },

    /// Request body exceeded the configured limit.
    RequestBodyTooLarge {
        /// Request method.
        method: Method,
        /// Accepted audit target.
        target: AuditTarget,
    },

    /// Request headers exceeded the configured limit.
    RequestHeadersTooLarge {
        /// Request method.
        method: Method,
        /// Accepted audit target.
        target: AuditTarget,
    },

    /// Gateway request concurrency was exhausted.
    TooManyRequests {
        /// Request method.
        method: Method,
        /// Raw audit target.
        target: AuditTarget,
    },
}

/// Audit target proven to come from an accepted origin-form request target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcceptedAuditTarget {
    /// Accepted audit target.
    target: AuditTarget,
}

/// Audit target captured before target parsing or admission succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparsedAuditTarget {
    /// Raw audit target.
    target: AuditTarget,
}

/// Audit target paired with the target parser rejection that produced it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RejectedAuditTarget {
    /// Target parser rejection.
    reason: TargetRejectionReason,
    /// Raw audit target.
    target: AuditTarget,
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
        /// Observed oversized response body.
        response_body: OversizedResponseBody,
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

    /// Upstream response stream timed out after upstream I/O started.
    UpstreamResponseTimeout {
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
    /// Existing audit log contained a complete but invalid NDJSON event.
    #[error("audit path {path} has invalid JSON on line {line}: {source}")]
    CorruptLog {
        /// Path that failed.
        path: PathBuf,
        /// One-based line number of the corrupt audit event.
        line: NonZeroU64,
        /// JSON parse error.
        source: serde_json::Error,
    },

    /// Audit event exceeded configured maximum.
    #[error("audit event has {bytes} bytes, maximum is {max}")]
    EventTooLarge {
        /// Serialized event bytes.
        bytes: usize,
        /// Maximum allowed bytes.
        max: usize,
    },

    /// Audit log tail could not be inspected.
    #[error("failed to inspect audit path {path}: {source}")]
    Inspect {
        /// Path that failed.
        path: PathBuf,
        /// I/O source error.
        source: io::Error,
    },

    /// Audit log could not be opened.
    #[error("failed to open audit path {path}: {source}")]
    Open {
        /// Path that failed.
        path: PathBuf,
        /// I/O source error.
        source: io::Error,
    },

    /// Audit log may contain a partial event from an earlier write failure.
    #[error("audit writer is poisoned after a previous write failure")]
    Poisoned,

    /// Audit log ended with a partial NDJSON event.
    #[error("audit path {path} has a partial final event")]
    TornLog {
        /// Path that failed.
        path: PathBuf,
    },

    /// Audit log write failed.
    #[error("failed to write audit event: {0}")]
    Write(io::Error),
}

/// Existing audit log tail state at startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditLogTail {
    /// Existing log ends with an NDJSON record terminator.
    Complete,
    /// Empty audit log.
    Empty,
    /// Existing log ends with a partial NDJSON record.
    Torn,
}

/// Sendable reader surface required to classify an existing audit log tail.
trait AuditLogTailReader: AsyncRead + AsyncSeek + Send + Unpin {}

impl<T> AuditLogTailReader for T where T: AsyncRead + AsyncSeek + Send + Unpin {}

/// Sendable writer surface required to append audit events.
trait AuditLogWriter: AsyncWrite + Send + Unpin {}

impl<T> AuditLogWriter for T where T: AsyncWrite + Send + Unpin {}

/// Structured audit event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct AuditEvent {
    /// Final audit decision.
    decision: AuditDecision,
    /// Stable error class for failed decisions.
    error_class: Option<String>,
    /// Request method.
    method: AuditMethod,
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
    status: AuditStatus,
    /// RFC 3339 UTC timestamp.
    timestamp: AuditTimestamp,
    /// Configured upstream origin.
    upstream_origin: String,
    /// Upstream path, when an upstream request was attempted.
    upstream_path: Option<String>,
    /// Upstream query, when an upstream request was attempted.
    upstream_query: Option<String>,
    /// Audit schema version.
    version: AuditSchemaVersion,
}

/// Existing audit event parsed at startup before appending.
#[derive(Debug, Deserialize)]
#[serde(try_from = "ExistingAuditEventFields")]
struct ExistingAuditEvent {
    /// Semantically validated existing audit event fields.
    fields: ExistingAuditEventFields,
}

/// Existing audit event fields parsed at startup before appending.
#[derive(Debug)]
struct ExistingAuditEventFields {
    /// Final audit decision.
    decision: ExistingAuditDecision,
    /// Stable error class for failed decisions.
    error_class: Option<ExistingAuditErrorClass>,
    /// Request method.
    method: String,
    /// Accepted request path, or bounded raw target for denied requests.
    path: String,
    /// Request query string without `?`.
    query: Option<String>,
    /// Request body summary.
    request_body: ExistingAuditBodySummary,
    /// Request identity.
    request_id: String,
    /// Response body summary.
    response_body: ExistingAuditBodySummary,
    /// Response status returned to the harness.
    status: StatusCode,
    /// RFC 3339 UTC timestamp.
    timestamp: String,
    /// Configured upstream origin.
    upstream_origin: UpstreamOrigin,
    /// Upstream path, when an upstream request was attempted.
    upstream_path: Option<String>,
    /// Upstream query, when an upstream request was attempted.
    upstream_query: Option<String>,
    /// Audit schema version.
    version: AuditSchemaVersion,
}

/// Wire-shaped existing audit event fields parsed at startup.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExistingAuditEventWireFields {
    /// Final audit decision.
    decision: ExistingAuditDecision,
    /// Stable error class for failed decisions.
    error_class: RequiredOption<ExistingAuditErrorClass>,
    /// Request method.
    #[serde(deserialize_with = "deserialize_existing_method")]
    method: String,
    /// Accepted request path, or bounded raw target for denied requests.
    #[serde(deserialize_with = "deserialize_existing_path")]
    path: String,
    /// Request query string without `?`.
    #[serde(deserialize_with = "deserialize_existing_query")]
    query: RequiredOption<String>,
    /// Request body summary.
    request_body: ExistingAuditBodySummary,
    /// Request identity.
    #[serde(deserialize_with = "deserialize_existing_request_id")]
    request_id: String,
    /// Response body summary.
    response_body: ExistingAuditBodySummary,
    /// Response status returned to the harness.
    #[serde(deserialize_with = "deserialize_existing_status")]
    status: StatusCode,
    /// RFC 3339 UTC timestamp.
    #[serde(deserialize_with = "deserialize_existing_timestamp")]
    timestamp: String,
    /// Configured upstream origin.
    #[serde(deserialize_with = "deserialize_existing_upstream_origin")]
    upstream_origin: UpstreamOrigin,
    /// Upstream path, when an upstream request was attempted.
    #[serde(deserialize_with = "deserialize_existing_upstream_path")]
    upstream_path: RequiredOption<String>,
    /// Upstream query, when an upstream request was attempted.
    #[serde(deserialize_with = "deserialize_existing_upstream_query")]
    upstream_query: RequiredOption<String>,
    /// Audit schema version.
    #[serde(deserialize_with = "deserialize_existing_version")]
    version: AuditSchemaVersion,
}

/// Field wrapper that requires presence while admitting JSON null.
#[derive(Debug)]
struct RequiredOption<T>(Option<T>);

/// Existing audit body summary parsed at startup.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "state")]
enum ExistingAuditBodySummary {
    /// Body was observed and empty.
    Empty,

    /// Body was observed and non-empty.
    NonEmpty {
        /// Body digest.
        #[serde(deserialize_with = "deserialize_blake3_hex")]
        blake3: String,
        /// Body byte count.
        bytes: NonZeroU64,
    },

    /// Body bytes were not observed.
    NotObserved,
}

/// Existing audit decision parsed at startup.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ExistingAuditDecision {
    /// Request was allowed and completed normally.
    Allowed,

    /// Request was denied before upstream I/O.
    Denied,

    /// Response handling failed.
    ResponseError,

    /// Upstream request failed before a response completed.
    UpstreamError,
}

/// Existing audit error class parsed at startup.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ExistingAuditErrorClass {
    /// Absolute-form request target was rejected.
    AbsoluteFormUnsupported,

    /// CONNECT request was rejected.
    ConnectUnsupported,

    /// Dot segment was rejected.
    DotSegment,

    /// Downstream closed before the response completed.
    DownstreamClosed,

    /// Encoded separator was rejected.
    #[serde(rename = "encoded_path_separator")]
    EncodedSeparator,

    /// Invalid percent encoding was rejected.
    InvalidPercentEncoding,

    /// Request `Connection` header contained an invalid dynamic header name.
    InvalidRequestConnectionHeader,

    /// Response `Connection` header contained an invalid dynamic header name.
    InvalidResponseConnectionHeader,

    /// Method was outside the allowlist.
    MethodDenied,

    /// Request target was not origin-form.
    NonOriginForm,

    /// Path was outside the allowlist.
    PathDenied,

    /// Path exceeded the supported byte limit.
    PathTooLong,

    /// Query exceeded the supported byte limit.
    QueryTooLong,

    /// Request body read failed.
    RequestBodyReadFailed,

    /// Request body read timed out.
    RequestBodyTimeout,

    /// Request body exceeded the supported byte limit.
    RequestBodyTooLarge,

    /// Request headers exceeded the supported byte limit.
    RequestHeadersTooLarge,

    /// Response body exceeded the supported byte limit.
    ResponseBodyTooLarge,

    /// Response headers exceeded the supported byte limit.
    ResponseHeadersTooLarge,

    /// Concurrency limit rejected the request.
    TooManyRequests,

    /// Gateway could not connect to the upstream.
    UpstreamConnectFailed,

    /// Upstream request failed after connection setup.
    UpstreamRequestFailed,

    /// Upstream response stream failed after upstream I/O started.
    UpstreamResponseStreamFailed,

    /// Upstream response stream timed out after upstream I/O started.
    UpstreamResponseTimeout,

    /// Upstream request timed out.
    UpstreamTimeout,
}

impl ExistingAuditBodySummary {
    /// Consumes all validated body-summary fields.
    fn consume(self) {
        match self {
            Self::Empty | Self::NotObserved => {}
            Self::NonEmpty { blake3, bytes } => drop((blake3, bytes)),
        }
    }

    /// Returns true when the body bytes were not observed.
    const fn is_not_observed(&self) -> bool {
        matches!(self, Self::NotObserved)
    }

    /// Returns true when the body bytes were observed.
    const fn is_observed(&self) -> bool {
        matches!(self, Self::Empty | Self::NonEmpty { .. })
    }
}

impl ExistingAuditErrorClass {
    /// Returns the fixed status for error classes that choose the response.
    const fn fixed_status(self) -> Option<StatusCode> {
        match self {
            Self::AbsoluteFormUnsupported
            | Self::DotSegment
            | Self::EncodedSeparator
            | Self::InvalidPercentEncoding
            | Self::InvalidRequestConnectionHeader
            | Self::NonOriginForm
            | Self::RequestBodyReadFailed => Some(StatusCode::BAD_REQUEST),
            Self::ConnectUnsupported => Some(StatusCode::METHOD_NOT_ALLOWED),
            Self::InvalidResponseConnectionHeader
            | Self::ResponseHeadersTooLarge
            | Self::UpstreamConnectFailed
            | Self::UpstreamRequestFailed => Some(StatusCode::BAD_GATEWAY),
            Self::MethodDenied | Self::PathDenied => Some(StatusCode::FORBIDDEN),
            Self::PathTooLong | Self::QueryTooLong => Some(StatusCode::URI_TOO_LONG),
            Self::RequestBodyTimeout => Some(StatusCode::REQUEST_TIMEOUT),
            Self::RequestBodyTooLarge => Some(StatusCode::PAYLOAD_TOO_LARGE),
            Self::RequestHeadersTooLarge => Some(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE),
            Self::TooManyRequests => Some(StatusCode::TOO_MANY_REQUESTS),
            Self::UpstreamTimeout => Some(StatusCode::GATEWAY_TIMEOUT),
            Self::DownstreamClosed
            | Self::ResponseBodyTooLarge
            | Self::UpstreamResponseStreamFailed
            | Self::UpstreamResponseTimeout => None,
        }
    }

    /// Returns true when the error class belongs to denied decisions.
    const fn is_denial(self) -> bool {
        matches!(
            self,
            Self::AbsoluteFormUnsupported
                | Self::ConnectUnsupported
                | Self::DotSegment
                | Self::EncodedSeparator
                | Self::InvalidPercentEncoding
                | Self::InvalidRequestConnectionHeader
                | Self::MethodDenied
                | Self::NonOriginForm
                | Self::PathDenied
                | Self::PathTooLong
                | Self::QueryTooLong
                | Self::RequestBodyReadFailed
                | Self::RequestBodyTimeout
                | Self::RequestBodyTooLarge
                | Self::RequestHeadersTooLarge
                | Self::TooManyRequests
        )
    }

    /// Returns true when the error class belongs to response-error decisions.
    const fn is_response_error(self) -> bool {
        matches!(
            self,
            Self::DownstreamClosed
                | Self::InvalidResponseConnectionHeader
                | Self::ResponseBodyTooLarge
                | Self::ResponseHeadersTooLarge
                | Self::UpstreamResponseStreamFailed
                | Self::UpstreamResponseTimeout
        )
    }

    /// Returns true when the error class belongs to upstream-error decisions.
    const fn is_upstream_error(self) -> bool {
        matches!(
            self,
            Self::UpstreamConnectFailed | Self::UpstreamRequestFailed | Self::UpstreamTimeout
        )
    }

    /// Returns true when the request body cannot have been observed.
    const fn requires_unobserved_request_body(self) -> bool {
        matches!(
            self,
            Self::RequestBodyReadFailed | Self::RequestBodyTimeout | Self::RequestBodyTooLarge
        )
    }
}

impl<'de, T> Deserialize<'de> for RequiredOption<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Self)
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        *place = Self::deserialize(deserializer)?;
        Ok(())
    }
}

impl<T> RequiredOption<T> {
    /// Returns the nullable field value.
    fn into_option(self) -> Option<T> {
        let Self(value) = self;
        value
    }

    /// Builds a present nullable field wrapper.
    const fn new(value: Option<T>) -> Self {
        Self(value)
    }
}

impl<'de> Deserialize<'de> for ExistingAuditEventFields {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = ExistingAuditEventWireFields::deserialize(deserializer)?;
        Ok(Self {
            decision: fields.decision,
            error_class: fields.error_class.into_option(),
            method: fields.method,
            path: fields.path,
            query: fields.query.into_option(),
            request_body: fields.request_body,
            request_id: fields.request_id,
            response_body: fields.response_body,
            status: fields.status,
            timestamp: fields.timestamp,
            upstream_origin: fields.upstream_origin,
            upstream_path: fields.upstream_path.into_option(),
            upstream_query: fields.upstream_query.into_option(),
            version: fields.version,
        })
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        *place = Self::deserialize(deserializer)?;
        Ok(())
    }
}

impl ExistingAuditEventFields {
    /// Validates that the audit target is authority-bearing.
    fn expect_authority_target(&self, message: &'static str) -> Result<(), &'static str> {
        if self.target_has_authority() {
            Ok(())
        } else {
            Err(message)
        }
    }

    /// Validates that the audit target is rejected without carrying authority.
    fn expect_non_authority_target_rejection(
        &self,
        expected: TargetRejectionReason,
        message: &'static str,
    ) -> Result<(), &'static str> {
        if self.target_has_authority() {
            Err(message)
        } else {
            self.expect_target_rejection(expected, message)
        }
    }

    /// Validates that the audit target reproduces the expected parser rejection.
    fn expect_target_rejection(
        &self,
        expected: TargetRejectionReason,
        message: &'static str,
    ) -> Result<(), &'static str> {
        match AcceptedTarget::new(&self.path, self.query.as_deref()) {
            Err(actual) if actual == expected => Ok(()),
            Ok(_) | Err(_) => Err(message),
        }
    }

    /// Returns the upstream URL target implied by the accepted request target.
    fn expected_upstream_target(&self) -> Result<AuditUpstreamTarget, &'static str> {
        let accepted = AcceptedTarget::new(&self.path, self.query.as_deref())
            .map_err(|_error| "upstream-attempted audit target must be accepted")?;
        let url = self
            .upstream_origin
            .join_path_query(accepted.origin_form_path(), accepted.origin_form_query());
        Ok(AuditUpstreamTarget::from_url(&url))
    }

    /// Returns true when the complete audited target parses with an authority.
    fn parsed_target_has_authority(&self) -> bool {
        Uri::try_from(self.raw_target_text().as_str()).is_ok_and(|uri| uri.authority().is_some())
    }

    /// Returns the audited request target as it appeared on the wire.
    fn raw_target_text(&self) -> String {
        self.query.as_ref().map_or_else(
            || self.path.clone(),
            |query| format!("{}?{query}", self.path),
        )
    }

    /// Returns true when the audited target carries an HTTP authority.
    fn target_has_authority(&self) -> bool {
        self.parsed_target_has_authority() || self.truncated_target_has_authority()
    }

    /// Returns true when writer-shaped truncation preserves an authority prefix.
    fn truncated_target_has_authority(&self) -> bool {
        truncated_audit_text_prefix(&self.path, MAX_AUDIT_TARGET_PATH_BYTES)
            .is_some_and(|prefix| Uri::try_from(prefix).is_ok_and(|uri| uri.authority().is_some()))
    }

    /// Validates cross-field invariants that JSON shape alone cannot encode.
    fn validate(&self) -> Result<(), &'static str> {
        let error_class = self.validate_error_class()?;
        self.validate_denied_target(error_class)?;
        self.validate_method(error_class)?;
        self.validate_request_body(error_class)?;
        self.validate_response_body(error_class)?;
        self.validate_status(error_class)?;
        self.validate_upstream_target()?;
        Ok(())
    }

    /// Validates denial error classes against the audited request target.
    fn validate_denied_target(
        &self,
        maybe_error_class: Option<ExistingAuditErrorClass>,
    ) -> Result<(), &'static str> {
        let Some(error_class) = maybe_error_class else {
            return Ok(());
        };
        if self.decision != ExistingAuditDecision::Denied {
            return Ok(());
        }

        match error_class {
            ExistingAuditErrorClass::AbsoluteFormUnsupported => {
                self.expect_authority_target("audit target does not match absolute-form denial")
            }
            ExistingAuditErrorClass::NonOriginForm => self.expect_non_authority_target_rejection(
                TargetRejectionReason::NonOriginForm,
                "audit target does not match non-origin-form denial",
            ),
            ExistingAuditErrorClass::DotSegment => self.expect_target_rejection(
                TargetRejectionReason::DotSegment,
                "audit target does not match dot-segment denial",
            ),
            ExistingAuditErrorClass::EncodedSeparator => self.expect_target_rejection(
                TargetRejectionReason::EncodedSeparator,
                "audit target does not match encoded-separator denial",
            ),
            ExistingAuditErrorClass::InvalidPercentEncoding => self.expect_target_rejection(
                TargetRejectionReason::InvalidPercentEncoding,
                "audit target does not match invalid-percent denial",
            ),
            ExistingAuditErrorClass::PathTooLong => {
                if !self.target_has_authority()
                    && is_truncated_audit_text(&self.path, MAX_AUDIT_TARGET_PATH_BYTES)
                {
                    Ok(())
                } else {
                    Err("audit target does not match path-too-long denial")
                }
            }
            ExistingAuditErrorClass::QueryTooLong => {
                if OriginFormPath::parse(&self.path).is_ok()
                    && self.query.as_deref().is_some_and(|query| {
                        is_truncated_audit_text(query, MAX_AUDIT_TARGET_QUERY_BYTES)
                    })
                {
                    Ok(())
                } else {
                    Err("audit target does not match query-too-long denial")
                }
            }
            ExistingAuditErrorClass::MethodDenied
            | ExistingAuditErrorClass::PathDenied
            | ExistingAuditErrorClass::InvalidRequestConnectionHeader
            | ExistingAuditErrorClass::RequestBodyReadFailed
            | ExistingAuditErrorClass::RequestBodyTimeout
            | ExistingAuditErrorClass::RequestBodyTooLarge
            | ExistingAuditErrorClass::RequestHeadersTooLarge => {
                if AcceptedTarget::new(&self.path, self.query.as_deref()).is_ok() {
                    Ok(())
                } else {
                    Err("audit target must be accepted before this denial")
                }
            }
            ExistingAuditErrorClass::ConnectUnsupported
            | ExistingAuditErrorClass::TooManyRequests => Ok(()),
            ExistingAuditErrorClass::DownstreamClosed
            | ExistingAuditErrorClass::InvalidResponseConnectionHeader
            | ExistingAuditErrorClass::ResponseBodyTooLarge
            | ExistingAuditErrorClass::ResponseHeadersTooLarge
            | ExistingAuditErrorClass::UpstreamConnectFailed
            | ExistingAuditErrorClass::UpstreamRequestFailed
            | ExistingAuditErrorClass::UpstreamResponseStreamFailed
            | ExistingAuditErrorClass::UpstreamResponseTimeout
            | ExistingAuditErrorClass::UpstreamTimeout => {
                Err("audit error class does not match decision")
            }
        }
    }

    /// Validates that the decision and error class agree.
    const fn validate_error_class(&self) -> Result<Option<ExistingAuditErrorClass>, &'static str> {
        match (self.decision, self.error_class) {
            (ExistingAuditDecision::Allowed, None) => Ok(None),
            (ExistingAuditDecision::Allowed, Some(_error_class)) => {
                Err("allowed audit events must not have an error class")
            }
            (ExistingAuditDecision::Denied, Some(error_class)) if error_class.is_denial() => {
                Ok(Some(error_class))
            }
            (ExistingAuditDecision::ResponseError, Some(error_class))
                if error_class.is_response_error() =>
            {
                Ok(Some(error_class))
            }
            (ExistingAuditDecision::UpstreamError, Some(error_class))
                if error_class.is_upstream_error() =>
            {
                Ok(Some(error_class))
            }
            (_, None) => Err("failed audit events must have an error class"),
            (_, Some(_error_class)) => Err("audit error class does not match decision"),
        }
    }

    /// Validates the method for decision-specific terminal states.
    fn validate_method(
        &self,
        error_class: Option<ExistingAuditErrorClass>,
    ) -> Result<(), &'static str> {
        let is_connect = self.method == Method::CONNECT.as_str();
        match error_class {
            Some(ExistingAuditErrorClass::ConnectUnsupported) if is_connect => Ok(()),
            Some(ExistingAuditErrorClass::ConnectUnsupported) => {
                Err("connect denials must record CONNECT")
            }
            Some(ExistingAuditErrorClass::TooManyRequests) => Ok(()),
            _ if is_connect => Err("CONNECT can only be denied before admission"),
            _ => Ok(()),
        }
    }

    /// Validates the request body summary for the decision.
    fn validate_request_body(
        &self,
        error_class: Option<ExistingAuditErrorClass>,
    ) -> Result<(), &'static str> {
        if error_class.is_some_and(ExistingAuditErrorClass::requires_unobserved_request_body) {
            return if self.request_body.is_not_observed() {
                Ok(())
            } else {
                Err("audit request body summary does not match error class")
            };
        }

        if self.decision == ExistingAuditDecision::Denied || self.request_body.is_observed() {
            Ok(())
        } else {
            Err("upstream-attempted audit events must observe the request body")
        }
    }

    /// Validates the response body summary for the decision.
    const fn validate_response_body(
        &self,
        error_class: Option<ExistingAuditErrorClass>,
    ) -> Result<(), &'static str> {
        match self.decision {
            ExistingAuditDecision::Allowed => {
                if self.response_body.is_observed() {
                    Ok(())
                } else {
                    Err("audit response body summary does not match decision")
                }
            }
            ExistingAuditDecision::Denied | ExistingAuditDecision::UpstreamError => {
                if self.response_body.is_not_observed() {
                    Ok(())
                } else {
                    Err("audit response body summary does not match decision")
                }
            }
            ExistingAuditDecision::ResponseError => self.validate_response_error_body(error_class),
        }
    }

    /// Validates the response body summary for response-error decisions.
    const fn validate_response_error_body(
        &self,
        error_class: Option<ExistingAuditErrorClass>,
    ) -> Result<(), &'static str> {
        match error_class {
            Some(
                ExistingAuditErrorClass::InvalidResponseConnectionHeader
                | ExistingAuditErrorClass::ResponseHeadersTooLarge,
            ) if self.response_body.is_not_observed() => Ok(()),
            Some(ExistingAuditErrorClass::ResponseBodyTooLarge)
                if matches!(
                    self.response_body,
                    ExistingAuditBodySummary::NonEmpty { .. }
                ) =>
            {
                Ok(())
            }
            Some(
                ExistingAuditErrorClass::DownstreamClosed
                | ExistingAuditErrorClass::UpstreamResponseStreamFailed
                | ExistingAuditErrorClass::UpstreamResponseTimeout,
            ) if self.response_body.is_observed() => Ok(()),
            _ => Err("audit response body summary does not match decision"),
        }
    }

    /// Validates fixed statuses implied by the error class.
    fn validate_status(
        &self,
        error_class: Option<ExistingAuditErrorClass>,
    ) -> Result<(), &'static str> {
        if let Some(expected) = error_class.and_then(ExistingAuditErrorClass::fixed_status)
            && self.status != expected
        {
            return Err("audit status does not match error class");
        }
        Ok(())
    }

    /// Validates the upstream target relationship for the decision.
    fn validate_upstream_target(&self) -> Result<(), &'static str> {
        match self.decision {
            ExistingAuditDecision::Denied => {
                if self.upstream_path.is_none() && self.upstream_query.is_none() {
                    Ok(())
                } else {
                    Err("denied audit events must not record an upstream target")
                }
            }
            ExistingAuditDecision::Allowed
            | ExistingAuditDecision::ResponseError
            | ExistingAuditDecision::UpstreamError => {
                let expected = self.expected_upstream_target()?;
                if self.upstream_path.as_deref() == Some(expected.path())
                    && self.upstream_query.as_deref() == expected.query()
                {
                    Ok(())
                } else {
                    Err("upstream audit target must match the joined upstream URL")
                }
            }
        }
    }
}

impl ExistingAuditEvent {
    /// Consumes all validated event fields.
    fn consume(self) {
        let Self { fields } = self;
        let ExistingAuditEventFields {
            decision,
            error_class,
            method,
            path,
            query,
            request_body,
            request_id,
            response_body,
            status,
            timestamp,
            upstream_origin,
            upstream_path,
            upstream_query,
            version,
        } = fields;
        request_body.consume();
        response_body.consume();
        drop((
            decision,
            error_class,
            method,
            path,
            query,
            request_id,
            status,
            timestamp,
            upstream_origin,
            upstream_path,
            upstream_query,
            version,
        ));
    }

    /// Returns the existing request identity.
    fn request_id(&self) -> &str {
        &self.fields.request_id
    }
}

impl TryFrom<ExistingAuditEventFields> for ExistingAuditEvent {
    type Error = &'static str;

    fn try_from(fields: ExistingAuditEventFields) -> Result<Self, Self::Error> {
        fields.validate()?;
        Ok(Self { fields })
    }
}

/// Current audit event schema version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuditSchemaVersion;

impl AuditSchemaVersion {
    /// Current schema version value serialized into each event.
    const CURRENT: Self = Self;

    /// Returns the numeric schema version.
    #[must_use]
    const fn as_u8() -> u8 {
        3
    }
}

/// Body accounting summary recorded in audit events.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
struct AuditBodySummary {
    /// Closed body-summary state.
    kind: AuditBodySummaryKind,
}

/// HTTP status recorded in audit events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuditStatus {
    /// Valid HTTP status code.
    code: StatusCode,
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

/// Body summary after bytes were observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObservedBodySummary {
    /// Body was observed and empty.
    Empty,

    /// Body was observed and non-empty.
    NonEmpty(NonEmptyBodyObservation),
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

/// Request context for a denied audit event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeniedAuditRequestInput {
    /// Denial reason paired with the request context.
    reason: AuditDenialReason,
    /// Request context common to every audit event.
    request: AuditRequestInput,
}

/// Request context for an audit event after the request body was observed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ObservedAuditRequestInput {
    /// Request context common to every audit event.
    request: AuditRequestInput,
    /// Upstream target derived from the same accepted target witness.
    upstream: AuditUpstreamTarget,
}

/// Upstream target recorded when upstream I/O was attempted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuditUpstreamTarget {
    /// Upstream request path.
    path: OriginFormPath,
    /// Upstream request query.
    query: Option<OriginFormQuery>,
}

/// Request target recorded in the audit log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuditTarget {
    /// Request path.
    path: String,
    /// Request query string without `?`.
    query: Option<String>,
}

/// Request method recorded in the audit log.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
struct AuditMethod {
    /// Bounded method text.
    value: String,
}

/// Newline-delimited JSON audit writer.
#[derive(Clone)]
pub(crate) struct AuditWriter {
    /// Maximum serialized event bytes, including the NDJSON newline.
    max_event_bytes: AuditEventBytes,
    /// Audit log writer state guarded for append writes.
    state: Arc<Mutex<AuditWriterState>>,
}

/// Mutable audit writer state.
struct AuditWriterState {
    /// Whether a prior write may have left a partial event.
    poisoned: bool,
    /// Concrete append writer.
    writer: Box<dyn AuditLogWriter>,
}

/// Request identity used in audit events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequestId {
    /// Bounded per-run token.
    run_token: RunToken,
    /// Non-zero per-run sequence.
    sequence: NonZeroU64,
}

/// Bounded per-run token used in request identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RunToken {
    /// Per-run entropy bytes.
    entropy: [u8; RUN_TOKEN_RANDOM_BYTES],
}

/// Run token rejection.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunTokenError {
    /// Token was empty.
    Empty,

    /// Token contained a byte outside lowercase hex and `-`.
    InvalidCharacter,

    /// Token was not exactly `hex-hex`.
    InvalidShape,

    /// Token exceeded the supported byte limit.
    TooLong,
}

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

    /// Creates a body summary from an observed body.
    #[must_use]
    const fn from_observation(observation: BodyObservation) -> Self {
        match observation {
            BodyObservation::Empty => Self::empty(),
            BodyObservation::NonEmpty(non_empty) => Self::non_empty(non_empty),
        }
    }

    /// Creates an observed body summary from a request body.
    #[must_use]
    fn from_request_body(request_body: &AccountedBody) -> Self {
        Self::from_observation(request_body.observation())
    }

    /// Creates a non-empty body summary.
    #[must_use]
    const fn non_empty(non_empty: NonEmptyBodyObservation) -> Self {
        Self {
            kind: AuditBodySummaryKind::NonEmpty {
                blake3: non_empty.blake3(),
                bytes: non_empty.bytes(),
            },
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

impl AuditStatus {
    /// Returns the underlying HTTP status code.
    #[cfg(test)]
    #[must_use]
    const fn as_status_code(self) -> StatusCode {
        self.code
    }

    /// Creates an audit status from an HTTP status code.
    #[must_use]
    const fn from_status_code(code: StatusCode) -> Self {
        Self { code }
    }
}

impl Serialize for AuditStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(self.code.as_u16())
    }
}

impl Serialize for AuditSchemaVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(Self::as_u8())
    }
}

impl ObservedBodySummary {
    /// Creates an observed body summary from an observed body.
    #[must_use]
    const fn from_observation(observation: BodyObservation) -> Self {
        match observation {
            BodyObservation::Empty => Self::Empty,
            BodyObservation::NonEmpty(non_empty) => Self::NonEmpty(non_empty),
        }
    }

    /// Creates an observed body summary from a response body account.
    #[must_use]
    pub(crate) fn from_response_account(response_account: &ResponseAccount) -> Self {
        Self::from_observation(response_account.observation())
    }

    /// Returns the underlying audit body summary.
    #[must_use]
    const fn into_summary(self) -> AuditBodySummary {
        match self {
            Self::Empty => AuditBodySummary::empty(),
            Self::NonEmpty(non_empty) => AuditBodySummary::non_empty(non_empty),
        }
    }
}

impl AcceptedAuditTarget {
    /// Creates an audit target witness from an accepted target witness.
    #[must_use]
    pub(crate) fn from_accepted(target: &AcceptedTarget) -> Self {
        Self {
            target: AuditTarget::from(target),
        }
    }

    /// Consumes the witness into the recorded audit target.
    #[must_use]
    fn into_target(self) -> AuditTarget {
        self.target
    }
}

impl AuditDenial {
    /// Creates an absolute-form denial.
    #[must_use]
    pub(crate) fn absolute_form_unsupported(
        method: Method,
        preparsed_target: PreparsedAuditTarget,
    ) -> Self {
        let target = preparsed_target.into_target();
        Self::from_kind(AuditDenialKind::AbsoluteFormUnsupported { method, target })
    }

    /// Creates an allowlist rejection denial.
    #[must_use]
    pub(crate) fn allowlist_rejected(
        method: Method,
        accepted_target: AcceptedAuditTarget,
        rejection: AllowlistRejectionReason,
    ) -> Self {
        let target = accepted_target.into_target();
        match rejection {
            AllowlistRejectionReason::MethodDenied => {
                Self::from_kind(AuditDenialKind::MethodDenied { method, target })
            }
            AllowlistRejectionReason::PathDenied => {
                Self::from_kind(AuditDenialKind::PathDenied { method, target })
            }
        }
    }

    /// Creates a CONNECT denial.
    #[must_use]
    pub(crate) fn connect_unsupported(preparsed_target: PreparsedAuditTarget) -> Self {
        let target = preparsed_target.into_target();
        Self::from_kind(AuditDenialKind::ConnectUnsupported { target })
    }

    /// Creates a dot-segment denial.
    #[must_use]
    const fn dot_segment(method: Method, target: AuditTarget) -> Self {
        Self::from_kind(AuditDenialKind::DotSegment { method, target })
    }

    /// Creates an encoded-separator denial.
    #[must_use]
    const fn encoded_separator(method: Method, target: AuditTarget) -> Self {
        Self::from_kind(AuditDenialKind::EncodedSeparator { method, target })
    }

    /// Creates a denial from its private closed variant.
    #[must_use]
    const fn from_kind(kind: AuditDenialKind) -> Self {
        Self { kind }
    }

    /// Consumes the denial into its method, target, and reason.
    #[must_use]
    fn into_parts(self) -> (Method, AuditTarget, AuditDenialReason) {
        match self.kind {
            AuditDenialKind::AbsoluteFormUnsupported { method, target } => {
                (method, target, AuditDenialReason::AbsoluteFormUnsupported)
            }
            AuditDenialKind::ConnectUnsupported { target } => (
                Method::CONNECT,
                target,
                AuditDenialReason::ConnectUnsupported,
            ),
            AuditDenialKind::DotSegment { method, target } => {
                (method, target, AuditDenialReason::DotSegment)
            }
            AuditDenialKind::EncodedSeparator { method, target } => {
                (method, target, AuditDenialReason::EncodedSeparator)
            }
            AuditDenialKind::InvalidPercentEncoding { method, target } => {
                (method, target, AuditDenialReason::InvalidPercentEncoding)
            }
            AuditDenialKind::InvalidRequestConnectionHeader { method, target } => (
                method,
                target,
                AuditDenialReason::InvalidRequestConnectionHeader,
            ),
            AuditDenialKind::MethodDenied { method, target } => {
                (method, target, AuditDenialReason::MethodDenied)
            }
            AuditDenialKind::NonOriginForm { method, target } => {
                (method, target, AuditDenialReason::NonOriginForm)
            }
            AuditDenialKind::PathDenied { method, target } => {
                (method, target, AuditDenialReason::PathDenied)
            }
            AuditDenialKind::PathTooLong { method, target } => {
                (method, target, AuditDenialReason::PathTooLong)
            }
            AuditDenialKind::QueryTooLong { method, target } => {
                (method, target, AuditDenialReason::QueryTooLong)
            }
            AuditDenialKind::RequestBodyReadFailed { method, target } => {
                (method, target, AuditDenialReason::RequestBodyReadFailed)
            }
            AuditDenialKind::RequestBodyTimeout { method, target } => {
                (method, target, AuditDenialReason::RequestBodyTimeout)
            }
            AuditDenialKind::RequestBodyTooLarge { method, target } => {
                (method, target, AuditDenialReason::RequestBodyTooLarge)
            }
            AuditDenialKind::RequestHeadersTooLarge { method, target } => {
                (method, target, AuditDenialReason::RequestHeadersTooLarge)
            }
            AuditDenialKind::TooManyRequests { method, target } => {
                (method, target, AuditDenialReason::TooManyRequests)
            }
        }
    }

    /// Creates an invalid-percent-encoding denial.
    #[must_use]
    const fn invalid_percent_encoding(method: Method, target: AuditTarget) -> Self {
        Self::from_kind(AuditDenialKind::InvalidPercentEncoding { method, target })
    }

    /// Creates an invalid request `Connection` header denial.
    #[must_use]
    pub(crate) fn invalid_request_connection_header(
        method: Method,
        accepted_target: AcceptedAuditTarget,
    ) -> Self {
        let target = accepted_target.into_target();
        Self::from_kind(AuditDenialKind::InvalidRequestConnectionHeader { method, target })
    }

    /// Creates a non-origin-form denial.
    #[must_use]
    const fn non_origin_form(method: Method, target: AuditTarget) -> Self {
        Self::from_kind(AuditDenialKind::NonOriginForm { method, target })
    }

    /// Creates a path-too-long denial.
    #[must_use]
    const fn path_too_long(method: Method, target: AuditTarget) -> Self {
        Self::from_kind(AuditDenialKind::PathTooLong { method, target })
    }

    /// Creates a query-too-long denial.
    #[must_use]
    const fn query_too_long(method: Method, target: AuditTarget) -> Self {
        Self::from_kind(AuditDenialKind::QueryTooLong { method, target })
    }

    /// Returns the closed denial reason.
    #[must_use]
    const fn reason(&self) -> AuditDenialReason {
        self.kind.reason()
    }

    /// Creates a request-body-read-failed denial.
    #[must_use]
    pub(crate) fn request_body_read_failed(
        method: Method,
        accepted_target: AcceptedAuditTarget,
    ) -> Self {
        let target = accepted_target.into_target();
        Self::from_kind(AuditDenialKind::RequestBodyReadFailed { method, target })
    }

    /// Creates a request-body-timeout denial.
    #[must_use]
    pub(crate) fn request_body_timeout(
        method: Method,
        accepted_target: AcceptedAuditTarget,
    ) -> Self {
        let target = accepted_target.into_target();
        Self::from_kind(AuditDenialKind::RequestBodyTimeout { method, target })
    }

    /// Creates a request-body-too-large denial.
    #[must_use]
    pub(crate) fn request_body_too_large(
        method: Method,
        accepted_target: AcceptedAuditTarget,
    ) -> Self {
        let target = accepted_target.into_target();
        Self::from_kind(AuditDenialKind::RequestBodyTooLarge { method, target })
    }

    /// Creates a request-headers-too-large denial.
    #[must_use]
    pub(crate) fn request_headers_too_large(
        method: Method,
        accepted_target: AcceptedAuditTarget,
    ) -> Self {
        let target = accepted_target.into_target();
        Self::from_kind(AuditDenialKind::RequestHeadersTooLarge { method, target })
    }

    /// Returns the response status for this denial.
    #[must_use]
    pub(crate) const fn status(&self) -> StatusCode {
        self.reason().status()
    }

    /// Creates a target parser rejection denial.
    #[must_use]
    pub(crate) fn target_rejected(method: Method, rejection: RejectedAuditTarget) -> Self {
        let (audit_target, reason) = rejection.into_parts();
        match reason {
            TargetRejectionReason::DotSegment => Self::dot_segment(method, audit_target),
            TargetRejectionReason::EncodedSeparator => {
                Self::encoded_separator(method, audit_target)
            }
            TargetRejectionReason::InvalidPercentEncoding => {
                Self::invalid_percent_encoding(method, audit_target)
            }
            TargetRejectionReason::NonOriginForm => Self::non_origin_form(method, audit_target),
            TargetRejectionReason::PathTooLong => Self::path_too_long(method, audit_target),
            TargetRejectionReason::QueryTooLong => Self::query_too_long(method, audit_target),
        }
    }

    /// Creates a too-many-requests denial.
    #[must_use]
    pub(crate) fn too_many_requests(
        method: Method,
        preparsed_target: PreparsedAuditTarget,
    ) -> Self {
        let target = preparsed_target.into_target();
        Self::from_kind(AuditDenialKind::TooManyRequests { method, target })
    }
}

impl PreparsedAuditTarget {
    /// Creates a preparsed audit target from the raw request URI.
    #[must_use]
    pub(crate) fn from_request_uri(uri: &Uri) -> Self {
        Self {
            target: AuditTarget::from_request_uri(uri),
        }
    }

    /// Consumes the witness into the recorded audit target.
    #[must_use]
    fn into_target(self) -> AuditTarget {
        self.target
    }
}

impl RejectedAuditTarget {
    /// Parses a request URI into an accepted target or a rejected audit target.
    pub(crate) fn accept_request_uri(uri: &Uri) -> Result<AcceptedTarget, Self> {
        AcceptedTarget::new(uri.path(), uri.query()).map_err(|reason| Self {
            reason,
            target: AuditTarget::from_request_uri(uri),
        })
    }

    /// Consumes the witness into the recorded target and rejection reason.
    #[must_use]
    fn into_parts(self) -> (AuditTarget, TargetRejectionReason) {
        (self.target, self.reason)
    }

    /// Returns the target parser rejection reason.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn reason(&self) -> TargetRejectionReason {
        self.reason
    }
}

impl AuditDenialKind {
    /// Returns the closed denial reason.
    #[must_use]
    const fn reason(&self) -> AuditDenialReason {
        match *self {
            Self::AbsoluteFormUnsupported { .. } => AuditDenialReason::AbsoluteFormUnsupported,
            Self::ConnectUnsupported { .. } => AuditDenialReason::ConnectUnsupported,
            Self::DotSegment { .. } => AuditDenialReason::DotSegment,
            Self::EncodedSeparator { .. } => AuditDenialReason::EncodedSeparator,
            Self::InvalidPercentEncoding { .. } => AuditDenialReason::InvalidPercentEncoding,
            Self::InvalidRequestConnectionHeader { .. } => {
                AuditDenialReason::InvalidRequestConnectionHeader
            }
            Self::MethodDenied { .. } => AuditDenialReason::MethodDenied,
            Self::NonOriginForm { .. } => AuditDenialReason::NonOriginForm,
            Self::PathDenied { .. } => AuditDenialReason::PathDenied,
            Self::PathTooLong { .. } => AuditDenialReason::PathTooLong,
            Self::QueryTooLong { .. } => AuditDenialReason::QueryTooLong,
            Self::RequestBodyReadFailed { .. } => AuditDenialReason::RequestBodyReadFailed,
            Self::RequestBodyTimeout { .. } => AuditDenialReason::RequestBodyTimeout,
            Self::RequestBodyTooLarge { .. } => AuditDenialReason::RequestBodyTooLarge,
            Self::RequestHeadersTooLarge { .. } => AuditDenialReason::RequestHeadersTooLarge,
            Self::TooManyRequests { .. } => AuditDenialReason::TooManyRequests,
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
            Self::EncodedSeparator => "encoded_path_separator",
            Self::InvalidPercentEncoding => "invalid_percent_encoding",
            Self::InvalidRequestConnectionHeader => "invalid_request_connection_header",
            Self::MethodDenied => "method_denied",
            Self::NonOriginForm => "non_origin_form",
            Self::PathDenied => "path_denied",
            Self::PathTooLong => "path_too_long",
            Self::QueryTooLong => "query_too_long",
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
            | Self::EncodedSeparator
            | Self::InvalidPercentEncoding
            | Self::InvalidRequestConnectionHeader
            | Self::NonOriginForm
            | Self::RequestBodyReadFailed => StatusCode::BAD_REQUEST,
            Self::ConnectUnsupported => StatusCode::METHOD_NOT_ALLOWED,
            Self::MethodDenied | Self::PathDenied => StatusCode::FORBIDDEN,
            Self::PathTooLong | Self::QueryTooLong => StatusCode::URI_TOO_LONG,
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
                AuditBodySummary::non_empty(response_body.observation()),
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
            AuditResponseErrorKind::UpstreamResponseTimeout {
                response_body,
                status,
            } => (
                "upstream_response_timeout",
                response_body.into_summary(),
                status,
            ),
        }
    }

    /// Creates a response-body-too-large response error.
    #[must_use]
    pub(crate) const fn response_body_too_large(
        response_body: OversizedResponseBody,
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

    /// Creates an upstream-response-timeout response error.
    #[must_use]
    pub(crate) const fn upstream_response_timeout(
        response_body: ObservedBodySummary,
        status: StatusCode,
    ) -> Self {
        Self {
            kind: AuditResponseErrorKind::UpstreamResponseTimeout {
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
        observed_request: ObservedAuditRequestInput,
        response_body: ObservedBodySummary,
        status: StatusCode,
    ) -> Self {
        let (request, upstream) = observed_request.into_parts();
        let outcome = AuditOutcome::allowed(response_body, status, upstream);
        Self { outcome, request }
    }

    /// Creates a denied audit event input.
    #[must_use]
    pub(crate) fn denied(denied_request: DeniedAuditRequestInput) -> Self {
        let (request, reason) = denied_request.into_parts();
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
        observed_request: ObservedAuditRequestInput,
        error: AuditResponseError,
    ) -> Self {
        let (request, upstream) = observed_request.into_parts();
        let outcome = AuditOutcome::response_error(error, upstream);
        Self { outcome, request }
    }

    /// Creates an upstream-error audit event input.
    #[must_use]
    pub(crate) fn upstream_error(
        observed_request: ObservedAuditRequestInput,
        error: AuditUpstreamError,
    ) -> Self {
        let (request, upstream) = observed_request.into_parts();
        let outcome = AuditOutcome::upstream_error(error, upstream);
        Self { outcome, request }
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
        denial: AuditDenial,
        request_id: RequestId,
        body: Option<&AccountedBody>,
        upstream_origin: UpstreamOrigin,
    ) -> DeniedAuditRequestInput {
        let (method, target, reason) = denial.into_parts();
        let request = Self::new(
            method,
            target,
            request_id,
            body.map_or_else(
                AuditBodySummary::not_observed,
                AuditBodySummary::from_request_body,
            ),
            upstream_origin,
        );
        DeniedAuditRequestInput { reason, request }
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

impl DeniedAuditRequestInput {
    /// Consumes the denied wrapper into request context and reason.
    #[must_use]
    fn into_parts(self) -> (AuditRequestInput, AuditDenialReason) {
        (self.request, self.reason)
    }
}

impl ObservedAuditRequestInput {
    /// Consumes the observed wrapper into request context and upstream target.
    #[must_use]
    fn into_parts(self) -> (AuditRequestInput, AuditUpstreamTarget) {
        (self.request, self.upstream)
    }

    /// Creates request context after the request body was observed.
    #[must_use]
    pub(crate) fn new(
        target: &AllowedTarget,
        request_id: RequestId,
        body: &AccountedBody,
        upstream_origin: UpstreamOrigin,
    ) -> Self {
        let upstream_url = upstream_origin.join_path_query(
            target.target().origin_form_path(),
            target.target().origin_form_query(),
        );
        let upstream = AuditUpstreamTarget::from_url(&upstream_url);
        let request = AuditRequestInput::new(
            target.method().clone(),
            AuditTarget::from(target.target()),
            request_id,
            AuditBodySummary::from_request_body(body),
            upstream_origin,
        );
        Self { request, upstream }
    }
}

impl AuditTarget {
    /// Creates an audit target from the raw request URI.
    ///
    /// Non-origin-form targets audit the full raw request target as the path so
    /// denial events preserve the requested authority for forensics.
    #[must_use]
    pub(crate) fn from_request_uri(uri: &Uri) -> Self {
        uri.authority().map_or_else(
            || Self::from_uri_parts(uri.path(), uri.query()),
            |authority| {
                let raw_target = uri.scheme_str().map_or_else(
                    || authority.as_str().to_owned(),
                    |scheme| format!("{scheme}://{authority}{}", uri.path()),
                );
                Self::from_uri_parts(&raw_target, uri.query())
            },
        )
    }

    /// Creates an audit target from raw request URI parts.
    #[must_use]
    pub(crate) fn from_uri_parts(path: &str, query: Option<&str>) -> Self {
        let normalized_path = if path.is_empty() { "/" } else { path };
        Self {
            path: bounded_audit_text(normalized_path, MAX_AUDIT_TARGET_PATH_BYTES),
            query: query.map(|value| bounded_audit_text(value, MAX_AUDIT_TARGET_QUERY_BYTES)),
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

impl AuditMethod {
    /// Creates a bounded audit method from an HTTP method.
    #[must_use]
    fn from_method(method: &Method) -> Self {
        Self {
            value: bounded_audit_text(method.as_str(), MAX_ALLOWED_METHOD_BYTES),
        }
    }
}

#[cfg(test)]
impl AuditUpstreamTarget {
    /// Creates an upstream target from forwarded path and query.
    #[must_use]
    fn new(path: &str, query: Option<&str>) -> Self {
        Self {
            path: OriginFormPath::parse(path).expect("test upstream path should parse"),
            query: query.map(|value| {
                OriginFormQuery::parse(value).expect("test upstream query should parse")
            }),
        }
    }
}

impl AuditUpstreamTarget {
    /// Creates an upstream target from the actual forwarded URL.
    #[must_use]
    fn from_url(url: &Url) -> Self {
        Self {
            path: OriginFormPath::parse(url.path()).expect("joined upstream path should parse"),
            query: url.query().map(|query| {
                OriginFormQuery::parse(query).expect("joined upstream query should parse")
            }),
        }
    }

    /// Consumes the upstream target into audit event fields.
    #[must_use]
    fn into_parts(self) -> (String, Option<String>) {
        (
            self.path.as_str().to_owned(),
            self.query.map(|query| query.as_str().to_owned()),
        )
    }

    /// Returns the upstream request path.
    #[must_use]
    fn path(&self) -> &str {
        self.path.as_str()
    }

    /// Returns the upstream request query.
    #[must_use]
    fn query(&self) -> Option<&str> {
        self.query.as_ref().map(OriginFormQuery::as_str)
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

impl fmt::Debug for AuditWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditWriter")
            .field("max_event_bytes", &self.max_event_bytes)
            .finish_non_exhaustive()
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
                status,
                Some(upstream),
            ),
            AuditOutcomeKind::Denied { reason } => (
                AuditDecision::Denied,
                Some(reason.error_class().to_owned()),
                AuditBodySummary::not_observed(),
                reason.status(),
                None,
            ),
            AuditOutcomeKind::ResponseError { error, upstream } => {
                let (error_class, response_body, status) = error.into_parts();
                (
                    AuditDecision::ResponseError,
                    Some(error_class.to_owned()),
                    response_body,
                    status,
                    Some(upstream),
                )
            }
            AuditOutcomeKind::UpstreamError { error, upstream } => (
                AuditDecision::UpstreamError,
                Some(error.error_class().to_owned()),
                AuditBodySummary::not_observed(),
                error.status(),
                Some(upstream),
            ),
        };
        let (upstream_path, upstream_query) = upstream.map_or((None, None), |upstream_target| {
            let (path, query) = upstream_target.into_parts();
            (Some(path), query)
        });
        Self {
            decision,
            error_class,
            method: AuditMethod::from_method(&method),
            path: target.path().to_owned(),
            query: target.query().map(str::to_owned),
            request_body,
            request_id,
            response_body,
            status: AuditStatus::from_status_code(status),
            timestamp,
            upstream_origin: upstream_origin.as_str().to_owned(),
            upstream_path,
            upstream_query,
            version: AuditSchemaVersion::CURRENT,
        }
    }
}

impl AuditWriterState {
    /// Creates append state around one concrete audit writer.
    fn new(writer: impl AuditLogWriter + 'static) -> Self {
        Self {
            poisoned: false,
            writer: Box::new(writer),
        }
    }

    /// Writes serialized audit bytes unless a previous write failed.
    async fn write_serialized(&mut self, serialized: &[u8]) -> Result<(), AuditError> {
        if self.poisoned {
            return Err(AuditError::Poisoned);
        }

        let result = write_serialized_event(&mut *self.writer, serialized).await;
        if matches!(&result, Err(AuditError::Write(_error))) {
            self.poisoned = true;
        }
        result
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
        let mut audit_file = OpenOptions::new()
            .append(true)
            .create(true)
            .read(true)
            .open(path)
            .await
            .map_err(|source| AuditError::Open {
                path: path.to_owned(),
                source,
            })?;
        match inspect_audit_log_tail(path, &mut audit_file).await? {
            AuditLogTail::Empty => {}
            AuditLogTail::Complete => validate_existing_audit_events(path, &mut audit_file).await?,
            AuditLogTail::Torn => {
                return Err(AuditError::TornLog {
                    path: path.to_owned(),
                });
            }
        }
        Ok(Self {
            max_event_bytes: config.max_audit_event_bytes(),
            state: Arc::new(Mutex::new(AuditWriterState::new(audit_file))),
        })
    }

    /// Writes one required audit event.
    ///
    /// # Errors
    ///
    /// Returns an error when the event exceeds the byte limit or writing fails.
    pub(crate) async fn write_event(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let serialized = serialize_event(event, self.max_event_bytes)?;

        self.state.lock().await.write_serialized(&serialized).await
    }
}

#[cfg(test)]
impl AuditWriter {
    /// Creates an audit writer around a supplied test writer.
    fn for_test_writer(
        writer: impl AuditLogWriter + 'static,
        max_event_bytes: AuditEventBytes,
    ) -> Self {
        Self {
            max_event_bytes,
            state: Arc::new(Mutex::new(AuditWriterState::new(writer))),
        }
    }
}

impl RequestId {
    /// Creates a request identity from a run token and sequence number.
    ///
    /// The sequence is unique within a run; the random run token makes
    /// cross-run collisions negligible under the OS RNG assumption.
    #[must_use]
    pub(crate) const fn from_parts(run_token: &RunToken, sequence: NonZeroU64) -> Self {
        Self {
            run_token: *run_token,
            sequence,
        }
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sequence = self.sequence.get();
        write!(f, "req-{}-{sequence:016x}", self.run_token)
    }
}

impl Serialize for RequestId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl RunToken {
    /// Creates a valid run token for tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn for_test(value: &str) -> Self {
        Self::new(value).expect("test run token should be valid")
    }

    /// Creates a run token from per-run entropy.
    #[must_use]
    pub(crate) const fn from_entropy(entropy: [u8; RUN_TOKEN_RANDOM_BYTES]) -> Self {
        Self { entropy }
    }

    /// Creates a fixed-width lower-hex two-part run token.
    #[cfg(test)]
    pub(crate) fn new(value: impl AsRef<str>) -> Result<Self, RunTokenError> {
        parse_run_token(value.as_ref()).map(Self::from_entropy)
    }
}

impl fmt::Display for RunToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [
            a0,
            a1,
            a2,
            a3,
            a4,
            a5,
            a6,
            a7,
            b0,
            b1,
            b2,
            b3,
            b4,
            b5,
            b6,
            b7,
        ] = self.entropy;
        write!(
            f,
            "{a0:02x}{a1:02x}{a2:02x}{a3:02x}{a4:02x}{a5:02x}{a6:02x}{a7:02x}-\
             {b0:02x}{b1:02x}{b2:02x}{b3:02x}{b4:02x}{b5:02x}{b6:02x}{b7:02x}"
        )
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

/// Returns audit text bounded to `max_bytes`, with original byte count if cut.
fn bounded_audit_text(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }

    let suffix = format!(
        "{AUDIT_TRUNCATION_PREFIX}{}{AUDIT_TRUNCATION_SUFFIX}",
        value.len()
    );
    let prefix_bytes = max_bytes
        .checked_sub(suffix.len())
        .expect("audit target bound should fit the truncation marker");
    let prefix = utf8_prefix(value, prefix_bytes);
    let capacity = prefix
        .len()
        .checked_add(suffix.len())
        .expect("bounded audit text length should fit usize");
    let mut bounded = String::with_capacity(capacity);
    bounded.push_str(&prefix);
    bounded.push_str(&suffix);
    bounded
}

/// Returns the longest UTF-8 prefix within `max_bytes`.
fn utf8_prefix(value: &str, max_bytes: usize) -> String {
    let mut prefix = String::new();
    for character in value.chars() {
        let next_len = prefix
            .len()
            .checked_add(character.len_utf8())
            .expect("UTF-8 prefix length should fit usize");
        if next_len > max_bytes {
            break;
        }
        prefix.push(character);
    }
    prefix
}

/// Inspects an existing audit log tail and maps I/O failures.
async fn inspect_audit_log_tail(
    path: &Path,
    reader: &mut dyn AuditLogTailReader,
) -> Result<AuditLogTail, AuditError> {
    classify_audit_log_tail(reader)
        .await
        .map_err(|source| AuditError::Inspect {
            path: path.to_owned(),
            source,
        })
}

/// Classifies the tail state for an existing audit log.
async fn classify_audit_log_tail(reader: &mut dyn AuditLogTailReader) -> io::Result<AuditLogTail> {
    let length = reader.seek(SeekFrom::End(0)).await?;
    if length == 0 {
        return Ok(AuditLogTail::Empty);
    }

    reader.seek(SeekFrom::End(-1)).await?;
    let mut final_byte = [0_u8; 1];
    reader.read_exact(&mut final_byte).await?;
    if final_byte == *b"\n" {
        Ok(AuditLogTail::Complete)
    } else {
        Ok(AuditLogTail::Torn)
    }
}

/// Deserializes a lowercase BLAKE3 hex digest.
fn deserialize_blake3_hex<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.len() == 64 && value.bytes().all(is_lower_hex_byte) {
        Ok(value)
    } else {
        Err(D::Error::invalid_value(
            Unexpected::Str(&value),
            &"a 64-byte lowercase hexadecimal BLAKE3 digest",
        ))
    }
}

/// Deserializes and validates the existing audit method string.
fn deserialize_existing_method<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let raw_value = String::deserialize(deserializer)?;
    let bounded_value =
        deserialize_existing_string_bounded(raw_value, MAX_ALLOWED_METHOD_BYTES, "audited method")?;
    if is_existing_audit_method(&bounded_value) {
        Ok(bounded_value)
    } else {
        Err(D::Error::invalid_value(
            Unexpected::Str(&bounded_value),
            &"a valid or truncated audited HTTP method",
        ))
    }
}

/// Returns true for method strings emitted by the current audit schema.
fn is_existing_audit_method(value: &str) -> bool {
    Method::from_bytes(value.as_bytes()).is_ok() || is_truncated_audit_method(value)
}

/// Returns true for writer-shaped truncated method strings.
fn is_truncated_audit_method(value: &str) -> bool {
    truncated_audit_text_prefix(value, MAX_ALLOWED_METHOD_BYTES)
        .is_some_and(|prefix| Method::from_bytes(prefix.as_bytes()).is_ok())
}

/// Returns true for writer-shaped truncated audit text.
fn is_truncated_audit_text(value: &str, max_bytes: usize) -> bool {
    truncated_audit_text_prefix(value, max_bytes).is_some()
}

/// Returns the untruncated prefix when audit text matches the writer shape.
fn truncated_audit_text_prefix(value: &str, max_bytes: usize) -> Option<&str> {
    let (prefix, suffix) = value.split_once(AUDIT_TRUNCATION_PREFIX)?;
    let original_bytes_text = suffix.strip_suffix(AUDIT_TRUNCATION_SUFFIX)?;
    let Ok(original_byte_count) = original_bytes_text.parse::<usize>() else {
        return None;
    };

    (value.len() == max_bytes && original_byte_count > max_bytes).then_some(prefix)
}

/// Validates an existing audit upstream path string.
fn deserialize_existing_origin_path<E>(
    raw_value: String,
    field_name: &'static str,
) -> Result<String, E>
where
    E: SerdeError,
{
    let bounded_value =
        deserialize_existing_string_bounded(raw_value, MAX_AUDIT_TARGET_PATH_BYTES, field_name)?;
    if OriginFormPath::parse(&bounded_value).is_ok() {
        Ok(bounded_value)
    } else {
        Err(E::invalid_value(
            Unexpected::Str(&bounded_value),
            &"an origin-form path accepted by the gateway",
        ))
    }
}

/// Validates an existing audit upstream query string.
fn deserialize_existing_origin_query<E>(
    raw_value: String,
    field_name: &'static str,
) -> Result<String, E>
where
    E: SerdeError,
{
    let bounded_value =
        deserialize_existing_string_bounded(raw_value, MAX_AUDIT_TARGET_QUERY_BYTES, field_name)?;
    if OriginFormQuery::parse(&bounded_value).is_ok() {
        Ok(bounded_value)
    } else {
        Err(E::invalid_value(
            Unexpected::Str(&bounded_value),
            &"an origin-form query accepted by the gateway",
        ))
    }
}

/// Deserializes and validates the existing audit path string.
fn deserialize_existing_path<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    deserialize_existing_string_bounded(value, MAX_AUDIT_TARGET_PATH_BYTES, "audit path")
}

/// Deserializes and validates the existing audit query field.
fn deserialize_existing_query<'de, D>(deserializer: D) -> Result<RequiredOption<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = RequiredOption::<String>::deserialize(deserializer)?.into_option();
    value
        .map(|query| {
            deserialize_existing_string_bounded(query, MAX_AUDIT_TARGET_QUERY_BYTES, "audit query")
        })
        .transpose()
        .map(RequiredOption::new)
}

/// Deserializes and validates the existing audit request identity.
fn deserialize_existing_request_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if is_existing_request_id(&value) {
        Ok(value)
    } else {
        Err(D::Error::invalid_value(
            Unexpected::Str(&value),
            &"a request id formatted as req-<16 hex>-<16 hex>-<16 hex>",
        ))
    }
}

/// Deserializes and validates the existing audit status code.
fn deserialize_existing_status<'de, D>(deserializer: D) -> Result<StatusCode, D::Error>
where
    D: Deserializer<'de>,
{
    let value = u16::deserialize(deserializer)?;
    StatusCode::from_u16(value).map_err(|_error| {
        D::Error::invalid_value(
            Unexpected::Unsigned(u64::from(value)),
            &"a valid HTTP status",
        )
    })
}

/// Deserializes and validates the existing audit timestamp.
fn deserialize_existing_timestamp<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let instant = humantime::parse_rfc3339(&value).map_err(|_error| {
        D::Error::invalid_value(Unexpected::Str(&value), &"an RFC 3339 timestamp")
    })?;
    let canonical = humantime::format_rfc3339_nanos(instant).to_string();
    if value == canonical {
        Ok(value)
    } else {
        Err(D::Error::invalid_value(
            Unexpected::Str(&value),
            &"an RFC 3339 timestamp in audit nanosecond format",
        ))
    }
}

/// Deserializes and validates the existing audit upstream origin.
fn deserialize_existing_upstream_origin<'de, D>(deserializer: D) -> Result<UpstreamOrigin, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    UpstreamOrigin::parse(&value).map_err(|_error| {
        D::Error::invalid_value(Unexpected::Str(&value), &"a supported upstream origin")
    })
}

/// Deserializes and validates the existing audit upstream path field.
fn deserialize_existing_upstream_path<'de, D>(
    deserializer: D,
) -> Result<RequiredOption<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = RequiredOption::<String>::deserialize(deserializer)?.into_option();
    value
        .map(|path| deserialize_existing_origin_path(path, "upstream path"))
        .transpose()
        .map(RequiredOption::new)
}

/// Deserializes and validates the existing audit upstream query field.
fn deserialize_existing_upstream_query<'de, D>(
    deserializer: D,
) -> Result<RequiredOption<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = RequiredOption::<String>::deserialize(deserializer)?.into_option();
    value
        .map(|query| deserialize_existing_origin_query(query, "upstream query"))
        .transpose()
        .map(RequiredOption::new)
}

/// Deserializes and validates the existing audit schema version.
fn deserialize_existing_version<'de, D>(deserializer: D) -> Result<AuditSchemaVersion, D::Error>
where
    D: Deserializer<'de>,
{
    let value = u8::deserialize(deserializer)?;
    if value == AuditSchemaVersion::as_u8() {
        Ok(AuditSchemaVersion::CURRENT)
    } else {
        Err(D::Error::invalid_value(
            Unexpected::Unsigned(u64::from(value)),
            &"the current audit schema version",
        ))
    }
}

/// Validates bounded audit text from an existing log line.
fn deserialize_existing_string_bounded<E>(
    value: String,
    max_bytes: usize,
    field_name: &'static str,
) -> Result<String, E>
where
    E: SerdeError,
{
    if value.len() <= max_bytes {
        Ok(value)
    } else {
        Err(E::custom(format!(
            "{field_name} must be at most {max_bytes} bytes"
        )))
    }
}

/// Returns true for lowercase hexadecimal bytes.
const fn is_lower_hex_byte(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'a'..=b'f')
}

/// Returns true for request ids emitted by the current audit schema.
fn is_existing_request_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("req-") else {
        return false;
    };
    let mut parts = rest.split('-');
    let first = parts
        .next()
        .expect("str::split yields at least one segment");
    let Some(second) = parts.next() else {
        return false;
    };
    let Some(sequence) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }

    [first, second]
        .into_iter()
        .all(|part| part.len() == 16 && part.bytes().all(is_lower_hex_byte))
        && sequence.len() == 16
        && sequence.bytes().all(is_lower_hex_byte)
        && u64::from_str_radix(sequence, 16)
            .ok()
            .and_then(NonZeroU64::new)
            .is_some()
}

/// Validates newline-terminated events in an existing audit log.
async fn validate_existing_audit_events(
    path: &Path,
    reader: &mut dyn AuditLogTailReader,
) -> Result<(), AuditError> {
    reader
        .seek(SeekFrom::Start(0))
        .await
        .map_err(|source| AuditError::Inspect {
            path: path.to_owned(),
            source,
        })?;

    let mut line_number = 1_u64;
    let mut line = Vec::new();
    let mut request_ids = HashSet::new();
    let mut buffered = BufReader::new(reader);
    loop {
        line.clear();
        let bytes_read = buffered
            .read_until(b'\n', &mut line)
            .await
            .map_err(|source| AuditError::Inspect {
                path: path.to_owned(),
                source,
            })?;
        if bytes_read == 0 {
            break;
        }
        // Callers validate existing events only after tail classification proves
        // that the log is newline-terminated.
        let _newline = line.pop();

        let numbered_line =
            NonZeroU64::new(line_number).expect("audit log line numbering starts at one");
        let event = serde_json::from_slice::<ExistingAuditEvent>(&line).map_err(|source| {
            AuditError::CorruptLog {
                path: path.to_owned(),
                line: numbered_line,
                source,
            }
        })?;
        if !request_ids.insert(event.request_id().to_owned()) {
            return Err(AuditError::CorruptLog {
                path: path.to_owned(),
                line: numbered_line,
                source: <serde_json::Error as SerdeError>::custom("duplicate audit request id"),
            });
        }
        event.consume();
        line_number = line_number
            .checked_add(1)
            .expect("audit log line count should not overflow");
    }

    buffered
        .get_mut()
        .seek(SeekFrom::End(0))
        .await
        .map_err(|source| AuditError::Inspect {
            path: path.to_owned(),
            source,
        })?;
    Ok(())
}

/// Parses a run token into its entropy bytes.
#[cfg(test)]
fn parse_run_token(text: &str) -> Result<[u8; RUN_TOKEN_RANDOM_BYTES], RunTokenError> {
    if text.is_empty() {
        return Err(RunTokenError::Empty);
    }
    if text.len() > RUN_TOKEN_BYTES {
        return Err(RunTokenError::TooLong);
    }

    let &[
        d0,
        d1,
        d2,
        d3,
        d4,
        d5,
        d6,
        d7,
        d8,
        d9,
        d10,
        d11,
        d12,
        d13,
        d14,
        d15,
        separator,
        d16,
        d17,
        d18,
        d19,
        d20,
        d21,
        d22,
        d23,
        d24,
        d25,
        d26,
        d27,
        d28,
        d29,
        d30,
        d31,
    ] = text.as_bytes()
    else {
        if has_invalid_run_token_character(text) {
            return Err(RunTokenError::InvalidCharacter);
        }
        return Err(RunTokenError::InvalidShape);
    };

    let pairs = [
        (d0, d1),
        (d2, d3),
        (d4, d5),
        (d6, d7),
        (d8, d9),
        (d10, d11),
        (d12, d13),
        (d14, d15),
        (d16, d17),
        (d18, d19),
        (d20, d21),
        (d22, d23),
        (d24, d25),
        (d26, d27),
        (d28, d29),
        (d30, d31),
    ];

    if pairs
        .iter()
        .copied()
        .any(|(high, low)| high == b'-' || low == b'-')
    {
        return Err(RunTokenError::InvalidShape);
    }
    if separator != b'-' {
        if token_nibble(separator).is_none() {
            return Err(RunTokenError::InvalidCharacter);
        }
        return Err(RunTokenError::InvalidShape);
    }

    let mut entropy = [0_u8; RUN_TOKEN_RANDOM_BYTES];
    for (byte, (high, low)) in entropy.iter_mut().zip(pairs) {
        *byte = parse_run_token_byte(high, low)?;
    }
    Ok(entropy)
}

/// Returns whether text contains a byte that cannot appear in a run token.
#[cfg(test)]
fn has_invalid_run_token_character(text: &str) -> bool {
    text.bytes()
        .any(|byte| byte != b'-' && token_nibble(byte).is_none())
}

/// Parses one run-token byte from a high and low lower-hex digit.
#[cfg(test)]
fn parse_run_token_byte(high: u8, low: u8) -> Result<u8, RunTokenError> {
    let high_nibble = token_nibble(high).ok_or(RunTokenError::InvalidCharacter)?;
    let low_nibble = token_nibble(low).ok_or(RunTokenError::InvalidCharacter)?;
    Ok((high_nibble << 4_u8) | low_nibble)
}

/// Converts a lower-hex digit to a nibble.
#[cfg(test)]
const fn token_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0' => Some(0),
        b'1' => Some(1),
        b'2' => Some(2),
        b'3' => Some(3),
        b'4' => Some(4),
        b'5' => Some(5),
        b'6' => Some(6),
        b'7' => Some(7),
        b'8' => Some(8),
        b'9' => Some(9),
        b'a' => Some(10),
        b'b' => Some(11),
        b'c' => Some(12),
        b'd' => Some(13),
        b'e' => Some(14),
        b'f' => Some(15),
        _other => None,
    }
}

/// Serializes one bounded audit event as NDJSON bytes.
fn serialize_event(
    event: &AuditEvent,
    max_event_bytes: AuditEventBytes,
) -> Result<Vec<u8>, AuditError> {
    let mut serialized = serialize_json_event(event);
    serialized.push(b'\n');
    let max = max_event_bytes.get();
    if serialized.len() > max {
        return Err(AuditError::EventTooLarge {
            bytes: serialized.len(),
            max,
        });
    }
    Ok(serialized)
}

/// Serializes the current audit event schema.
fn serialize_json_event(event: &AuditEvent) -> Vec<u8> {
    serde_json::to_vec(event).expect("audit events contain only infallible JSON values")
}

/// Writes serialized audit bytes to the supplied writer.
async fn write_serialized_event<W>(writer: &mut W, serialized: &[u8]) -> Result<(), AuditError>
where
    W: AsyncWrite + Unpin + ?Sized,
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
        AcceptedAuditTarget, AuditBodySummary, AuditDecision, AuditDenial, AuditDenialReason,
        AuditError, AuditEvent, AuditEventInput, AuditLogTail, AuditOutcome, AuditRequestInput,
        AuditResponseError, AuditResponseHeaderError, AuditSchemaVersion, AuditTarget,
        AuditTimestamp, AuditUpstreamError, AuditUpstreamTarget, AuditWriter,
        ExistingAuditBodySummary, ExistingAuditDecision, ExistingAuditErrorClass,
        ExistingAuditEventFields, MAX_AUDIT_TARGET_PATH_BYTES, MAX_AUDIT_TARGET_QUERY_BYTES,
        ObservedBodySummary, PreparsedAuditTarget, RUN_TOKEN_BYTES, RejectedAuditTarget, RequestId,
        RequiredOption, RunToken, RunTokenError, classify_audit_log_tail, inspect_audit_log_tail,
        is_existing_request_id, is_truncated_audit_method, validate_existing_audit_events,
        write_serialized_event,
    };
    use crate::allowlist::{AcceptedTarget, AllowlistRejectionReason, TargetRejectionReason};
    use crate::body::{
        BodyObservation, NonEmptyBodyObservation, OversizedResponseBody, ResponseAccount,
    };
    use crate::config::{
        AuditEventBytes, GatewayConfig, MAX_ALLOWED_METHOD_BYTES, MIN_AUDIT_EVENT_BYTES,
        ResponseBodyBytes, UpstreamOrigin,
    };
    use crate::target::{MAX_ORIGIN_FORM_PATH_BYTES, MAX_ORIGIN_FORM_QUERY_BYTES};
    use ::http::{Method, StatusCode, Uri};
    use core::num::{NonZeroU64, NonZeroUsize};
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use core::time::Duration;
    use pretty_assertions::assert_eq;
    use serde_json::{Map, Value};
    use std::io::SeekFrom;
    use std::path::{Path, PathBuf};
    #[cfg(unix)]
    use std::process::Command;
    use std::sync::{Arc as StdArc, Mutex as StdMutex};
    use std::time::UNIX_EPOCH;
    use std::{fs, io};
    use tempfile::tempdir;
    use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

    /// Test writer that fails one write operation class.
    #[derive(Debug)]
    struct FailingWriter {
        /// Operation that should fail.
        failure: WriterFailure,
    }

    /// Test writer that writes a prefix, then fails the next write.
    #[derive(Debug)]
    struct PartialWriteThenFailWriter {
        /// Bytes successfully written before failure.
        bytes: SharedWrittenBytes,
        /// Prefix bytes to write before failing.
        prefix_bytes: usize,
        /// Write calls observed by the writer.
        write_calls: u8,
    }

    /// Shared captured bytes from a test writer.
    type SharedWrittenBytes = StdArc<StdMutex<Vec<u8>>>;

    /// Test writer failure mode.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum WriterFailure {
        /// Fail flushes.
        Flush,

        /// Fail writes.
        Write,
    }

    impl PartialWriteThenFailWriter {
        /// Creates a writer that writes `prefix_bytes` before failing.
        fn new(bytes: SharedWrittenBytes, prefix_bytes: usize) -> Self {
            Self {
                bytes,
                prefix_bytes,
                write_calls: 0,
            }
        }
    }

    /// Test reader that can fail one audit-tail inspection operation.
    #[derive(Debug)]
    pub(super) struct TailReader {
        /// Reader bytes.
        bytes: Vec<u8>,
        /// Failure mode.
        failure: Option<TailReaderFailure>,
        /// Current position.
        position: usize,
        /// Seek call count.
        seek_calls: u8,
    }

    /// Test audit-tail reader failure mode.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum TailReaderFailure {
        /// Fail the second seek.
        FinalSeek,
        /// Fail the first seek.
        InitialSeek,
        /// Fail the final-byte read.
        Read,
    }

    impl TailReader {
        /// Creates a failing test reader.
        pub(super) fn failing(bytes: impl Into<Vec<u8>>, failure: TailReaderFailure) -> Self {
            Self {
                bytes: bytes.into(),
                failure: Some(failure),
                position: 0,
                seek_calls: 0,
            }
        }

        /// Creates a successful test reader.
        pub(super) fn new(bytes: impl Into<Vec<u8>>) -> Self {
            Self {
                bytes: bytes.into(),
                failure: None,
                position: 0,
                seek_calls: 0,
            }
        }

        /// Converts a seek request into a test-reader position.
        fn seek_position(&self, position: SeekFrom) -> io::Result<usize> {
            match position {
                SeekFrom::Start(offset) => usize::try_from(offset).map_err(|_error| {
                    io::Error::new(io::ErrorKind::InvalidInput, "seek offset too large")
                }),
                SeekFrom::End(0) => Ok(self.bytes.len()),
                SeekFrom::End(-1) => self.bytes.len().checked_sub(1).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "negative seek offset")
                }),
                SeekFrom::End(_offset) | SeekFrom::Current(_offset) => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported test seek",
                )),
            }
        }
    }

    impl AsyncRead for TailReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.failure == Some(TailReaderFailure::Read) {
                return Poll::Ready(Err(io::Error::other("read failed")));
            }
            let Some(available) = self.bytes.len().checked_sub(self.position) else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "test read position out of bounds",
                )));
            };
            let length = available.min(buf.remaining());
            let end = self
                .position
                .checked_add(length)
                .expect("test read position should not overflow");
            let chunk = self.bytes.get(self.position..end).ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "test read out of bounds")
            });
            match chunk {
                Ok(bytes) => {
                    buf.put_slice(bytes);
                    self.position = end;
                    Poll::Ready(Ok(()))
                }
                Err(error) => Poll::Ready(Err(error)),
            }
        }
    }

    impl AsyncSeek for TailReader {
        fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
            let position =
                u64::try_from(self.position).expect("test reader position should fit in u64");
            Poll::Ready(Ok(position))
        }

        fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
            self.seek_calls = self
                .seek_calls
                .checked_add(1)
                .expect("test seek count should not overflow");
            match (self.failure, self.seek_calls) {
                (Some(TailReaderFailure::InitialSeek), 1) => {
                    Err(io::Error::other("initial seek failed"))
                }
                (Some(TailReaderFailure::FinalSeek), 2) => {
                    Err(io::Error::other("final seek failed"))
                }
                _ => {
                    self.position = self.seek_position(position)?;
                    Ok(())
                }
            }
        }
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

    impl AsyncWrite for PartialWriteThenFailWriter {
        fn is_write_vectored(&self) -> bool {
            false
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.write_calls > 0 {
                return Poll::Ready(Err(io::Error::other("partial write failed")));
            }

            let length = self.prefix_bytes.min(buf.len());
            let prefix = buf
                .get(..length)
                .expect("prefix length should be bounded by buffer length");
            self.bytes
                .lock()
                .expect("written bytes should lock")
                .extend_from_slice(prefix);
            self.write_calls = self
                .write_calls
                .checked_add(1)
                .expect("test write count should not overflow");
            Poll::Ready(Ok(length))
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            let Some(first) = bufs.iter().find(|buf| !buf.is_empty()) else {
                return Poll::Ready(Ok(0));
            };
            self.poll_write(cx, first)
        }
    }

    /// Builds a non-zero request sequence for tests.
    fn request_sequence(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).expect("test request sequence should be non-zero")
    }

    /// Returns the observation for non-empty test body bytes.
    fn non_empty_body(bytes: &[u8]) -> NonEmptyBodyObservation {
        NonEmptyBodyObservation::for_test(bytes)
    }

    /// Returns the oversized response body observed when `bytes` crosses a tiny limit.
    pub(super) fn oversized_response_body(bytes: &[u8]) -> OversizedResponseBody {
        let mut account = ResponseAccount::new(ResponseBodyBytes::for_test(
            NonZeroU64::new(1).expect("limit should be non-zero"),
        ));
        account
            .add_chunk(bytes)
            .expect_err("test body should exceed the tiny limit")
    }

    /// Returns the fixed upstream origin used by unit-test fixtures.
    fn upstream_origin() -> UpstreamOrigin {
        UpstreamOrigin::parse("https://api.openai.com").expect("origin should parse")
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
            RequestId::from_parts(
                &RunToken::for_test("000000000000000a-000000000000000b"),
                request_sequence(1),
            ),
            body,
            upstream_origin(),
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

    /// Builds valid writer-shaped denied existing audit event lines.
    pub(super) fn denial_existing_event_lines() -> Vec<(&'static str, Vec<u8>)> {
        let absolute_form_too_long = format!(
            "http://evil.example/{}",
            "a".repeat(MAX_AUDIT_TARGET_PATH_BYTES)
        );
        let path_too_long = format!("/{}", "a".repeat(MAX_AUDIT_TARGET_PATH_BYTES));
        let query_too_long = "q".repeat(MAX_AUDIT_TARGET_QUERY_BYTES + 1);

        Vec::from([
            (
                "absolute form unsupported",
                serialized_denial_event_line(
                    "GET",
                    AuditTarget::from_uri_parts("http://evil.example/steal", None),
                    AuditDenialReason::AbsoluteFormUnsupported,
                ),
            ),
            (
                "absolute form unsupported with truncated target",
                serialized_denial_event_line(
                    "GET",
                    AuditTarget::from_uri_parts(&absolute_form_too_long, None),
                    AuditDenialReason::AbsoluteFormUnsupported,
                ),
            ),
            (
                "connect unsupported",
                serialized_denial_event_line(
                    "CONNECT",
                    AuditTarget::from_uri_parts("evil.example:443", None),
                    AuditDenialReason::ConnectUnsupported,
                ),
            ),
            (
                "dot segment",
                serialized_denial_event_line(
                    "GET",
                    AuditTarget::from_uri_parts("/v1/../models", None),
                    AuditDenialReason::DotSegment,
                ),
            ),
            (
                "encoded separator",
                serialized_denial_event_line(
                    "GET",
                    AuditTarget::from_uri_parts("/v1/%2fmodels", None),
                    AuditDenialReason::EncodedSeparator,
                ),
            ),
            (
                "invalid percent encoding",
                serialized_denial_event_line(
                    "GET",
                    AuditTarget::from_uri_parts("/v1/%zz", None),
                    AuditDenialReason::InvalidPercentEncoding,
                ),
            ),
            (
                "non-origin form",
                serialized_denial_event_line(
                    "GET",
                    AuditTarget::from_uri_parts("*", None),
                    AuditDenialReason::NonOriginForm,
                ),
            ),
            (
                "path too long",
                serialized_denial_event_line(
                    "GET",
                    AuditTarget::from_uri_parts(&path_too_long, None),
                    AuditDenialReason::PathTooLong,
                ),
            ),
            (
                "query too long",
                serialized_denial_event_line(
                    "GET",
                    AuditTarget::from_uri_parts("/v1/models", Some(&query_too_long)),
                    AuditDenialReason::QueryTooLong,
                ),
            ),
            (
                "request body timeout",
                serialized_unobserved_denial_event_line(AuditDenialReason::RequestBodyTimeout),
            ),
            (
                "too many requests",
                serialized_denial_event_line(
                    "CONNECT",
                    AuditTarget::from_uri_parts("evil.example:443", None),
                    AuditDenialReason::TooManyRequests,
                ),
            ),
        ])
    }

    /// Builds one valid serialized denial event line.
    fn serialized_denial_event_line(
        method: &str,
        target: AuditTarget,
        reason: AuditDenialReason,
    ) -> Vec<u8> {
        serialized_audit_event_line(&AuditEvent::new(denied_input(method, target, reason)))
    }

    /// Builds one valid serialized audit event line.
    pub(super) fn serialized_denied_event_line() -> Vec<u8> {
        serialized_audit_event_line(&denied_event())
    }

    /// Builds one valid serialized audit event line.
    fn serialized_audit_event_line(event: &AuditEvent) -> Vec<u8> {
        let mut line = serde_json::to_vec(event).expect("event should serialize");
        line.push(b'\n');
        line
    }

    /// Builds a serialized denial line whose request body was not observed.
    fn serialized_unobserved_denial_event_line(reason: AuditDenialReason) -> Vec<u8> {
        let request = request_input(
            "GET",
            AuditTarget::from_uri_parts("/v1/models", None),
            AuditBodySummary::not_observed(),
        );
        serialized_audit_event_line(&AuditEvent::new(AuditEventInput::new(
            request,
            AuditOutcome::denied(reason),
        )))
    }

    /// Builds one valid serialized audit event value.
    pub(super) fn serialized_denied_event_value() -> Value {
        serde_json::from_slice(&serialized_denied_event_line())
            .expect("serialized event line should parse as JSON")
    }

    /// Builds one valid serialized audit event line from a JSON value.
    pub(super) fn serialized_event_value_line(value: &Value) -> Vec<u8> {
        let mut line = serde_json::to_vec(value).expect("event value should serialize");
        line.push(b'\n');
        line
    }

    /// Builds one valid non-empty body summary JSON value.
    pub(super) fn non_empty_body_value() -> Value {
        Value::Object(Map::from_iter([
            ("blake3".to_owned(), Value::String("0".repeat(64))),
            ("bytes".to_owned(), Value::from(1_u64)),
            ("state".to_owned(), Value::String("non_empty".to_owned())),
        ]))
    }

    /// Builds one serialized audit event line with one field replaced.
    pub(super) fn serialized_event_line_with_field(field: &'static str, value: Value) -> Vec<u8> {
        serialized_event_line_with_fields([(field, value)])
    }

    /// Builds one serialized audit event line with fields replaced.
    pub(super) fn serialized_event_line_with_fields<const N: usize>(
        fields: [(&'static str, Value); N],
    ) -> Vec<u8> {
        let mut event = serialized_denied_event_value();
        let object = event
            .as_object_mut()
            .expect("serialized event should be an object");
        for (field, value) in fields {
            object.insert(field.to_owned(), value);
        }
        serialized_event_value_line(&event)
    }

    /// Builds one serialized audit event line with one field removed.
    pub(super) fn serialized_event_line_without_field(field: &'static str) -> Vec<u8> {
        let mut event = serialized_denied_event_value();
        let object = event
            .as_object_mut()
            .expect("serialized event should be an object");
        object
            .remove(field)
            .expect("serialized event should contain field");
        serialized_event_value_line(&event)
    }

    /// Covers in-place deserialization for required nullable fields.
    pub(super) fn required_nullable_fields_deserialize_in_place() {
        let mut nullable = RequiredOption::<String>::new(None);
        let mut nullable_deserializer = serde_json::Deserializer::from_str("\"present\"");

        <RequiredOption<String> as serde::Deserialize>::deserialize_in_place(
            &mut nullable_deserializer,
            &mut nullable,
        )
        .expect("required nullable field should deserialize in place");

        assert_eq!(nullable.into_option(), Some("present".to_owned()));

        let mut invalid_nullable = RequiredOption::<String>::new(None);
        let mut invalid_nullable_deserializer = serde_json::Deserializer::from_str("false");
        let invalid_nullable_error =
            <RequiredOption<String> as serde::Deserialize>::deserialize_in_place(
                &mut invalid_nullable_deserializer,
                &mut invalid_nullable,
            )
            .expect_err("invalid nullable field should fail in-place deserialization");

        assert!(
            invalid_nullable_error.to_string().contains("invalid type"),
            "unexpected required nullable field error: {invalid_nullable_error}"
        );

        let mut fields =
            serde_json::from_value::<ExistingAuditEventFields>(serialized_denied_event_value())
                .expect("existing audit event fields should parse");
        let mut event = serialized_denied_event_value();
        let object = event
            .as_object_mut()
            .expect("serialized event should be an object");
        object.insert("query".to_owned(), Value::String("limit=1".to_owned()));
        let serialized_event = serde_json::to_vec(&event).expect("event should serialize");
        let mut fields_deserializer = serde_json::Deserializer::from_slice(&serialized_event);

        <ExistingAuditEventFields as serde::Deserialize>::deserialize_in_place(
            &mut fields_deserializer,
            &mut fields,
        )
        .expect("existing audit event fields should deserialize in place");

        assert_eq!(fields.query.as_deref(), Some("limit=1"));

        let missing_query = serialized_event_line_without_field("query");
        let mut missing_query_deserializer = serde_json::Deserializer::from_slice(&missing_query);
        let missing_query_error =
            <ExistingAuditEventFields as serde::Deserialize>::deserialize_in_place(
                &mut missing_query_deserializer,
                &mut fields,
            )
            .expect_err("missing query should fail in-place deserialization");

        assert!(
            missing_query_error
                .to_string()
                .contains("missing field `query`"),
            "unexpected existing audit fields error: {missing_query_error}"
        );
    }

    /// Covers value deserialization for present required nullable fields.
    pub(super) fn required_nullable_fields_deserialize_present_values() {
        let event = AuditEvent::new(AuditEventInput::new(
            request_input(
                "GET",
                AuditTarget::from_uri_parts("/v1/models", Some("limit=1")),
                AuditBodySummary::empty(),
            ),
            AuditOutcome::allowed(
                ObservedBodySummary::Empty,
                StatusCode::OK,
                AuditUpstreamTarget::new("/v1/models", Some("limit=1")),
            ),
        ));
        let event_value = serde_json::from_slice::<Value>(&serialized_audit_event_line(&event))
            .expect("serialized allowed event line should parse as JSON");
        let fields = serde_json::from_value::<ExistingAuditEventFields>(event_value)
            .expect("allowed event fields should parse from a JSON value");

        assert_eq!(fields.error_class, None);
        assert_eq!(fields.query.as_deref(), Some("limit=1"));
        assert_eq!(fields.upstream_path.as_deref(), Some("/v1/models"));
        assert_eq!(fields.upstream_query.as_deref(), Some("limit=1"));

        for (field, invalid_value) in [
            ("status", Value::from(99_u64)),
            ("timestamp", Value::String("not-a-timestamp".to_owned())),
            ("upstream_origin", Value::String("not-a-url".to_owned())),
        ] {
            let mut invalid = serialized_denied_event_value();
            let object = invalid
                .as_object_mut()
                .expect("serialized event should be an object");
            object.insert(field.to_owned(), invalid_value);
            serde_json::from_value::<ExistingAuditEventFields>(invalid)
                .expect_err("invalid audit event value should fail deserialization");
        }
    }

    /// Covers duplicate request-id rejection for existing audit logs.
    pub(super) async fn duplicate_existing_request_ids_reject() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("duplicate.ndjson");
        let line = serialized_denied_event_line();
        let contents = [line.as_slice(), line.as_slice()].concat();

        fs::write(&audit_log, contents).expect("duplicate log should be written");
        let result =
            AuditWriter::open(&GatewayConfig::for_test(audit_log, roomy_event_limit())).await;

        assert!(matches!(result, Err(super::AuditError::CorruptLog { .. })));
    }

    #[test]
    fn required_nullable_fields_deserialize_in_place_in_unit_tests() {
        required_nullable_fields_deserialize_in_place();
        required_nullable_fields_deserialize_present_values();
    }

    #[tokio::test]
    async fn duplicate_existing_request_ids_reject_in_unit_tests() {
        duplicate_existing_request_ids_reject().await;
    }

    /// Builds one valid non-empty body summary with a custom digest.
    fn non_empty_body_value_with_digest(digest: String) -> Value {
        let mut body = non_empty_body_value();
        body.as_object_mut()
            .expect("body summary should be an object")
            .insert("blake3".to_owned(), Value::String(digest));
        body
    }

    /// Builds schema-invalid existing audit event lines.
    pub(super) fn schema_invalid_existing_event_lines() -> Vec<(&'static str, Vec<u8>)> {
        let too_long_method = "A".repeat(MAX_ALLOWED_METHOD_BYTES + 1);
        let too_long_path = "x".repeat(MAX_ORIGIN_FORM_PATH_BYTES + 1);
        let too_long_query = "x".repeat(MAX_ORIGIN_FORM_QUERY_BYTES + 1);

        let mut lines = Vec::new();
        lines.extend(schema_invalid_existing_target_lines(
            too_long_method,
            too_long_path.clone(),
            too_long_query.clone(),
        ));
        lines.extend(schema_invalid_existing_body_lines());
        lines.extend(schema_invalid_existing_identity_lines());
        lines.extend(schema_invalid_existing_metadata_lines(
            too_long_path,
            too_long_query,
        ));
        lines
    }

    /// Builds schema-invalid body field lines.
    fn schema_invalid_existing_body_lines() -> [(&'static str, Vec<u8>); 2] {
        [
            (
                "invalid body digest",
                serialized_event_line_with_field(
                    "request_body",
                    non_empty_body_value_with_digest("g".repeat(64)),
                ),
            ),
            (
                "short body digest",
                serialized_event_line_with_field(
                    "request_body",
                    non_empty_body_value_with_digest("0".repeat(63)),
                ),
            ),
        ]
    }

    /// Builds schema-invalid request identity lines.
    fn schema_invalid_existing_identity_lines() -> [(&'static str, Vec<u8>); 5] {
        [
            (
                "invalid request id",
                serialized_event_line_with_field(
                    "request_id",
                    Value::String("req-not-a-request-id".to_owned()),
                ),
            ),
            (
                "short request id part",
                serialized_event_line_with_field(
                    "request_id",
                    Value::String(
                        "req-00000000000000-000000000000000b-0000000000000001".to_owned(),
                    ),
                ),
            ),
            (
                "zero request id sequence",
                serialized_event_line_with_field(
                    "request_id",
                    Value::String(
                        "req-000000000000000a-000000000000000b-0000000000000000".to_owned(),
                    ),
                ),
            ),
            (
                "short request id sequence",
                serialized_event_line_with_field(
                    "request_id",
                    Value::String(
                        "req-000000000000000a-000000000000000b-00000000000000".to_owned(),
                    ),
                ),
            ),
            (
                "invalid request id sequence hex",
                serialized_event_line_with_field(
                    "request_id",
                    Value::String(
                        "req-000000000000000a-000000000000000b-000000000000000g".to_owned(),
                    ),
                ),
            ),
        ]
    }

    /// Builds schema-invalid metadata and upstream field lines.
    fn schema_invalid_existing_metadata_lines(
        too_long_path: String,
        too_long_query: String,
    ) -> [(&'static str, Vec<u8>); 16] {
        [
            (
                "missing error class",
                serialized_event_line_without_field("error_class"),
            ),
            (
                "missing query",
                serialized_event_line_without_field("query"),
            ),
            (
                "missing upstream path",
                serialized_event_line_without_field("upstream_path"),
            ),
            (
                "missing upstream query",
                serialized_event_line_without_field("upstream_query"),
            ),
            (
                "invalid status",
                serialized_event_line_with_field("status", Value::from(99_u64)),
            ),
            (
                "invalid timestamp",
                serialized_event_line_with_field(
                    "timestamp",
                    Value::String("not-a-timestamp".to_owned()),
                ),
            ),
            (
                "non-canonical timestamp without nanos",
                serialized_event_line_with_field(
                    "timestamp",
                    Value::String("1970-01-01T00:00:00Z".to_owned()),
                ),
            ),
            (
                "non-canonical timestamp with short fraction",
                serialized_event_line_with_field(
                    "timestamp",
                    Value::String("1970-01-01T00:00:00.1Z".to_owned()),
                ),
            ),
            (
                "invalid upstream origin",
                serialized_event_line_with_field(
                    "upstream_origin",
                    Value::String("ftp://api.openai.com".to_owned()),
                ),
            ),
            (
                "too-long upstream path",
                serialized_event_line_with_field("upstream_path", Value::String(too_long_path)),
            ),
            (
                "invalid upstream path",
                serialized_event_line_with_field(
                    "upstream_path",
                    Value::String("not-origin-form".to_owned()),
                ),
            ),
            (
                "upstream path with component delimiter",
                serialized_event_line_with_field(
                    "upstream_path",
                    Value::String("/v1/models?limit=1".to_owned()),
                ),
            ),
            (
                "too-long upstream query",
                serialized_event_line_with_field("upstream_query", Value::String(too_long_query)),
            ),
            (
                "invalid upstream query",
                serialized_event_line_with_field(
                    "upstream_query",
                    Value::String("bad=%zz".to_owned()),
                ),
            ),
            (
                "upstream query with fragment delimiter",
                serialized_event_line_with_field(
                    "upstream_query",
                    Value::String("limit=1#fragment".to_owned()),
                ),
            ),
            (
                "invalid version",
                serialized_event_line_with_field("version", Value::from(4_u64)),
            ),
        ]
    }

    /// Builds schema-invalid method and target field lines.
    fn schema_invalid_existing_target_lines(
        too_long_method: String,
        too_long_path: String,
        too_long_query: String,
    ) -> [(&'static str, Vec<u8>); 5] {
        [
            (
                "empty method",
                serialized_event_line_with_field("method", Value::String(String::new())),
            ),
            (
                "too-long method",
                serialized_event_line_with_field("method", Value::String(too_long_method)),
            ),
            (
                "invalid method token",
                serialized_event_line_with_field("method", Value::String("bad method".to_owned())),
            ),
            (
                "too-long path",
                serialized_event_line_with_field("path", Value::String(too_long_path)),
            ),
            (
                "too-long query",
                serialized_event_line_with_field("query", Value::String(too_long_query)),
            ),
        ]
    }

    /// Builds semantically invalid existing audit event lines.
    pub(super) fn semantic_invalid_existing_event_lines() -> Vec<(&'static str, Vec<u8>)> {
        let mut lines = Vec::new();
        lines.extend(semantic_invalid_decision_lines());
        lines.extend(semantic_invalid_denial_shape_lines());
        lines.extend(semantic_invalid_response_header_lines());
        lines.extend(semantic_invalid_response_body_lines());
        lines.extend(semantic_invalid_upstream_lines());
        lines
    }

    /// Builds decision-level semantically invalid existing audit event lines.
    fn semantic_invalid_decision_lines() -> [(&'static str, Vec<u8>); 10] {
        [
            (
                "allowed with error class",
                serialized_event_line_with_fields([
                    ("decision", Value::String("allowed".to_owned())),
                    ("upstream_path", Value::String("/v1/models".to_owned())),
                ]),
            ),
            (
                "allowed with unobserved response body",
                serialized_event_line_with_fields([
                    ("decision", Value::String("allowed".to_owned())),
                    ("error_class", Value::Null),
                    ("status", Value::from(200_u64)),
                    ("upstream_path", Value::String("/v1/models".to_owned())),
                ]),
            ),
            (
                "allowed CONNECT",
                serialized_event_line_with_fields([
                    ("decision", Value::String("allowed".to_owned())),
                    ("error_class", Value::Null),
                    ("method", Value::String("CONNECT".to_owned())),
                    ("request_body", non_empty_body_value()),
                    ("response_body", non_empty_body_value()),
                    ("status", Value::from(200_u64)),
                    ("upstream_path", Value::String("/v1/models".to_owned())),
                ]),
            ),
            (
                "denied with response error class",
                serialized_event_line_with_field(
                    "error_class",
                    Value::String("response_headers_too_large".to_owned()),
                ),
            ),
            (
                "connect unsupported with GET",
                serialized_event_line_with_fields([
                    (
                        "error_class",
                        Value::String("connect_unsupported".to_owned()),
                    ),
                    ("method", Value::String("GET".to_owned())),
                    ("status", Value::from(405_u64)),
                ]),
            ),
            (
                "failed without error class",
                serialized_event_line_with_field("error_class", Value::Null),
            ),
            (
                "request body timeout with observed request body",
                serialized_event_line_with_fields([
                    (
                        "error_class",
                        Value::String("request_body_timeout".to_owned()),
                    ),
                    ("request_body", empty_body_value()),
                    ("status", Value::from(408_u64)),
                ]),
            ),
            (
                "denied with response body",
                serialized_event_line_with_field("response_body", non_empty_body_value()),
            ),
            (
                "denied with upstream path",
                serialized_event_line_with_field(
                    "upstream_path",
                    Value::String("/v1/models".to_owned()),
                ),
            ),
            (
                "denied with upstream query",
                serialized_event_line_with_field(
                    "upstream_query",
                    Value::String("limit=1".to_owned()),
                ),
            ),
        ]
    }

    /// Builds denial-target semantically invalid existing audit event lines.
    fn semantic_invalid_denial_shape_lines() -> [(&'static str, Vec<u8>); 7] {
        let absolute_form_too_long = AuditTarget::from_uri_parts(
            &format!(
                "http://evil.example/{}",
                "a".repeat(MAX_AUDIT_TARGET_PATH_BYTES)
            ),
            None,
        );

        [
            (
                "method denied with non-origin target",
                serialized_event_line_with_fields([
                    ("path", Value::String("not-origin-form".to_owned())),
                    ("status", Value::from(403_u64)),
                ]),
            ),
            (
                "dot segment denial with encoded separator target",
                serialized_event_line_with_fields([
                    ("error_class", Value::String("dot_segment".to_owned())),
                    ("path", Value::String("/v1/%2fmodels".to_owned())),
                    ("status", Value::from(400_u64)),
                ]),
            ),
            (
                "non-origin-form denial with origin target",
                serialized_event_line_with_fields([
                    ("error_class", Value::String("non_origin_form".to_owned())),
                    ("path", Value::String("/v1/models".to_owned())),
                    ("status", Value::from(400_u64)),
                ]),
            ),
            (
                "path too long without truncated path",
                serialized_event_line_with_fields([
                    ("error_class", Value::String("path_too_long".to_owned())),
                    ("path", Value::String("/v1/models".to_owned())),
                    ("status", Value::from(414_u64)),
                ]),
            ),
            (
                "path too long with authority target",
                serialized_event_line_with_fields([
                    ("error_class", Value::String("path_too_long".to_owned())),
                    (
                        "path",
                        Value::String(absolute_form_too_long.path().to_owned()),
                    ),
                    ("status", Value::from(414_u64)),
                ]),
            ),
            (
                "query too long with non-origin target",
                serialized_event_line_with_fields([
                    ("error_class", Value::String("query_too_long".to_owned())),
                    ("path", Value::String("*".to_owned())),
                    (
                        "query",
                        Value::String("q".repeat(MAX_AUDIT_TARGET_QUERY_BYTES)),
                    ),
                    ("status", Value::from(414_u64)),
                ]),
            ),
            (
                "query too long without truncated query",
                serialized_event_line_with_fields([
                    ("error_class", Value::String("query_too_long".to_owned())),
                    ("query", Value::String("limit=1".to_owned())),
                    ("status", Value::from(414_u64)),
                ]),
            ),
        ]
    }

    /// Builds valid response-error existing audit event lines.
    pub(super) fn response_error_existing_event_lines() -> [(&'static str, Vec<u8>); 6] {
        [
            (
                "invalid response connection header",
                response_error_existing_event_line(
                    "invalid_response_connection_header",
                    Value::from(502_u64),
                    not_observed_body_value(),
                ),
            ),
            (
                "response header error",
                response_error_existing_event_line(
                    "response_headers_too_large",
                    Value::from(502_u64),
                    not_observed_body_value(),
                ),
            ),
            (
                "response body too large",
                response_error_existing_event_line(
                    "response_body_too_large",
                    Value::from(200_u64),
                    non_empty_body_value(),
                ),
            ),
            (
                "downstream closed",
                response_error_existing_event_line(
                    "downstream_closed",
                    Value::from(200_u64),
                    non_empty_body_value(),
                ),
            ),
            (
                "upstream response stream failed",
                response_error_existing_event_line(
                    "upstream_response_stream_failed",
                    Value::from(200_u64),
                    non_empty_body_value(),
                ),
            ),
            (
                "upstream response timeout",
                response_error_existing_event_line(
                    "upstream_response_timeout",
                    Value::from(200_u64),
                    non_empty_body_value(),
                ),
            ),
        ]
    }

    /// Builds one valid response-error existing audit event line.
    fn response_error_existing_event_line(
        error_class: &'static str,
        status: Value,
        response_body: Value,
    ) -> Vec<u8> {
        serialized_event_line_with_fields([
            ("decision", Value::String("response_error".to_owned())),
            ("error_class", Value::String(error_class.to_owned())),
            ("status", status),
            ("upstream_path", Value::String("/v1/models".to_owned())),
            ("response_body", response_body),
        ])
    }

    /// Builds response-level semantically invalid header/downstream lines.
    fn semantic_invalid_response_header_lines() -> [(&'static str, Vec<u8>); 4] {
        [
            (
                "response error with denial class",
                serialized_event_line_with_fields([
                    ("decision", Value::String("response_error".to_owned())),
                    ("error_class", Value::String("method_denied".to_owned())),
                    ("upstream_path", Value::String("/v1/models".to_owned())),
                ]),
            ),
            (
                "invalid response connection header with observed response body",
                serialized_event_line_with_fields([
                    ("decision", Value::String("response_error".to_owned())),
                    (
                        "error_class",
                        Value::String("invalid_response_connection_header".to_owned()),
                    ),
                    ("status", Value::from(502_u64)),
                    ("upstream_path", Value::String("/v1/models".to_owned())),
                    ("response_body", non_empty_body_value()),
                ]),
            ),
            (
                "response header error with observed response body",
                serialized_event_line_with_fields([
                    ("decision", Value::String("response_error".to_owned())),
                    (
                        "error_class",
                        Value::String("response_headers_too_large".to_owned()),
                    ),
                    ("status", Value::from(502_u64)),
                    ("upstream_path", Value::String("/v1/models".to_owned())),
                    ("response_body", non_empty_body_value()),
                ]),
            ),
            (
                "downstream closed with unobserved response body",
                serialized_event_line_with_fields([
                    ("decision", Value::String("response_error".to_owned())),
                    ("error_class", Value::String("downstream_closed".to_owned())),
                    ("status", Value::from(200_u64)),
                    ("upstream_path", Value::String("/v1/models".to_owned())),
                ]),
            ),
        ]
    }

    /// Builds response-level semantically invalid body lines.
    fn semantic_invalid_response_body_lines() -> [(&'static str, Vec<u8>); 5] {
        [
            (
                "response body too large with empty response body",
                serialized_event_line_with_fields([
                    ("decision", Value::String("response_error".to_owned())),
                    (
                        "error_class",
                        Value::String("response_body_too_large".to_owned()),
                    ),
                    ("status", Value::from(200_u64)),
                    ("upstream_path", Value::String("/v1/models".to_owned())),
                    ("response_body", empty_body_value()),
                ]),
            ),
            (
                "response body too large with unobserved response body",
                serialized_event_line_with_fields([
                    ("decision", Value::String("response_error".to_owned())),
                    (
                        "error_class",
                        Value::String("response_body_too_large".to_owned()),
                    ),
                    ("status", Value::from(200_u64)),
                    ("upstream_path", Value::String("/v1/models".to_owned())),
                ]),
            ),
            (
                "stream response error with unobserved response body",
                serialized_event_line_with_fields([
                    ("decision", Value::String("response_error".to_owned())),
                    (
                        "error_class",
                        Value::String("upstream_response_stream_failed".to_owned()),
                    ),
                    ("status", Value::from(200_u64)),
                    ("upstream_path", Value::String("/v1/models".to_owned())),
                ]),
            ),
            (
                "upstream response timeout with unobserved response body",
                serialized_event_line_with_fields([
                    ("decision", Value::String("response_error".to_owned())),
                    (
                        "error_class",
                        Value::String("upstream_response_timeout".to_owned()),
                    ),
                    ("status", Value::from(200_u64)),
                    ("upstream_path", Value::String("/v1/models".to_owned())),
                ]),
            ),
            (
                "upstream error with observed response body",
                serialized_event_line_with_fields([
                    ("decision", Value::String("upstream_error".to_owned())),
                    ("error_class", Value::String("upstream_timeout".to_owned())),
                    ("status", Value::from(504_u64)),
                    ("upstream_path", Value::String("/v1/models".to_owned())),
                    ("response_body", non_empty_body_value()),
                ]),
            ),
        ]
    }

    /// Builds upstream-level semantically invalid existing audit event lines.
    fn semantic_invalid_upstream_lines() -> [(&'static str, Vec<u8>); 8] {
        [
            (
                "upstream error with response error class",
                serialized_event_line_with_fields([
                    ("decision", Value::String("upstream_error".to_owned())),
                    (
                        "error_class",
                        Value::String("response_headers_too_large".to_owned()),
                    ),
                    ("status", Value::from(502_u64)),
                    ("upstream_path", Value::String("/v1/models".to_owned())),
                ]),
            ),
            (
                "upstream error with target mismatch",
                serialized_event_line_with_fields([
                    ("decision", Value::String("upstream_error".to_owned())),
                    ("error_class", Value::String("upstream_timeout".to_owned())),
                    ("status", Value::from(504_u64)),
                    ("upstream_path", Value::String("/v1/other".to_owned())),
                ]),
            ),
            (
                "upstream error with query mismatch",
                serialized_event_line_with_fields([
                    ("decision", Value::String("upstream_error".to_owned())),
                    ("error_class", Value::String("upstream_timeout".to_owned())),
                    ("query", Value::String("limit=1".to_owned())),
                    ("status", Value::from(504_u64)),
                    ("upstream_path", Value::String("/v1/models".to_owned())),
                    ("upstream_query", Value::String("limit=2".to_owned())),
                ]),
            ),
            (
                "upstream attempted without observed request body",
                serialized_event_line_with_fields([
                    ("decision", Value::String("upstream_error".to_owned())),
                    ("error_class", Value::String("upstream_timeout".to_owned())),
                    ("request_body", not_observed_body_value()),
                    ("status", Value::from(504_u64)),
                    ("upstream_path", Value::String("/v1/models".to_owned())),
                ]),
            ),
            (
                "upstream attempted with rejected request target",
                serialized_event_line_with_fields([
                    ("decision", Value::String("upstream_error".to_owned())),
                    ("error_class", Value::String("upstream_timeout".to_owned())),
                    ("path", Value::String("not-origin-form".to_owned())),
                    ("status", Value::from(504_u64)),
                    ("upstream_path", Value::String("not-origin-form".to_owned())),
                ]),
            ),
            (
                "upstream attempted with path component delimiter",
                serialized_event_line_with_fields([
                    ("decision", Value::String("upstream_error".to_owned())),
                    ("error_class", Value::String("upstream_timeout".to_owned())),
                    ("path", Value::String("/v1/models?limit=1".to_owned())),
                    ("status", Value::from(504_u64)),
                    ("upstream_path", Value::String("/v1/models".to_owned())),
                ]),
            ),
            (
                "upstream attempted with query fragment delimiter",
                serialized_event_line_with_fields([
                    ("decision", Value::String("upstream_error".to_owned())),
                    ("error_class", Value::String("upstream_timeout".to_owned())),
                    ("query", Value::String("limit=1#fragment".to_owned())),
                    ("status", Value::from(504_u64)),
                    ("upstream_path", Value::String("/v1/models".to_owned())),
                ]),
            ),
            (
                "denied with status mismatch",
                serialized_event_line_with_field("status", Value::from(200_u64)),
            ),
        ]
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
    fn denial_reasons_report_stable_error_classes_and_statuses() {
        let cases = [
            (
                AuditDenialReason::AbsoluteFormUnsupported,
                "absolute_form_unsupported",
                StatusCode::BAD_REQUEST,
            ),
            (
                AuditDenialReason::ConnectUnsupported,
                "connect_unsupported",
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (
                AuditDenialReason::DotSegment,
                "dot_segment",
                StatusCode::BAD_REQUEST,
            ),
            (
                AuditDenialReason::EncodedSeparator,
                "encoded_path_separator",
                StatusCode::BAD_REQUEST,
            ),
            (
                AuditDenialReason::InvalidPercentEncoding,
                "invalid_percent_encoding",
                StatusCode::BAD_REQUEST,
            ),
            (
                AuditDenialReason::InvalidRequestConnectionHeader,
                "invalid_request_connection_header",
                StatusCode::BAD_REQUEST,
            ),
            (
                AuditDenialReason::MethodDenied,
                "method_denied",
                StatusCode::FORBIDDEN,
            ),
            (
                AuditDenialReason::NonOriginForm,
                "non_origin_form",
                StatusCode::BAD_REQUEST,
            ),
            (
                AuditDenialReason::PathDenied,
                "path_denied",
                StatusCode::FORBIDDEN,
            ),
            (
                AuditDenialReason::PathTooLong,
                "path_too_long",
                StatusCode::URI_TOO_LONG,
            ),
            (
                AuditDenialReason::QueryTooLong,
                "query_too_long",
                StatusCode::URI_TOO_LONG,
            ),
            (
                AuditDenialReason::RequestBodyReadFailed,
                "request_body_read_failed",
                StatusCode::BAD_REQUEST,
            ),
            (
                AuditDenialReason::RequestBodyTimeout,
                "request_body_timeout",
                StatusCode::REQUEST_TIMEOUT,
            ),
            (
                AuditDenialReason::RequestBodyTooLarge,
                "request_body_too_large",
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                AuditDenialReason::RequestHeadersTooLarge,
                "request_headers_too_large",
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            ),
            (
                AuditDenialReason::TooManyRequests,
                "too_many_requests",
                StatusCode::TOO_MANY_REQUESTS,
            ),
        ];

        for (reason, error_class, status) in cases {
            assert_eq!(reason.error_class(), error_class);
            assert_eq!(reason.status(), status);
        }
    }

    fn rejected_audit_target(
        uri: &Uri,
        expected: TargetRejectionReason,
    ) -> (RejectedAuditTarget, AuditTarget) {
        let rejection =
            RejectedAuditTarget::accept_request_uri(uri).expect_err("target should be rejected");
        assert_eq!(rejection.reason(), expected);
        let target = AuditTarget::from_request_uri(uri);
        (rejection, target)
    }

    fn accepted_denial_constructor_cases(
        accepted_target: &AcceptedAuditTarget,
        target: &AuditTarget,
    ) -> Vec<(AuditDenial, Method, AuditTarget, AuditDenialReason)> {
        vec![
            (
                AuditDenial::invalid_request_connection_header(
                    Method::GET,
                    accepted_target.clone(),
                ),
                Method::GET,
                target.clone(),
                AuditDenialReason::InvalidRequestConnectionHeader,
            ),
            (
                AuditDenial::allowlist_rejected(
                    Method::DELETE,
                    accepted_target.clone(),
                    AllowlistRejectionReason::MethodDenied,
                ),
                Method::DELETE,
                target.clone(),
                AuditDenialReason::MethodDenied,
            ),
            (
                AuditDenial::allowlist_rejected(
                    Method::GET,
                    accepted_target.clone(),
                    AllowlistRejectionReason::PathDenied,
                ),
                Method::GET,
                target.clone(),
                AuditDenialReason::PathDenied,
            ),
            (
                AuditDenial::request_body_read_failed(Method::POST, accepted_target.clone()),
                Method::POST,
                target.clone(),
                AuditDenialReason::RequestBodyReadFailed,
            ),
            (
                AuditDenial::request_body_timeout(Method::POST, accepted_target.clone()),
                Method::POST,
                target.clone(),
                AuditDenialReason::RequestBodyTimeout,
            ),
            (
                AuditDenial::request_body_too_large(Method::POST, accepted_target.clone()),
                Method::POST,
                target.clone(),
                AuditDenialReason::RequestBodyTooLarge,
            ),
            (
                AuditDenial::request_headers_too_large(Method::POST, accepted_target.clone()),
                Method::POST,
                target.clone(),
                AuditDenialReason::RequestHeadersTooLarge,
            ),
        ]
    }

    fn preparsed_denial_constructor_cases(
        preparsed_target: &PreparsedAuditTarget,
        target: &AuditTarget,
    ) -> Vec<(AuditDenial, Method, AuditTarget, AuditDenialReason)> {
        vec![
            (
                AuditDenial::absolute_form_unsupported(Method::GET, preparsed_target.clone()),
                Method::GET,
                target.clone(),
                AuditDenialReason::AbsoluteFormUnsupported,
            ),
            (
                AuditDenial::connect_unsupported(preparsed_target.clone()),
                Method::CONNECT,
                target.clone(),
                AuditDenialReason::ConnectUnsupported,
            ),
            (
                AuditDenial::too_many_requests(Method::GET, preparsed_target.clone()),
                Method::GET,
                target.clone(),
                AuditDenialReason::TooManyRequests,
            ),
        ]
    }

    fn rejected_denial_constructor_cases()
    -> Vec<(AuditDenial, Method, AuditTarget, AuditDenialReason)> {
        let path_too_long_uri = format!("/{}?limit=1", "a".repeat(MAX_ORIGIN_FORM_PATH_BYTES))
            .parse::<Uri>()
            .expect("URI should parse");
        let query_too_long_uri =
            format!("/v1/models?{}", "q".repeat(MAX_ORIGIN_FORM_QUERY_BYTES + 1))
                .parse::<Uri>()
                .expect("URI should parse");
        let dot_segment = rejected_audit_target(
            &Uri::from_static("/v1/../models?limit=1"),
            TargetRejectionReason::DotSegment,
        );
        let encoded_separator = rejected_audit_target(
            &Uri::from_static("/v1/%2fmodels?limit=1"),
            TargetRejectionReason::EncodedSeparator,
        );
        let invalid_percent_encoding = rejected_audit_target(
            &Uri::from_static("/v1/%zz?limit=1"),
            TargetRejectionReason::InvalidPercentEncoding,
        );
        let non_origin_form =
            rejected_audit_target(&Uri::from_static("*"), TargetRejectionReason::NonOriginForm);
        let path_too_long =
            rejected_audit_target(&path_too_long_uri, TargetRejectionReason::PathTooLong);
        let query_too_long =
            rejected_audit_target(&query_too_long_uri, TargetRejectionReason::QueryTooLong);
        vec![
            (
                AuditDenial::target_rejected(Method::GET, dot_segment.0),
                Method::GET,
                dot_segment.1,
                AuditDenialReason::DotSegment,
            ),
            (
                AuditDenial::target_rejected(Method::GET, encoded_separator.0),
                Method::GET,
                encoded_separator.1,
                AuditDenialReason::EncodedSeparator,
            ),
            (
                AuditDenial::target_rejected(Method::GET, invalid_percent_encoding.0),
                Method::GET,
                invalid_percent_encoding.1,
                AuditDenialReason::InvalidPercentEncoding,
            ),
            (
                AuditDenial::target_rejected(Method::GET, non_origin_form.0),
                Method::GET,
                non_origin_form.1,
                AuditDenialReason::NonOriginForm,
            ),
            (
                AuditDenial::target_rejected(Method::GET, path_too_long.0),
                Method::GET,
                path_too_long.1,
                AuditDenialReason::PathTooLong,
            ),
            (
                AuditDenial::target_rejected(Method::GET, query_too_long.0),
                Method::GET,
                query_too_long.1,
                AuditDenialReason::QueryTooLong,
            ),
        ]
    }

    #[test]
    fn audit_denial_constructors_pair_method_target_and_reason() {
        let uri = Uri::from_static("/v1/models?limit=1");
        let target = AuditTarget::from_request_uri(&uri);
        let accepted =
            AcceptedTarget::new("/v1/models", Some("limit=1")).expect("target should be accepted");
        let accepted_target = AcceptedAuditTarget::from_accepted(&accepted);
        let preparsed_target = PreparsedAuditTarget::from_request_uri(&uri);
        let mut cases = preparsed_denial_constructor_cases(&preparsed_target, &target);
        cases.extend(rejected_denial_constructor_cases());
        cases.extend(accepted_denial_constructor_cases(&accepted_target, &target));

        for (denial, method, expected_target, reason) in cases {
            let status = denial.status();
            let (actual_method, actual_target, actual_reason) = denial.into_parts();

            assert_eq!(actual_method, method);
            assert_eq!(actual_target, expected_target);
            assert_eq!(actual_reason, reason);
            assert_eq!(status, reason.status());
        }
    }

    #[test]
    fn response_header_errors_report_stable_error_classes_and_statuses() {
        let cases = [
            (
                AuditResponseHeaderError::InvalidConnectionHeader,
                "invalid_response_connection_header",
            ),
            (
                AuditResponseHeaderError::TooLarge,
                "response_headers_too_large",
            ),
        ];

        for (error, error_class) in cases {
            assert_eq!(error.error_class(), error_class);
            assert_eq!(error.status(), StatusCode::BAD_GATEWAY);
        }
    }

    #[test]
    fn upstream_errors_report_stable_error_classes_and_statuses() {
        let cases = [
            (
                AuditUpstreamError::Connect,
                "upstream_connect_failed",
                StatusCode::BAD_GATEWAY,
            ),
            (
                AuditUpstreamError::Request,
                "upstream_request_failed",
                StatusCode::BAD_GATEWAY,
            ),
            (
                AuditUpstreamError::Timeout,
                "upstream_timeout",
                StatusCode::GATEWAY_TIMEOUT,
            ),
        ];

        for (error, error_class, status) in cases {
            assert_eq!(error.error_class(), error_class);
            assert_eq!(error.status(), status);
        }
    }

    #[test]
    fn oversized_response_body_records_observed_bytes() {
        let mut account = ResponseAccount::new(ResponseBodyBytes::for_test(
            NonZeroU64::new(4).expect("limit should be non-zero"),
        ));
        let oversized = account
            .add_chunk(b"accepted")
            .expect_err("chunk should exceed the response limit");

        assert_eq!(oversized.observation(), non_empty_body(b"accepted"));
        assert_eq!(account.observation(), BodyObservation::Empty);
    }

    #[test]
    fn response_body_too_large_records_observed_bytes() {
        let error = AuditResponseError::response_body_too_large(
            oversized_response_body(b"accepted"),
            StatusCode::OK,
        );
        let (_error_class, response_body, _status) = error.into_parts();

        assert_eq!(
            response_body,
            AuditBodySummary::non_empty(non_empty_body(b"accepted"))
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
        let expected = StatusCode::METHOD_NOT_ALLOWED;

        assert_eq!(event.status.as_status_code(), expected);
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
    fn new_truncates_overlong_methods_with_original_length() {
        let method = "A".repeat(MAX_ALLOWED_METHOD_BYTES + 1);
        let target = AuditTarget::from_uri_parts("/v1/models", None);
        let input = denied_input(&method, target, AuditDenialReason::MethodDenied);
        let suffix = format!("...[truncated original_bytes={}]", method.len());

        let event = AuditEvent::new(input);
        let value = serde_json::to_value(event).expect("event should serialize");
        let audited_method = value
            .as_object()
            .and_then(|object| object.get("method"))
            .expect("method should exist")
            .as_str()
            .expect("method should serialize as a string");

        assert_eq!(audited_method.len(), MAX_ALLOWED_METHOD_BYTES);
        assert!(audited_method.ends_with(&suffix));
    }

    #[test]
    fn upstream_target_test_constructor_preserves_parts() {
        let target = AuditUpstreamTarget::new("/v1/models", Some("limit=1"));

        assert_eq!(target.path(), "/v1/models");
        assert_eq!(target.query(), Some("limit=1"));
    }

    #[test]
    fn run_token_rejects_empty_text() {
        assert_eq!(RunToken::new(""), Err(RunTokenError::Empty));
    }

    #[test]
    fn run_token_rejects_invalid_text() {
        let cases = Vec::from([
            ("abcdef".to_owned(), RunTokenError::InvalidShape),
            ("-abcdef".to_owned(), RunTokenError::InvalidShape),
            ("abcdef-".to_owned(), RunTokenError::InvalidShape),
            ("ab-cd-ef".to_owned(), RunTokenError::InvalidShape),
            ("AB-cd".to_owned(), RunTokenError::InvalidCharacter),
            ("ab_cd-ef".to_owned(), RunTokenError::InvalidCharacter),
            ("ab\ncd-ef".to_owned(), RunTokenError::InvalidCharacter),
            (
                "aaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb".to_owned(),
                RunTokenError::InvalidShape,
            ),
            (
                "aaaaaaaaaaaaaaa--bbbbbbbbbbbbbbbb".to_owned(),
                RunTokenError::InvalidShape,
            ),
            (
                "aaaaaaaaaaaaaa-a-bbbbbbbbbbbbbbbb".to_owned(),
                RunTokenError::InvalidShape,
            ),
            (
                "aaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbb-".to_owned(),
                RunTokenError::InvalidShape,
            ),
            (
                "0123456789abcdef*fedcba9876543210".to_owned(),
                RunTokenError::InvalidCharacter,
            ),
            (
                "0123456789abcdef-fedcba987654321-".to_owned(),
                RunTokenError::InvalidShape,
            ),
            (
                "0123456789abcdef-fedcba987654321g".to_owned(),
                RunTokenError::InvalidCharacter,
            ),
            (
                "0g23456789abcdef-fedcba9876543210".to_owned(),
                RunTokenError::InvalidCharacter,
            ),
            (
                "g123456789abcdef-fedcba9876543210".to_owned(),
                RunTokenError::InvalidCharacter,
            ),
            ("a".repeat(RUN_TOKEN_BYTES + 1), RunTokenError::TooLong),
        ]);

        for (token, expected) in cases {
            assert_eq!(
                RunToken::new(token.as_str()),
                Err(expected),
                "token {token:?}"
            );
        }
    }

    #[test]
    fn run_token_accepts_production_shape() {
        let token = RunToken::new("000000000000001a-000000000000002b")
            .expect("production-shaped token should parse");

        assert_eq!(token.to_string(), "000000000000001a-000000000000002b");
    }

    #[test]
    fn run_token_accepts_the_exact_supported_length() {
        let text = format!("{}-{}", "a".repeat(16), "b".repeat(16));
        assert_eq!(text.len(), RUN_TOKEN_BYTES);

        let token = RunToken::new(text.clone()).expect("exact-length token should parse");

        assert_eq!(token.to_string(), text);
    }

    #[test]
    fn run_token_helpers_cover_every_digit_and_invalid_byte() {
        for (byte, expected) in [
            (b'0', Some(0)),
            (b'1', Some(1)),
            (b'2', Some(2)),
            (b'3', Some(3)),
            (b'4', Some(4)),
            (b'5', Some(5)),
            (b'6', Some(6)),
            (b'7', Some(7)),
            (b'8', Some(8)),
            (b'9', Some(9)),
            (b'a', Some(10)),
            (b'b', Some(11)),
            (b'c', Some(12)),
            (b'd', Some(13)),
            (b'e', Some(14)),
            (b'f', Some(15)),
            (b'g', None),
        ] {
            assert_eq!(super::token_nibble(byte), expected);
        }

        assert!(!super::has_invalid_run_token_character("0123-abcd"));
        assert!(super::has_invalid_run_token_character("0123-abcz"));
        assert_eq!(super::parse_run_token_byte(b'0', b'f'), Ok(15));
        assert_eq!(
            super::parse_run_token_byte(b'g', b'0'),
            Err(RunTokenError::InvalidCharacter)
        );
        assert_eq!(
            super::parse_run_token_byte(b'0', b'g'),
            Err(RunTokenError::InvalidCharacter)
        );
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
    pub(super) fn existing_denial_error_classes_bind_statuses() {
        let cases = [
            (
                ExistingAuditErrorClass::AbsoluteFormUnsupported,
                Some(StatusCode::BAD_REQUEST),
            ),
            (
                ExistingAuditErrorClass::ConnectUnsupported,
                Some(StatusCode::METHOD_NOT_ALLOWED),
            ),
            (
                ExistingAuditErrorClass::DotSegment,
                Some(StatusCode::BAD_REQUEST),
            ),
            (
                ExistingAuditErrorClass::EncodedSeparator,
                Some(StatusCode::BAD_REQUEST),
            ),
            (
                ExistingAuditErrorClass::InvalidPercentEncoding,
                Some(StatusCode::BAD_REQUEST),
            ),
            (
                ExistingAuditErrorClass::InvalidRequestConnectionHeader,
                Some(StatusCode::BAD_REQUEST),
            ),
            (
                ExistingAuditErrorClass::MethodDenied,
                Some(StatusCode::FORBIDDEN),
            ),
            (
                ExistingAuditErrorClass::NonOriginForm,
                Some(StatusCode::BAD_REQUEST),
            ),
            (
                ExistingAuditErrorClass::PathDenied,
                Some(StatusCode::FORBIDDEN),
            ),
            (
                ExistingAuditErrorClass::PathTooLong,
                Some(StatusCode::URI_TOO_LONG),
            ),
            (
                ExistingAuditErrorClass::QueryTooLong,
                Some(StatusCode::URI_TOO_LONG),
            ),
            (
                ExistingAuditErrorClass::RequestBodyReadFailed,
                Some(StatusCode::BAD_REQUEST),
            ),
            (
                ExistingAuditErrorClass::RequestBodyTimeout,
                Some(StatusCode::REQUEST_TIMEOUT),
            ),
            (
                ExistingAuditErrorClass::RequestBodyTooLarge,
                Some(StatusCode::PAYLOAD_TOO_LARGE),
            ),
            (
                ExistingAuditErrorClass::RequestHeadersTooLarge,
                Some(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE),
            ),
            (
                ExistingAuditErrorClass::TooManyRequests,
                Some(StatusCode::TOO_MANY_REQUESTS),
            ),
        ];

        for (error_class, status) in cases {
            assert_eq!(error_class.fixed_status(), status);
            assert!(error_class.is_denial());
            assert!(!error_class.is_response_error());
            assert!(!error_class.is_upstream_error());
        }
    }

    #[test]
    pub(super) fn existing_denied_target_rejects_non_denial_error_classes() {
        let fields = ExistingAuditEventFields {
            decision: ExistingAuditDecision::Denied,
            error_class: Some(ExistingAuditErrorClass::DownstreamClosed),
            method: "GET".to_owned(),
            path: "/v1/models".to_owned(),
            query: None,
            request_body: ExistingAuditBodySummary::Empty,
            request_id: "req-000000000000000a-000000000000000b-0000000000000001".to_owned(),
            response_body: ExistingAuditBodySummary::NotObserved,
            status: StatusCode::OK,
            timestamp: "1970-01-01T00:00:00.000000000Z".to_owned(),
            upstream_origin: upstream_origin(),
            upstream_path: None,
            upstream_query: None,
            version: AuditSchemaVersion::CURRENT,
        };

        assert_eq!(
            fields.validate_denied_target(fields.error_class),
            Err("audit error class does not match decision"),
        );
    }

    #[test]
    pub(super) fn existing_denied_target_distinguishes_authority_targets() {
        let absolute_form_too_long = AuditTarget::from_uri_parts(
            &format!(
                "http://evil.example/{}",
                "a".repeat(MAX_AUDIT_TARGET_PATH_BYTES)
            ),
            None,
        );
        let absolute_form = existing_denied_target_fields(
            ExistingAuditErrorClass::AbsoluteFormUnsupported,
            "http://evil.example/steal",
            Some("limit=1"),
        );
        let absolute_form_misclassified = existing_denied_target_fields(
            ExistingAuditErrorClass::NonOriginForm,
            "http://evil.example/steal",
            Some("limit=1"),
        );
        let truncated_absolute_form = existing_denied_target_fields(
            ExistingAuditErrorClass::AbsoluteFormUnsupported,
            absolute_form_too_long.path(),
            absolute_form_too_long.query(),
        );
        let truncated_absolute_form_misclassified = existing_denied_target_fields(
            ExistingAuditErrorClass::NonOriginForm,
            absolute_form_too_long.path(),
            absolute_form_too_long.query(),
        );
        let non_origin_form =
            existing_denied_target_fields(ExistingAuditErrorClass::NonOriginForm, "*", None);
        let non_origin_form_misclassified = existing_denied_target_fields(
            ExistingAuditErrorClass::AbsoluteFormUnsupported,
            "*",
            None,
        );

        assert_eq!(
            absolute_form.validate_denied_target(absolute_form.error_class),
            Ok(())
        );
        assert_eq!(
            absolute_form_misclassified
                .validate_denied_target(absolute_form_misclassified.error_class),
            Err("audit target does not match non-origin-form denial")
        );
        assert_eq!(
            truncated_absolute_form.validate_denied_target(truncated_absolute_form.error_class),
            Ok(())
        );
        assert_eq!(
            truncated_absolute_form_misclassified
                .validate_denied_target(truncated_absolute_form_misclassified.error_class),
            Err("audit target does not match non-origin-form denial")
        );
        assert_eq!(
            non_origin_form.validate_denied_target(non_origin_form.error_class),
            Ok(())
        );
        assert_eq!(
            non_origin_form_misclassified
                .validate_denied_target(non_origin_form_misclassified.error_class),
            Err("audit target does not match absolute-form denial")
        );
    }

    fn existing_denied_target_fields(
        error_class: ExistingAuditErrorClass,
        path: &str,
        query: Option<&str>,
    ) -> ExistingAuditEventFields {
        ExistingAuditEventFields {
            decision: ExistingAuditDecision::Denied,
            error_class: Some(error_class),
            method: "GET".to_owned(),
            path: path.to_owned(),
            query: query.map(str::to_owned),
            request_body: ExistingAuditBodySummary::Empty,
            request_id: "req-000000000000000a-000000000000000b-0000000000000001".to_owned(),
            response_body: ExistingAuditBodySummary::NotObserved,
            status: error_class
                .fixed_status()
                .expect("denial should have a fixed status"),
            timestamp: "1970-01-01T00:00:00.000000000Z".to_owned(),
            upstream_origin: upstream_origin(),
            upstream_path: None,
            upstream_query: None,
            version: AuditSchemaVersion::CURRENT,
        }
    }

    #[test]
    pub(super) fn existing_upstream_targets_are_derived_from_accepted_targets() {
        let accepted = existing_upstream_error_fields(
            "/v1/models",
            Some("q='"),
            Some("/v1/models"),
            Some("q=%27"),
        );
        let rejected =
            existing_upstream_error_fields("not-origin-form", None, Some("not-origin-form"), None);

        assert_eq!(accepted.validate_upstream_target(), Ok(()));
        assert_eq!(
            rejected.validate_upstream_target(),
            Err("upstream-attempted audit target must be accepted"),
        );
    }

    fn existing_upstream_error_fields(
        path: &str,
        query: Option<&str>,
        upstream_path: Option<&str>,
        upstream_query: Option<&str>,
    ) -> ExistingAuditEventFields {
        ExistingAuditEventFields {
            decision: ExistingAuditDecision::UpstreamError,
            error_class: Some(ExistingAuditErrorClass::UpstreamTimeout),
            method: "GET".to_owned(),
            path: path.to_owned(),
            query: query.map(str::to_owned),
            request_body: ExistingAuditBodySummary::Empty,
            request_id: "req-000000000000000a-000000000000000b-0000000000000001".to_owned(),
            response_body: ExistingAuditBodySummary::NotObserved,
            status: StatusCode::GATEWAY_TIMEOUT,
            timestamp: "1970-01-01T00:00:00.000000000Z".to_owned(),
            upstream_origin: upstream_origin(),
            upstream_path: upstream_path.map(str::to_owned),
            upstream_query: upstream_query.map(str::to_owned),
            version: AuditSchemaVersion::CURRENT,
        }
    }

    pub(super) fn existing_request_body_failures_require_unobserved_bodies() {
        for error_class in [
            ExistingAuditErrorClass::RequestBodyReadFailed,
            ExistingAuditErrorClass::RequestBodyTimeout,
            ExistingAuditErrorClass::RequestBodyTooLarge,
        ] {
            let accepted = existing_request_body_failure_fields(
                error_class,
                ExistingAuditBodySummary::NotObserved,
            );
            let rejected =
                existing_request_body_failure_fields(error_class, ExistingAuditBodySummary::Empty);

            assert_eq!(accepted.validate_request_body(accepted.error_class), Ok(()));
            assert_eq!(
                rejected.validate_request_body(rejected.error_class),
                Err("audit request body summary does not match error class")
            );
        }
    }

    fn existing_request_body_failure_fields(
        error_class: ExistingAuditErrorClass,
        request_body: ExistingAuditBodySummary,
    ) -> ExistingAuditEventFields {
        ExistingAuditEventFields {
            decision: ExistingAuditDecision::Denied,
            error_class: Some(error_class),
            method: "GET".to_owned(),
            path: "/v1/models".to_owned(),
            query: None,
            request_body,
            request_id: "req-000000000000000a-000000000000000b-0000000000000001".to_owned(),
            response_body: ExistingAuditBodySummary::NotObserved,
            status: error_class
                .fixed_status()
                .expect("request-body denial should have a fixed status"),
            timestamp: "1970-01-01T00:00:00.000000000Z".to_owned(),
            upstream_origin: upstream_origin(),
            upstream_path: None,
            upstream_query: None,
            version: super::AuditSchemaVersion::CURRENT,
        }
    }

    #[test]
    pub(super) fn existing_response_error_classes_bind_statuses() {
        let cases = [
            (ExistingAuditErrorClass::DownstreamClosed, None),
            (
                ExistingAuditErrorClass::InvalidResponseConnectionHeader,
                Some(StatusCode::BAD_GATEWAY),
            ),
            (ExistingAuditErrorClass::ResponseBodyTooLarge, None),
            (
                ExistingAuditErrorClass::ResponseHeadersTooLarge,
                Some(StatusCode::BAD_GATEWAY),
            ),
            (ExistingAuditErrorClass::UpstreamResponseStreamFailed, None),
            (ExistingAuditErrorClass::UpstreamResponseTimeout, None),
        ];

        for (error_class, status) in cases {
            assert_eq!(error_class.fixed_status(), status);
            assert!(!error_class.is_denial());
            assert!(error_class.is_response_error());
            assert!(!error_class.is_upstream_error());
        }
    }

    #[test]
    pub(super) fn existing_upstream_error_classes_bind_statuses() {
        let cases = [
            (
                ExistingAuditErrorClass::UpstreamConnectFailed,
                Some(StatusCode::BAD_GATEWAY),
            ),
            (
                ExistingAuditErrorClass::UpstreamRequestFailed,
                Some(StatusCode::BAD_GATEWAY),
            ),
            (
                ExistingAuditErrorClass::UpstreamTimeout,
                Some(StatusCode::GATEWAY_TIMEOUT),
            ),
        ];

        for (error_class, status) in cases {
            assert_eq!(error_class.fixed_status(), status);
            assert!(!error_class.is_denial());
            assert!(!error_class.is_response_error());
            assert!(error_class.is_upstream_error());
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
        assert_eq!(
            object["request_id"],
            "req-000000000000000a-000000000000000b-0000000000000001"
        );
        assert!(object["upstream_path"].is_null());
        assert!(object["upstream_query"].is_null());
        assert!(object["query"].is_null());
        assert_eq!(object["request_body"], empty_body_value());
        assert_eq!(object["response_body"], not_observed_body_value());
        assert_eq!(object["status"], 403_u64);
    }

    #[test]
    pub(super) fn truncated_audit_methods_reject_non_writer_shapes() {
        let marker = super::AUDIT_TRUNCATION_PREFIX;
        let suffix = super::AUDIT_TRUNCATION_SUFFIX;
        let valid_suffix = format!("{marker}65{suffix}");
        let prefix_len = MAX_ALLOWED_METHOD_BYTES
            .checked_sub(valid_suffix.len())
            .expect("test suffix should fit in the audited method bound");
        let valid_shape = format!("{}{valid_suffix}", "A".repeat(prefix_len));
        let too_small_suffix = format!("{marker}64{suffix}");
        let too_small_prefix_len = MAX_ALLOWED_METHOD_BYTES
            .checked_sub(too_small_suffix.len())
            .expect("test suffix should fit in the audited method bound");
        let too_small_original = format!("{}{too_small_suffix}", "A".repeat(too_small_prefix_len));

        assert!(is_truncated_audit_method(&valid_shape));
        assert!(!is_truncated_audit_method("GET"));
        assert!(!is_truncated_audit_method(&format!("A{marker}65")));
        assert!(!is_truncated_audit_method(&format!("A{marker}not{suffix}")));
        assert!(!is_truncated_audit_method(&format!("A{valid_suffix}")));
        assert!(!is_truncated_audit_method(&too_small_original));
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
    fn from_uri_parts_truncates_overlong_paths_with_original_length() {
        let path = format!("/{}", "a".repeat(MAX_ORIGIN_FORM_PATH_BYTES));
        let target = AuditTarget::from_uri_parts(&path, None);
        let suffix = format!(
            "...[truncated original_bytes={}]",
            MAX_ORIGIN_FORM_PATH_BYTES + 1
        );

        assert_eq!(target.path().len(), MAX_ORIGIN_FORM_PATH_BYTES);
        assert!(target.path().starts_with('/'));
        assert!(target.path().ends_with(&suffix));
        assert_eq!(target.query(), None);
    }

    #[test]
    fn from_uri_parts_truncates_overlong_queries_with_original_length() {
        let query = "q".repeat(MAX_ORIGIN_FORM_QUERY_BYTES + 1);
        let target = AuditTarget::from_uri_parts("/v1/models", Some(&query));
        let suffix = format!(
            "...[truncated original_bytes={}]",
            MAX_ORIGIN_FORM_QUERY_BYTES + 1
        );
        let audited_query = target.query().expect("query should be audited");

        assert_eq!(target.path(), "/v1/models");
        assert_eq!(audited_query.len(), MAX_ORIGIN_FORM_QUERY_BYTES);
        assert!(audited_query.ends_with(&suffix));
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
    async fn open_accepts_newline_terminated_audit_logs() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        fs::write(&audit_log, serialized_denied_event_line())
            .expect("existing log should be written");
        let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());
        let writer = AuditWriter::open(&config)
            .await
            .expect("audit writer should open");

        writer
            .write_event(&denied_event())
            .await
            .expect("event should append");

        let contents = fs::read_to_string(&audit_log).expect("audit log should be readable");
        let mut lines = contents.lines();
        let first = lines.next().expect("existing audit line should remain");
        let second = lines.next().expect("appended audit line should exist");
        let first_value: serde_json::Value =
            serde_json::from_str(first).expect("existing audit line should remain valid JSON");
        let value: serde_json::Value =
            serde_json::from_str(second).expect("appended audit line should be valid JSON");
        let object = value
            .as_object()
            .expect("appended audit line should be an object");
        let decision = object.get("decision").expect("decision should exist");
        let first_object = first_value
            .as_object()
            .expect("existing audit line should be an object");
        let first_version = first_object.get("version").expect("version should exist");

        assert_eq!(first_version, 3_u64);
        assert_eq!(decision, "denied");
        assert_eq!(lines.next(), None);
    }

    #[tokio::test]
    async fn open_accepts_existing_connect_denials() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        fs::write(
            &audit_log,
            serialized_event_line_with_fields([
                (
                    "error_class",
                    Value::String("connect_unsupported".to_owned()),
                ),
                ("method", Value::String("CONNECT".to_owned())),
                ("path", Value::String("evil.example:443".to_owned())),
                ("status", Value::from(405_u64)),
            ]),
        )
        .expect("existing log should be written");
        let config = GatewayConfig::for_test(audit_log, roomy_event_limit());

        let result = AuditWriter::open(&config).await;

        assert!(result.is_ok(), "CONNECT denial should be accepted");
    }

    #[tokio::test]
    async fn open_accepts_existing_too_many_requests_denials() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        fs::write(
            &audit_log,
            serialized_event_line_with_fields([
                ("error_class", Value::String("too_many_requests".to_owned())),
                ("method", Value::String("CONNECT".to_owned())),
                ("path", Value::String("evil.example:443".to_owned())),
                ("status", Value::from(429_u64)),
            ]),
        )
        .expect("existing log should be written");
        let config = GatewayConfig::for_test(audit_log, roomy_event_limit());

        let result = AuditWriter::open(&config).await;

        assert!(
            result.is_ok(),
            "too-many-requests denial should be accepted"
        );
    }

    #[tokio::test]
    async fn open_accepts_existing_request_body_timeout_denials() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        fs::write(
            &audit_log,
            serialized_event_line_with_fields([
                (
                    "error_class",
                    Value::String("request_body_timeout".to_owned()),
                ),
                ("request_body", not_observed_body_value()),
                ("status", Value::from(408_u64)),
            ]),
        )
        .expect("existing log should be written");
        let config = GatewayConfig::for_test(audit_log, roomy_event_limit());

        let result = AuditWriter::open(&config).await;

        assert!(
            result.is_ok(),
            "request-body-timeout denial should be accepted"
        );
    }

    #[tokio::test]
    async fn open_rejects_complete_non_json_audit_logs() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        fs::write(&audit_log, b"not-json\n").expect("corrupt log should be written");
        let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());

        let result = AuditWriter::open(&config).await;

        let first_line = NonZeroU64::new(1).expect("literal should be non-zero");
        assert!(
            matches!(
                result,
                Err(AuditError::CorruptLog { path, line, .. })
                    if path == audit_log && line == first_line
            ),
            "complete non-JSON logs should be rejected"
        );
    }

    #[tokio::test]
    async fn open_rejects_schema_invalid_audit_logs() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        fs::write(&audit_log, b"{\"version\":3}\n").expect("schema-invalid log should be written");
        let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());

        let result = AuditWriter::open(&config).await;

        let first_line = NonZeroU64::new(1).expect("literal should be non-zero");
        assert!(
            matches!(
                result,
                Err(AuditError::CorruptLog { path, line, .. })
                    if path == audit_log && line == first_line
            ),
            "schema-invalid logs should be rejected"
        );
    }

    #[tokio::test]
    async fn open_accepts_existing_logs_with_non_empty_body_summaries() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        let mut event = serialized_denied_event_value();
        let object = event
            .as_object_mut()
            .expect("serialized event should be an object");
        object.insert("decision".to_owned(), Value::String("allowed".to_owned()));
        object.insert("error_class".to_owned(), Value::Null);
        object.insert("request_body".to_owned(), non_empty_body_value());
        object.insert("response_body".to_owned(), non_empty_body_value());
        object.insert("status".to_owned(), Value::from(200_u64));
        object.insert(
            "upstream_path".to_owned(),
            Value::String("/v1/models".to_owned()),
        );
        fs::write(&audit_log, serialized_event_value_line(&event))
            .expect("existing log should be written");
        let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());

        let result = AuditWriter::open(&config).await;

        assert!(
            result.is_ok(),
            "non-empty body summaries should be accepted"
        );
    }

    #[tokio::test]
    async fn open_accepts_existing_encoded_separator_denials() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        let event = AuditEvent::new(denied_input(
            "GET",
            AuditTarget::from_uri_parts("/v1/%2fmodels", None),
            AuditDenialReason::EncodedSeparator,
        ));
        let mut line = serde_json::to_vec(&event).expect("event should serialize");
        line.push(b'\n');
        fs::write(&audit_log, line).expect("existing log should be written");
        let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());

        let result = AuditWriter::open(&config).await;

        assert!(
            result.is_ok(),
            "encoded-separator denials should be accepted"
        );
    }

    #[tokio::test]
    async fn open_accepts_existing_denial_shapes() {
        for (case_name, contents) in denial_existing_event_lines() {
            let directory = tempdir().expect("temporary directory should be created");
            let audit_log = directory.path().join("audit.ndjson");
            fs::write(&audit_log, contents).expect("existing log should be written");
            let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());

            let result = AuditWriter::open(&config).await;

            assert!(result.is_ok(), "{case_name} should be accepted");
        }
    }

    #[tokio::test]
    async fn open_accepts_existing_logs_with_truncated_methods() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        let method = "A".repeat(MAX_ALLOWED_METHOD_BYTES + 1);
        let event = AuditEvent::new(denied_input(
            &method,
            AuditTarget::from_uri_parts("/v1/models", None),
            AuditDenialReason::MethodDenied,
        ));
        let mut line = serde_json::to_vec(&event).expect("event should serialize");
        line.push(b'\n');
        fs::write(&audit_log, line).expect("existing log should be written");
        let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());

        let result = AuditWriter::open(&config).await;

        assert!(
            result.is_ok(),
            "truncated audited methods should be accepted"
        );
    }

    #[tokio::test]
    async fn open_accepts_existing_response_error_shapes() {
        for (case_name, contents) in response_error_existing_event_lines() {
            let directory = tempdir().expect("temporary directory should be created");
            let audit_log = directory.path().join("audit.ndjson");
            fs::write(&audit_log, contents).expect("existing log should be written");
            let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());

            let result = AuditWriter::open(&config).await;

            assert!(result.is_ok(), "{case_name} should be accepted");
        }
    }

    #[tokio::test]
    async fn open_rejects_schema_invalid_existing_audit_fields() {
        for (case_name, contents) in schema_invalid_existing_event_lines() {
            let directory = tempdir().expect("temporary directory should be created");
            let audit_log = directory.path().join("audit.ndjson");
            fs::write(&audit_log, contents).expect("schema-invalid log should be written");
            let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());

            let result = AuditWriter::open(&config).await;

            let first_line = NonZeroU64::new(1).expect("literal should be non-zero");
            assert!(
                matches!(
                    result,
                    Err(AuditError::CorruptLog {
                        path,
                        line: audit_line,
                        ..
                    }) if path == audit_log && audit_line == first_line
                ),
                "{case_name} should be rejected"
            );
        }
    }

    #[tokio::test]
    async fn open_rejects_semantic_invalid_existing_audit_fields() {
        for (case_name, contents) in semantic_invalid_existing_event_lines() {
            let directory = tempdir().expect("temporary directory should be created");
            let audit_log = directory.path().join("audit.ndjson");
            fs::write(&audit_log, contents).expect("semantic-invalid log should be written");
            let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());

            let result = AuditWriter::open(&config).await;

            let first_line = NonZeroU64::new(1).expect("literal should be non-zero");
            assert!(
                matches!(
                    result,
                    Err(AuditError::CorruptLog {
                        path,
                        line: audit_line,
                        ..
                    }) if path == audit_log && audit_line == first_line
                ),
                "{case_name} should be rejected"
            );
        }
    }

    #[tokio::test]
    async fn open_rejects_type_invalid_existing_audit_fields() {
        let mut invalid_request_body = non_empty_body_value();
        invalid_request_body
            .as_object_mut()
            .expect("body summary should be an object")
            .insert("blake3".to_owned(), Value::Bool(false));
        let cases = [
            (
                "typed-invalid body digest",
                serialized_event_line_with_field("request_body", invalid_request_body),
            ),
            (
                "typed-invalid method",
                serialized_event_line_with_field("method", Value::Bool(false)),
            ),
            (
                "typed-invalid path",
                serialized_event_line_with_field("path", Value::Bool(false)),
            ),
            (
                "typed-invalid query",
                serialized_event_line_with_field("query", Value::Bool(false)),
            ),
            (
                "typed-invalid request id",
                serialized_event_line_with_field("request_id", Value::Bool(false)),
            ),
            (
                "typed-invalid status",
                serialized_event_line_with_field("status", Value::Bool(false)),
            ),
            (
                "typed-invalid timestamp",
                serialized_event_line_with_field("timestamp", Value::Bool(false)),
            ),
            (
                "typed-invalid upstream origin",
                serialized_event_line_with_field("upstream_origin", Value::Bool(false)),
            ),
            (
                "typed-invalid upstream path",
                serialized_event_line_with_field("upstream_path", Value::Bool(false)),
            ),
            (
                "typed-invalid upstream query",
                serialized_event_line_with_field("upstream_query", Value::Bool(false)),
            ),
            (
                "typed-invalid version",
                serialized_event_line_with_field("version", Value::Bool(false)),
            ),
        ];

        for (case_name, contents) in cases {
            let directory = tempdir().expect("temporary directory should be created");
            let audit_log = directory.path().join("audit.ndjson");
            fs::write(&audit_log, contents).expect("type-invalid log should be written");
            let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());

            let result = AuditWriter::open(&config).await;

            assert!(
                matches!(result, Err(AuditError::CorruptLog { path, .. }) if path == audit_log),
                "{case_name} should be rejected"
            );
        }
    }

    #[test]
    fn existing_request_ids_accept_only_emitted_shape() {
        let accepted = "req-000000000000000a-000000000000000b-0000000000000001";
        let rejected = [
            "",
            "req-",
            "req-000000000000000a",
            "req-000000000000000a-000000000000000b",
            "req-00000000000000-000000000000000b-0000000000000001",
            "req-000000000000000a-000000000000000b-0000000000000001-extra",
            "req-000000000000000g-000000000000000b-0000000000000001",
            "req-000000000000000a-000000000000000b-0000000000000000",
        ];

        assert!(is_existing_request_id(accepted));
        for value in rejected {
            assert!(!is_existing_request_id(value));
        }
    }

    #[tokio::test]
    async fn open_reports_the_corrupt_audit_log_line_number() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        let mut contents = serialized_denied_event_line();
        contents.extend_from_slice(b"not-json\n");
        fs::write(&audit_log, contents).expect("corrupt log should be written");
        let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());

        let result = AuditWriter::open(&config).await;

        let second_line = NonZeroU64::new(2).expect("literal should be non-zero");
        assert!(
            matches!(
                result,
                Err(AuditError::CorruptLog { path, line, .. })
                    if path == audit_log && line == second_line
            ),
            "corrupt audit logs should report the corrupt line"
        );
    }

    #[tokio::test]
    async fn open_rejects_duplicate_existing_request_ids() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        let line = serialized_denied_event_line();
        fs::write(&audit_log, [line.as_slice(), line.as_slice()].concat())
            .expect("duplicate log should be written");
        let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());

        let result = AuditWriter::open(&config).await;

        let second_line = NonZeroU64::new(2).expect("literal should be non-zero");
        assert!(
            matches!(
                result,
                Err(AuditError::CorruptLog {
                    path,
                    line: audit_line,
                    ..
                }) if path == audit_log && audit_line == second_line
            ),
            "duplicate request ids should be rejected"
        );
    }

    #[tokio::test]
    async fn open_rejects_partial_final_audit_events() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        fs::write(&audit_log, b"{\"version\":3}").expect("partial log should be written");
        let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());

        let result = AuditWriter::open(&config).await;

        assert!(matches!(result, Err(AuditError::TornLog { path }) if path == audit_log));
        let contents = fs::read_to_string(&audit_log).expect("audit log should be readable");
        assert_eq!(contents, "{\"version\":3}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn open_fails_when_the_audit_path_is_unseekable() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        let status = Command::new("mkfifo")
            .arg(&audit_log)
            .status()
            .expect("mkfifo should run");
        assert!(status.success());
        let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());

        let result = AuditWriter::open(&config).await;

        assert!(matches!(result, Err(AuditError::Inspect { path, .. }) if path == audit_log));
    }

    #[tokio::test]
    async fn classify_audit_log_tail_reports_empty_logs() {
        let mut reader = TailReader::new([]);

        let tail = classify_audit_log_tail(&mut reader)
            .await
            .expect("tail classification should succeed");

        assert_eq!(tail, AuditLogTail::Empty);
    }

    #[tokio::test]
    async fn classify_audit_log_tail_reports_complete_logs() {
        let mut reader = TailReader::new(*b"{\"version\":3}\n");

        let tail = classify_audit_log_tail(&mut reader)
            .await
            .expect("tail classification should succeed");

        assert_eq!(tail, AuditLogTail::Complete);
    }

    #[tokio::test]
    async fn classify_audit_log_tail_reports_torn_logs() {
        let mut reader = TailReader::new(*b"{\"version\":3}");

        let tail = classify_audit_log_tail(&mut reader)
            .await
            .expect("tail classification should succeed");

        assert_eq!(tail, AuditLogTail::Torn);
    }

    #[tokio::test]
    async fn inspect_audit_log_tail_reports_initial_seek_errors() {
        let path = Path::new("audit.ndjson");
        let mut reader = TailReader::failing([], TailReaderFailure::InitialSeek);

        let result = inspect_audit_log_tail(path, &mut reader).await;

        assert!(
            matches!(result, Err(AuditError::Inspect { path: error_path, .. }) if error_path == path)
        );
    }

    #[tokio::test]
    async fn inspect_audit_log_tail_reports_final_seek_errors() {
        let path = Path::new("audit.ndjson");
        let mut reader = TailReader::failing(*b"{\"version\":3}\n", TailReaderFailure::FinalSeek);

        let result = inspect_audit_log_tail(path, &mut reader).await;

        assert!(
            matches!(result, Err(AuditError::Inspect { path: error_path, .. }) if error_path == path)
        );
    }

    #[tokio::test]
    async fn inspect_audit_log_tail_reports_read_errors() {
        let path = Path::new("audit.ndjson");
        let mut reader = TailReader::failing(*b"{\"version\":3}\n", TailReaderFailure::Read);

        let result = inspect_audit_log_tail(path, &mut reader).await;

        assert!(
            matches!(result, Err(AuditError::Inspect { path: error_path, .. }) if error_path == path)
        );
    }

    #[tokio::test]
    async fn validate_existing_audit_events_reports_reader_errors() {
        let path = Path::new("audit.ndjson");
        let mut initial_seek_reader = TailReader::failing(
            serialized_denied_event_line(),
            TailReaderFailure::InitialSeek,
        );
        let mut read_reader =
            TailReader::failing(serialized_denied_event_line(), TailReaderFailure::Read);
        let mut final_seek_reader =
            TailReader::failing(serialized_denied_event_line(), TailReaderFailure::FinalSeek);

        let initial_seek_result =
            validate_existing_audit_events(path, &mut initial_seek_reader).await;
        let read_result = validate_existing_audit_events(path, &mut read_reader).await;
        let final_seek_result = validate_existing_audit_events(path, &mut final_seek_reader).await;

        assert!(
            matches!(initial_seek_result, Err(AuditError::Inspect { path: error_path, .. }) if error_path == path)
        );
        assert!(
            matches!(read_result, Err(AuditError::Inspect { path: error_path, .. }) if error_path == path)
        );
        assert!(
            matches!(final_seek_result, Err(AuditError::Inspect { path: error_path, .. }) if error_path == path)
        );
    }

    #[tokio::test]
    async fn write_event_appends_one_ndjson_line() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        let config = GatewayConfig::for_test(audit_log.clone(), roomy_event_limit());
        let writer = AuditWriter::open(&config)
            .await
            .expect("audit writer should open");

        assert!(format!("{writer:?}").contains("AuditWriter"));
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
            .len()
            .checked_add(1)
            .expect("test event length should fit usize");
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
    async fn write_event_accepts_maximum_admitted_target_at_the_minimum() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        let path = format!("/{}", "a".repeat(MAX_ORIGIN_FORM_PATH_BYTES - 1));
        let query = "q".repeat(MAX_ORIGIN_FORM_QUERY_BYTES);
        let accepted =
            AcceptedTarget::new(&path, Some(&query)).expect("maximum admitted target should parse");
        let upstream_origin = upstream_origin();
        let upstream_url = upstream_origin
            .join_path_query(accepted.origin_form_path(), accepted.origin_form_query());
        let upstream = AuditUpstreamTarget::from_url(&upstream_url);
        let input = request_input(
            "GET",
            AuditTarget::from(accepted),
            AuditBodySummary::empty(),
        );
        let event = AuditEvent::new(AuditEventInput::new(
            input,
            AuditOutcome::allowed(ObservedBodySummary::Empty, StatusCode::OK, upstream),
        ));
        let config = GatewayConfig::for_test(
            audit_log.clone(),
            NonZeroUsize::new(MIN_AUDIT_EVENT_BYTES).expect("minimum should be non-zero"),
        );
        let writer = AuditWriter::open(&config)
            .await
            .expect("audit writer should open");

        writer
            .write_event(&event)
            .await
            .expect("a maximum admitted target should fit in the minimum event limit");

        let contents = fs::read_to_string(&audit_log).expect("audit log should be readable");
        assert_eq!(contents.lines().count(), 1);
    }

    #[tokio::test]
    async fn write_event_rejects_events_over_the_configured_maximum() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        let event = denied_event();
        let exact_size = serde_json::to_vec(&event)
            .expect("event should serialize")
            .len()
            .checked_add(1)
            .expect("test event length should fit usize");
        let too_small = exact_size
            .checked_sub(1)
            .and_then(NonZeroUsize::new)
            .expect("test event should be longer than one byte");
        let config = GatewayConfig::for_test(audit_log.clone(), too_small);
        let writer = AuditWriter::open(&config)
            .await
            .expect("audit writer should open");

        let result = writer.write_event(&event).await;

        assert!(matches!(
            result,
            Err(AuditError::EventTooLarge { bytes, max })
                if bytes == exact_size && max == too_small.get(),
        ));
        let contents = fs::read_to_string(&audit_log).expect("audit log should be readable");
        assert_eq!(contents, "");
    }

    #[tokio::test]
    async fn write_event_poisons_writer_after_partial_write_failure() {
        let written = StdArc::new(StdMutex::new(Vec::new()));
        let writer = AuditWriter::for_test_writer(
            PartialWriteThenFailWriter::new(StdArc::clone(&written), 8),
            AuditEventBytes::for_test(roomy_event_limit()),
        );

        let first = writer.write_event(&denied_event()).await;

        assert!(matches!(first, Err(AuditError::Write(_))));
        let after_first = written.lock().expect("written bytes should lock").clone();
        assert_eq!(after_first, b"{\"decisi");

        let second = writer.write_event(&denied_event()).await;

        assert!(matches!(second, Err(AuditError::Poisoned)));
        assert_eq!(
            written
                .lock()
                .expect("written bytes should lock")
                .as_slice(),
            after_first.as_slice()
        );
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
    use super::tests::{
        TailReader, TailReaderFailure, denial_existing_event_lines,
        duplicate_existing_request_ids_reject, existing_denial_error_classes_bind_statuses,
        existing_denied_target_distinguishes_authority_targets,
        existing_denied_target_rejects_non_denial_error_classes,
        existing_request_body_failures_require_unobserved_bodies,
        existing_response_error_classes_bind_statuses,
        existing_upstream_error_classes_bind_statuses, non_empty_body_value,
        oversized_response_body, required_nullable_fields_deserialize_in_place,
        required_nullable_fields_deserialize_present_values, response_error_existing_event_lines,
        schema_invalid_existing_event_lines, semantic_invalid_existing_event_lines,
        serialized_denied_event_line, serialized_denied_event_value, serialized_event_value_line,
        truncated_audit_methods_reject_non_writer_shapes,
    };
    use super::{
        AcceptedAuditTarget, AuditBodySummary, AuditDenial, AuditDenialReason, AuditEvent,
        AuditEventInput, AuditOutcome, AuditRequestInput, AuditResponseError,
        AuditResponseHeaderError, AuditTarget, AuditUpstreamError, AuditUpstreamTarget,
        AuditWriter, ObservedBodySummary, PreparsedAuditTarget, RejectedAuditTarget, RequestId,
        RunToken, RunTokenError, inspect_audit_log_tail, is_existing_request_id,
    };
    use crate::allowlist::{AcceptedTarget, AllowlistRejectionReason, TargetRejectionReason};
    use crate::body::{BodyDigest, NonEmptyBodyObservation, ResponseAccount};
    use crate::config::{
        GatewayConfig, MAX_ALLOWED_METHOD_BYTES, ResponseBodyBytes, UpstreamOrigin,
    };
    use crate::target::{MAX_ORIGIN_FORM_PATH_BYTES, MAX_ORIGIN_FORM_QUERY_BYTES};
    use ::http::{Method, StatusCode, Uri};
    use core::num::NonZeroU64;
    use core::num::NonZeroUsize;
    use core::time::Duration;
    use proptest::prelude::*;
    use proptest::{collection, option};
    use serde_json::{Map, Value, value::to_raw_value};
    use std::fs;
    use std::path::Path;
    #[cfg(unix)]
    use std::process::Command;
    use std::time::UNIX_EPOCH;
    use tempfile::tempdir;
    use tokio::runtime::{Builder, Runtime};

    /// Returns body length as a `u64`.
    fn body_len(bytes: &[u8]) -> u64 {
        u64::try_from(bytes.len()).expect("generated body length should fit u64")
    }

    /// Returns the digest for non-empty generated body bytes.
    fn body_digest(bytes: &[u8]) -> BodyDigest {
        BodyDigest::for_test(bytes)
    }

    /// Returns the observation for non-empty generated body bytes.
    fn non_empty_observation(bytes: &[u8]) -> NonEmptyBodyObservation {
        NonEmptyBodyObservation::for_test(bytes)
    }

    /// Returns a non-empty audit body summary for observed bytes.
    fn body_summary(bytes: &[u8]) -> AuditBodySummary {
        AuditBodySummary::non_empty(non_empty_observation(bytes))
    }

    /// Returns an observed body summary for observed bytes.
    fn observed_body_summary(bytes: &[u8]) -> ObservedBodySummary {
        ObservedBodySummary::NonEmpty(non_empty_observation(bytes))
    }

    /// Returns the serialized non-empty body summary for observed bytes.
    fn body_value(bytes: u64, digest: &str) -> Value {
        Value::Object(Map::from_iter([
            ("blake3".to_owned(), Value::String(digest.to_owned())),
            ("bytes".to_owned(), Value::from(bytes)),
            ("state".to_owned(), Value::String("non_empty".to_owned())),
        ]))
    }

    /// Returns an accepted audit target for generated denial constructors.
    fn accepted_audit_target() -> AcceptedAuditTarget {
        let target =
            AcceptedTarget::new("/v1/models", Some("limit=1")).expect("target should be accepted");
        AcceptedAuditTarget::from_accepted(&target)
    }

    /// Returns one audit denial constructor output by index.
    fn audit_denial(index: u8) -> (AuditDenial, AuditDenialReason) {
        let method = Method::POST;
        match index {
            0 => (
                AuditDenial::absolute_form_unsupported(method, preparsed_audit_target()),
                AuditDenialReason::AbsoluteFormUnsupported,
            ),
            1 => (
                AuditDenial::connect_unsupported(preparsed_audit_target()),
                AuditDenialReason::ConnectUnsupported,
            ),
            2 => (
                AuditDenial::target_rejected(
                    method,
                    rejected_audit_target(TargetRejectionReason::DotSegment),
                ),
                AuditDenialReason::DotSegment,
            ),
            3 => (
                AuditDenial::target_rejected(
                    method,
                    rejected_audit_target(TargetRejectionReason::EncodedSeparator),
                ),
                AuditDenialReason::EncodedSeparator,
            ),
            4 => (
                AuditDenial::target_rejected(
                    method,
                    rejected_audit_target(TargetRejectionReason::InvalidPercentEncoding),
                ),
                AuditDenialReason::InvalidPercentEncoding,
            ),
            5 => (
                AuditDenial::invalid_request_connection_header(method, accepted_audit_target()),
                AuditDenialReason::InvalidRequestConnectionHeader,
            ),
            6 => (
                AuditDenial::allowlist_rejected(
                    method,
                    accepted_audit_target(),
                    AllowlistRejectionReason::MethodDenied,
                ),
                AuditDenialReason::MethodDenied,
            ),
            7 => (
                AuditDenial::target_rejected(
                    method,
                    rejected_audit_target(TargetRejectionReason::NonOriginForm),
                ),
                AuditDenialReason::NonOriginForm,
            ),
            8 => (
                AuditDenial::allowlist_rejected(
                    method,
                    accepted_audit_target(),
                    AllowlistRejectionReason::PathDenied,
                ),
                AuditDenialReason::PathDenied,
            ),
            9 => (
                AuditDenial::target_rejected(
                    method,
                    rejected_audit_target(TargetRejectionReason::PathTooLong),
                ),
                AuditDenialReason::PathTooLong,
            ),
            10 => (
                AuditDenial::target_rejected(
                    method,
                    rejected_audit_target(TargetRejectionReason::QueryTooLong),
                ),
                AuditDenialReason::QueryTooLong,
            ),
            11 => (
                AuditDenial::request_body_read_failed(method, accepted_audit_target()),
                AuditDenialReason::RequestBodyReadFailed,
            ),
            12 => (
                AuditDenial::request_body_timeout(method, accepted_audit_target()),
                AuditDenialReason::RequestBodyTimeout,
            ),
            13 => (
                AuditDenial::request_body_too_large(method, accepted_audit_target()),
                AuditDenialReason::RequestBodyTooLarge,
            ),
            14 => (
                AuditDenial::request_headers_too_large(method, accepted_audit_target()),
                AuditDenialReason::RequestHeadersTooLarge,
            ),
            _ => (
                AuditDenial::too_many_requests(method, preparsed_audit_target()),
                AuditDenialReason::TooManyRequests,
            ),
        }
    }

    /// Returns a preparsed audit target for generated denial constructors.
    fn preparsed_audit_target() -> PreparsedAuditTarget {
        PreparsedAuditTarget::from_request_uri(&Uri::from_static("/v1/models?limit=1"))
    }

    /// Returns a parser-rejected audit target for generated denial constructors.
    fn rejected_audit_target(reason: TargetRejectionReason) -> RejectedAuditTarget {
        let uri = uri_for_target_rejection(reason);
        let rejection =
            RejectedAuditTarget::accept_request_uri(&uri).expect_err("target should be rejected");
        assert_eq!(rejection.reason(), reason);
        rejection
    }

    /// Returns a URI rejected by the target parser with the requested reason.
    fn uri_for_target_rejection(reason: TargetRejectionReason) -> Uri {
        match reason {
            TargetRejectionReason::DotSegment => Uri::from_static("/v1/../models"),
            TargetRejectionReason::EncodedSeparator => Uri::from_static("/v1/%2fmodels"),
            TargetRejectionReason::InvalidPercentEncoding => Uri::from_static("/v1/%zz"),
            TargetRejectionReason::NonOriginForm => Uri::from_static("*"),
            TargetRejectionReason::PathTooLong => {
                format!("/{}", "a".repeat(MAX_ORIGIN_FORM_PATH_BYTES))
                    .parse()
                    .expect("URI should parse")
            }
            TargetRejectionReason::QueryTooLong => {
                format!("/v1/models?{}", "q".repeat(MAX_ORIGIN_FORM_QUERY_BYTES + 1))
                    .parse()
                    .expect("URI should parse")
            }
        }
    }

    #[test]
    fn request_uri_audit_targets_preserve_origin_and_authority_forms() {
        let cases = [
            (
                Uri::from_static("/v1/models?limit=1"),
                "/v1/models",
                Some("limit=1"),
            ),
            (
                Uri::from_static("http://evil.example/steal?limit=1"),
                "http://evil.example/steal",
                Some("limit=1"),
            ),
            (
                Uri::from_static("evil.example:443"),
                "evil.example:443",
                None,
            ),
        ];

        for (uri, path, query) in cases {
            let target = AuditTarget::from_request_uri(&uri);

            assert_eq!(target.path(), path);
            assert_eq!(target.query(), query);
        }
    }

    #[test]
    fn empty_response_account_serializes_as_empty_body() {
        let account = ResponseAccount::new(ResponseBodyBytes::for_test(
            NonZeroU64::new(1).expect("limit should be non-zero"),
        ));
        let summary = ObservedBodySummary::from_response_account(&account).into_summary();

        let value = serde_json::to_value(summary).expect("summary should serialize");

        assert_eq!(
            value,
            Value::Object(Map::from_iter([(
                "state".to_owned(),
                Value::String("empty".to_owned()),
            )])),
        );
    }

    #[test]
    fn request_id_serializes_as_wire_text_across_json_encoders() {
        let sequence = NonZeroU64::new(15).expect("sequence should be non-zero");
        let request_id = RequestId::from_parts(
            &RunToken::for_test("0000000000007e57-000000000000c0de"),
            sequence,
        );
        let expected = "\"req-0000000000007e57-000000000000c0de-000000000000000f\"";

        let string = serde_json::to_string(&request_id).expect("request id should serialize");
        let bytes = serde_json::to_vec(&request_id).expect("request id should serialize");
        let raw_value = to_raw_value(&request_id).expect("request id should serialize");
        let value = serde_json::to_value(request_id).expect("request id should serialize");

        assert_eq!(string, expected);
        assert_eq!(bytes, expected.as_bytes());
        assert_eq!(raw_value.get(), expected);
        assert_eq!(
            value.as_str(),
            Some("req-0000000000007e57-000000000000c0de-000000000000000f")
        );
    }

    /// Generates observed non-empty body bytes.
    fn non_empty_body() -> impl Strategy<Value = Vec<u8>> {
        collection::vec(any::<u8>(), 1..33)
    }

    /// Generates valid run tokens matching the production two-part shape.
    fn run_token_valid() -> impl Strategy<Value = String> {
        ("[0-9a-f]{16}", "[0-9a-f]{16}").prop_map(|(first, second)| format!("{first}-{second}"))
    }

    /// Generates exact-length run tokens with misplaced separators.
    fn run_token_invalid_shape() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("aaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb".to_owned()),
            Just("aaaaaaaaaaaaaaa--bbbbbbbbbbbbbbbb".to_owned()),
            Just("aaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbb-".to_owned()),
        ]
    }

    /// Returns a parsed method from generated method text.
    fn method_value(method: &str) -> Method {
        Method::from_bytes(method.as_bytes()).expect("generated method should parse")
    }

    /// Generates method text across the audited method boundary.
    fn method_text() -> impl Strategy<Value = String> {
        prop_oneof![
            8 => "[A-Z]{3,8}",
            1 => Just("A".repeat(MAX_ALLOWED_METHOD_BYTES + 1)),
        ]
    }

    /// Returns one closed denial reason from a generated index.
    const fn denial_reason(index: u8) -> AuditDenialReason {
        match index {
            0 => AuditDenialReason::AbsoluteFormUnsupported,
            1 => AuditDenialReason::ConnectUnsupported,
            2 => AuditDenialReason::DotSegment,
            3 => AuditDenialReason::EncodedSeparator,
            4 => AuditDenialReason::InvalidPercentEncoding,
            5 => AuditDenialReason::InvalidRequestConnectionHeader,
            6 => AuditDenialReason::MethodDenied,
            7 => AuditDenialReason::NonOriginForm,
            8 => AuditDenialReason::PathDenied,
            9 => AuditDenialReason::PathTooLong,
            10 => AuditDenialReason::QueryTooLong,
            11 => AuditDenialReason::RequestBodyReadFailed,
            12 => AuditDenialReason::RequestBodyTimeout,
            13 => AuditDenialReason::RequestBodyTooLarge,
            14 => AuditDenialReason::RequestHeadersTooLarge,
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

    /// Returns a denied audit event for writer proptests.
    fn denied_audit_event() -> AuditEvent {
        let request = AuditRequestInput::new(
            Method::GET,
            AuditTarget::from_uri_parts("/v1/models", None),
            RequestId::from_parts(
                &RunToken::for_test("000000000000000a-000000000000000b"),
                NonZeroU64::new(1).expect("literal should be non-zero"),
            ),
            AuditBodySummary::empty(),
            upstream_origin(),
        );
        AuditEvent::new(AuditEventInput::new(
            request,
            AuditOutcome::denied(AuditDenialReason::MethodDenied),
        ))
    }

    /// Returns an audit event byte limit large enough for open-only tests.
    fn roomy_event_limit() -> NonZeroUsize {
        NonZeroUsize::new(4096).expect("event limit should be non-zero")
    }

    /// Returns a local runtime for audit writer tests.
    fn audit_runtime() -> Runtime {
        Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("audit runtime should build")
    }

    /// Opens an audit writer on a local test runtime.
    fn open_writer(config: &GatewayConfig) -> Result<AuditWriter, super::AuditError> {
        audit_runtime().block_on(AuditWriter::open(config))
    }

    /// Asserts that one existing audit log line is accepted at startup.
    fn assert_existing_log_accepts(
        directory: &Path,
        filename: String,
        contents: Vec<u8>,
        case_name: &str,
    ) {
        let audit_log = directory.join(filename);
        fs::write(&audit_log, contents).expect("valid audit log should be written");

        let result = open_writer(&GatewayConfig::for_test(audit_log, roomy_event_limit()));

        assert!(result.is_ok(), "{case_name} should be accepted");
    }

    /// Asserts that one existing audit log line is rejected as corrupt.
    fn assert_existing_log_rejects(
        directory: &Path,
        filename: String,
        contents: Vec<u8>,
        case_name: &str,
    ) {
        let audit_log = directory.join(filename);
        fs::write(&audit_log, contents).expect("invalid audit log should be written");

        let result = open_writer(&GatewayConfig::for_test(
            audit_log.clone(),
            roomy_event_limit(),
        ));

        assert!(
            matches!(result, Err(super::AuditError::CorruptLog { path, .. }) if path == audit_log),
            "{case_name} should be rejected"
        );
    }

    #[test]
    fn run_token_parser_covers_each_boundary_class() {
        let all_digits = "0123456789abcdef-fedcba9876543210";

        let token = RunToken::new(all_digits).expect("all lower-hex digits should parse");

        assert_eq!(token.to_string(), all_digits);
        assert_eq!(RunToken::new(""), Err(RunTokenError::Empty));
        assert_eq!(
            RunToken::new("g123456789abcdef-fedcba9876543210"),
            Err(RunTokenError::InvalidCharacter),
        );
        assert_eq!(
            RunToken::new("0g23456789abcdef-fedcba9876543210"),
            Err(RunTokenError::InvalidCharacter),
        );
        assert_eq!(
            RunToken::new("0123456789abcdef_fedcba9876543210"),
            Err(RunTokenError::InvalidCharacter),
        );
        assert_eq!(RunToken::new("AB-cd"), Err(RunTokenError::InvalidCharacter),);
        assert_eq!(
            RunToken::new("0123456789abcdef-fedcba9876543210f"),
            Err(RunTokenError::TooLong),
        );
        assert_eq!(
            RunToken::new("0123456789abcdef0fedcba987654321"),
            Err(RunTokenError::InvalidShape),
        );
        assert_eq!(
            RunToken::new("0123456789abcde--fedcba9876543210"),
            Err(RunTokenError::InvalidShape),
        );
    }

    #[test]
    fn open_classifies_existing_log_tails() {
        let directory = tempdir().expect("temporary directory should be created");
        let empty_log = directory.path().join("empty.ndjson");
        let complete_log = directory.path().join("complete.ndjson");
        let torn_log = directory.path().join("torn.ndjson");
        fs::write(&complete_log, serialized_denied_event_line())
            .expect("complete log should be written");
        fs::write(&torn_log, b"{\"version\":3}").expect("torn log should be written");

        let empty_result = open_writer(&GatewayConfig::for_test(empty_log, roomy_event_limit()));
        let complete_result =
            open_writer(&GatewayConfig::for_test(complete_log, roomy_event_limit()));
        let torn_result = open_writer(&GatewayConfig::for_test(
            torn_log.clone(),
            roomy_event_limit(),
        ));

        empty_result.expect("missing audit log should open");
        complete_result.expect("newline-terminated audit log should open");
        assert!(matches!(
            torn_result,
            Err(super::AuditError::TornLog { path }) if path == torn_log
        ));
    }

    #[test]
    fn existing_audit_log_schema_rejects_invalid_field_states() {
        let directory = tempdir().expect("temporary directory should be created");
        let valid_log = directory.path().join("valid.ndjson");
        let mut event = serialized_denied_event_value();
        let object = event
            .as_object_mut()
            .expect("serialized event should be an object");
        object.insert("request_body".to_owned(), non_empty_body_value());
        fs::write(&valid_log, serialized_event_value_line(&event))
            .expect("valid log should be written");

        open_writer(&GatewayConfig::for_test(valid_log, roomy_event_limit()))
            .expect("valid existing log should open");

        let valid_query_log = directory.path().join("valid-query.ndjson");
        let valid_query_line = serialized_event_value_line(&Value::Object(Map::from_iter([
            ("decision".to_owned(), Value::String("allowed".to_owned())),
            ("error_class".to_owned(), Value::Null),
            ("method".to_owned(), Value::String("GET".to_owned())),
            ("path".to_owned(), Value::String("/v1/models".to_owned())),
            ("query".to_owned(), Value::String("q='".to_owned())),
            ("request_body".to_owned(), non_empty_body_value()),
            (
                "request_id".to_owned(),
                Value::String("req-000000000000000a-000000000000000b-0000000000000001".to_owned()),
            ),
            ("response_body".to_owned(), non_empty_body_value()),
            ("status".to_owned(), Value::from(200_u64)),
            (
                "timestamp".to_owned(),
                Value::String("1970-01-01T00:00:00.000000000Z".to_owned()),
            ),
            (
                "upstream_origin".to_owned(),
                Value::String("https://api.openai.com".to_owned()),
            ),
            (
                "upstream_path".to_owned(),
                Value::String("/v1/models".to_owned()),
            ),
            (
                "upstream_query".to_owned(),
                Value::String("q=%27".to_owned()),
            ),
            ("version".to_owned(), Value::from(3_u64)),
        ])));
        fs::write(&valid_query_log, valid_query_line).expect("valid log should be written");

        open_writer(&GatewayConfig::for_test(
            valid_query_log,
            roomy_event_limit(),
        ))
        .expect("valid query-bearing existing log should open");

        for (index, (case_name, contents)) in denial_existing_event_lines().into_iter().enumerate()
        {
            assert_existing_log_accepts(
                directory.path(),
                format!("valid-denial-shape-{index}.ndjson"),
                contents,
                case_name,
            );
        }

        for (index, (case_name, contents)) in response_error_existing_event_lines()
            .into_iter()
            .enumerate()
        {
            assert_existing_log_accepts(
                directory.path(),
                format!("valid-response-error-{index}.ndjson"),
                contents,
                case_name,
            );
        }

        for (index, (case_name, contents)) in schema_invalid_existing_event_lines()
            .into_iter()
            .enumerate()
        {
            assert_existing_log_rejects(
                directory.path(),
                format!("invalid-{index}.ndjson"),
                contents,
                case_name,
            );
        }

        for (index, (case_name, contents)) in semantic_invalid_existing_event_lines()
            .into_iter()
            .enumerate()
        {
            assert_existing_log_rejects(
                directory.path(),
                format!("semantic-invalid-{index}.ndjson"),
                contents,
                case_name,
            );
        }
    }

    #[test]
    fn existing_audit_helpers_cover_closed_domains_under_property_filter() {
        existing_denial_error_classes_bind_statuses();
        existing_denied_target_distinguishes_authority_targets();
        existing_denied_target_rejects_non_denial_error_classes();
        existing_request_body_failures_require_unobserved_bodies();
        existing_response_error_classes_bind_statuses();
        existing_upstream_error_classes_bind_statuses();
        audit_runtime().block_on(duplicate_existing_request_ids_reject());
        assert!(!is_existing_request_id("request-id"));
        assert!(!is_existing_request_id("req-000000000000000a"));
        assert!(!is_existing_request_id(
            "req-000000000000000a-000000000000000b"
        ));
        required_nullable_fields_deserialize_in_place();
        required_nullable_fields_deserialize_present_values();
        truncated_audit_methods_reject_non_writer_shapes();
    }

    #[test]
    fn write_event_checks_serialized_size_bound_under_property_filter() {
        let directory = tempdir().expect("temporary directory should be created");
        let accepted_log = directory.path().join("accepted.ndjson");
        let rejected_log = directory.path().join("rejected.ndjson");
        let event = denied_audit_event();
        let exact_size = serde_json::to_vec(&event)
            .expect("event should serialize")
            .len()
            .checked_add(1)
            .expect("test event length should fit usize");
        let exact_limit = NonZeroUsize::new(exact_size).expect("event length should be non-zero");
        let too_small = exact_size
            .checked_sub(1)
            .and_then(NonZeroUsize::new)
            .expect("test event should be longer than one byte");
        let accepted_config = GatewayConfig::for_test(accepted_log, exact_limit);
        let rejected_config = GatewayConfig::for_test(rejected_log, too_small);
        let runtime = audit_runtime();

        let accepted_writer = runtime
            .block_on(AuditWriter::open(&accepted_config))
            .expect("accepted writer should open");
        let rejected_writer = runtime
            .block_on(AuditWriter::open(&rejected_config))
            .expect("rejected writer should open");
        let accepted = runtime.block_on(accepted_writer.write_event(&event));
        let rejected = runtime.block_on(rejected_writer.write_event(&event));

        accepted.expect("event at exact limit should be accepted");
        assert!(matches!(
            rejected,
            Err(super::AuditError::EventTooLarge { bytes, max })
                if bytes == exact_size && max == too_small.get()
        ));
    }

    #[cfg(unix)]
    #[test]
    fn open_reports_unseekable_audit_logs() {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        let status = Command::new("mkfifo")
            .arg(&audit_log)
            .status()
            .expect("mkfifo should run");
        assert!(status.success());

        let result = open_writer(&GatewayConfig::for_test(
            audit_log.clone(),
            roomy_event_limit(),
        ));

        assert!(matches!(
            result,
            Err(super::AuditError::Inspect { path, .. }) if path == audit_log
        ));
    }

    #[test]
    fn tail_inspection_reports_final_seek_and_read_errors() {
        let path = Path::new("audit.ndjson");
        let runtime = audit_runtime();
        let mut final_seek_reader =
            TailReader::failing(*b"{\"version\":3}\n", TailReaderFailure::FinalSeek);
        let mut read_reader = TailReader::failing(*b"{\"version\":3}\n", TailReaderFailure::Read);

        let final_seek_result =
            runtime.block_on(inspect_audit_log_tail(path, &mut final_seek_reader));
        let read_result = runtime.block_on(inspect_audit_log_tail(path, &mut read_reader));

        assert!(matches!(
            final_seek_result,
            Err(super::AuditError::Inspect { path: error_path, .. }) if error_path == path
        ));
        assert!(matches!(
            read_result,
            Err(super::AuditError::Inspect { path: error_path, .. }) if error_path == path
        ));
    }

    #[test]
    fn every_audit_denial_constructor_preserves_reason_and_status() {
        for index in 0_u8..16 {
            let (denial, expected_reason) = audit_denial(index);
            let expected_status = expected_reason.status();
            let actual_status = denial.status();
            let (method, _target, reason) = denial.into_parts();

            assert_eq!(reason, expected_reason);
            assert_eq!(actual_status, expected_status);
            assert_eq!(expected_status, reason.status());
            if expected_reason == AuditDenialReason::ConnectUnsupported {
                assert_eq!(method, Method::CONNECT);
            }
        }
    }

    proptest! {
        #[test]
        fn audit_denial_constructors_preserve_reason_and_status(index in 0_u8..16) {
            let (denial, expected_reason) = audit_denial(index);
            let expected_status = expected_reason.status();
            let actual_status = denial.status();
            let (method, _target, reason) = denial.into_parts();

            prop_assert_eq!(reason, expected_reason);
            prop_assert_eq!(actual_status, expected_status);
            prop_assert_eq!(expected_status, reason.status());
            if expected_reason == AuditDenialReason::ConnectUnsupported {
                prop_assert_eq!(method, Method::CONNECT);
            }
        }

        #[test]
        fn event_serialization_preserves_variant_semantics(
            outcome_kind in 0_u8..4,
            denial_kind in 0_u8..16,
            response_error_kind in 0_u8..6,
            upstream_error_kind in 0_u8..3,
            method in method_text(),
            path in raw_path(),
            query in option::of("[a-z]{1,5}=[a-z]{1,5}"),
            upstream_path in "/[A-Za-z0-9/_-]{0,20}",
            upstream_query in option::of("[a-z]{1,5}=[a-z]{1,5}"),
            status_code_value in 100_u16..600,
            request_body_bytes in non_empty_body(),
            response_body_bytes in non_empty_body(),
            run_token in run_token_valid(),
            sequence_value in 1_u64..=u64::MAX,
        ) {
            let sequence =
                NonZeroU64::new(sequence_value).expect("generated sequence should be non-zero");
            let status = status_code(status_code_value);
            let request_body = body_summary(&request_body_bytes);
            let request_bytes = body_len(&request_body_bytes);
            let request_digest = body_digest(&request_body_bytes).to_hex_string();
            let observed_response_body = observed_body_summary(&response_body_bytes);
            let response_bytes = body_len(&response_body_bytes);
            let response_digest = body_digest(&response_body_bytes).to_hex_string();
            let upstream = AuditUpstreamTarget::new(&upstream_path, upstream_query.as_deref());
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
                        1 => {
                            let overflow_body = b"overflow";
                            let overflow_digest = body_digest(overflow_body).to_hex_string();
                            (
                                AuditResponseError::response_body_too_large(
                                    oversized_response_body(overflow_body),
                                    status,
                                ),
                                body_value(body_len(overflow_body), &overflow_digest),
                            )
                        }
                        2 => (
                            AuditResponseError::response_header(response_header_error(0)),
                            not_observed_body_value(),
                        ),
                        3 => (
                            AuditResponseError::response_header(response_header_error(1)),
                            not_observed_body_value(),
                        ),
                        4 => (
                            AuditResponseError::upstream_response_stream_failed(
                                observed_response_body,
                                status,
                            ),
                            body_value(response_bytes, &response_digest),
                        ),
                        _ => (
                            AuditResponseError::upstream_response_timeout(
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
            let request_run_token =
                RunToken::new(run_token).expect("generated run token should be valid");
            let request = AuditRequestInput::new(
                method_value(&method),
                AuditTarget::from_uri_parts(&path, query.as_deref()),
                RequestId::from_parts(&request_run_token, sequence),
                request_body,
                upstream_origin(),
            );
            let input = AuditEventInput::new(request, outcome);

            let event = AuditEvent::new(input);
            let value = serde_json::to_value(&event).expect("event should serialize");
            let serialized = serde_json::to_vec(&event).expect("event should serialize to bytes");
            let serialized_value: Value =
                serde_json::from_slice(&serialized).expect("serialized event should parse");
            let serialized_text =
                serde_json::to_string(&event).expect("event should serialize to text");
            let text_value: Value =
                serde_json::from_str(&serialized_text).expect("serialized event text should parse");
            let object = value.as_object().expect("event should be a JSON object");

            prop_assert_eq!(&serialized_value, &value);
            prop_assert_eq!(&text_value, &value);
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
            run_token in run_token_valid(),
            sequence_value in 1_u64..=u64::MAX,
        ) {
            let sequence =
                NonZeroU64::new(sequence_value).expect("generated sequence should be non-zero");
            let request_run_token =
                RunToken::new(run_token.clone()).expect("generated run token should be valid");
            let value = serde_json::to_value(RequestId::from_parts(&request_run_token, sequence))
                .expect("request id should serialize");

            let expected = format!("req-{run_token}-{sequence_value:016x}");
            prop_assert_eq!(value.as_str(), Some(expected.as_str()));
        }

        #[test]
        fn run_token_rejects_generated_invalid_shapes(
            run_token in run_token_invalid_shape(),
        ) {
            prop_assert_eq!(RunToken::new(run_token), Err(RunTokenError::InvalidShape));
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
