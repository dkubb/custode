//! Runtime port traits and values.

use crate::allowlist::AllowedTarget;
use crate::audit::{AuditError, AuditEvent, AuditTimestamp, RequestId};
use crate::body::AccountedBody;
use crate::config::{RequestTimeout, UpstreamOrigin};
use crate::headers::ForwardedRequestHeaders;
use axum::body::Bytes;
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use futures_util::stream::BoxStream;
use http::{HeaderMap, Method, StatusCode};
use non_empty_string::NonEmptyString;
use thiserror::Error;
use url::Url;

/// Maximum retained diagnostic bytes for upstream errors.
const MAX_UPSTREAM_ERROR_MESSAGE_BYTES: usize = 4_096;

/// Boxed future returned by runtime ports.
pub(crate) type BoxFuture<'future, T> = Pin<Box<dyn Future<Output = T> + Send + 'future>>;

/// Streaming upstream response body.
pub(crate) type UpstreamBody = BoxStream<'static, Result<Bytes, UpstreamBodyError>>;

/// Per-request upstream timeout deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UpstreamDeadline {
    /// Timeout duration applied to the upstream request.
    timeout: Duration,
}

/// Port that supplies audit timestamps.
pub(crate) trait Clock: fmt::Debug + Send + Sync {
    /// Returns the current audit timestamp.
    fn now(&self) -> AuditTimestamp;
}

/// Port that writes audit events.
pub(crate) trait AuditSink: fmt::Debug + Send + Sync {
    /// Writes one required audit event.
    fn append_event<'future>(
        &'future self,
        event: &'future AuditEvent,
    ) -> BoxFuture<'future, Result<(), AuditError>>;
}

/// Port that allocates request identities.
pub(crate) trait RequestIdSource: fmt::Debug + Send + Sync {
    /// Allocates the next request identity.
    fn next_request_id(&self) -> Result<RequestId, RequestIdError>;
}

/// Request identity allocation error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum RequestIdError {
    /// All non-zero request sequence numbers have already been allocated.
    #[error("request id sequence exhausted")]
    SequenceExhausted,
}

/// Port that sends accepted requests to the configured provider.
pub(crate) trait UpstreamClient: fmt::Debug + Send + Sync {
    /// Sends one upstream request.
    fn send(
        &self,
        request: UpstreamRequest,
    ) -> BoxFuture<'_, Result<UpstreamResponse, UpstreamError>>;
}

/// Request passed to the upstream client port.
#[derive(Debug)]
pub(crate) struct UpstreamRequest {
    /// Upstream request body bytes.
    body: Vec<u8>,
    /// Per-request upstream timeout deadline.
    deadline: UpstreamDeadline,
    /// Upstream request headers.
    headers: HeaderMap,
    /// Upstream request method.
    method: Method,
    /// Fully joined upstream URL.
    url: Url,
}

/// Response returned by the upstream client port.
pub(crate) struct UpstreamResponse {
    /// Streaming response body.
    body: UpstreamBody,
    /// Upstream response headers.
    headers: HeaderMap,
    /// Upstream response status.
    status: StatusCode,
}

/// Upstream request failure kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UpstreamErrorKind {
    /// The upstream connection could not be established.
    Connect,

    /// The upstream request failed before a response was available.
    Request,

    /// The upstream request timed out.
    Timeout,
}

/// Upstream request failure.
#[derive(Debug, Error)]
#[error("{message}")]
pub(crate) struct UpstreamError {
    /// Stable failure kind.
    kind: UpstreamErrorKind,
    /// Source error message.
    message: UpstreamErrorMessage,
}

/// Upstream response body streaming failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub(crate) struct UpstreamBodyError {
    /// Stable response-body failure kind.
    kind: UpstreamBodyErrorKind,
    /// Source error message.
    message: UpstreamErrorMessage,
}

/// Upstream response body failure kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UpstreamBodyErrorKind {
    /// Upstream response body stream failed.
    Stream,

    /// Upstream response body timed out after response headers arrived.
    Timeout,
}

/// Bounded non-empty upstream diagnostic message.
#[derive(Clone, Debug, Eq, PartialEq)]
struct UpstreamErrorMessage {
    /// Bounded non-empty text.
    value: NonEmptyString,
}

impl UpstreamDeadline {
    /// Creates a deadline from a configured timeout duration.
    #[must_use]
    pub(crate) const fn from_timeout(timeout: RequestTimeout) -> Self {
        Self {
            timeout: timeout.as_duration(),
        }
    }

    /// Returns the timeout duration.
    #[must_use]
    pub(crate) const fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl UpstreamBodyError {
    /// Returns the stable failure kind.
    #[must_use]
    pub(crate) const fn kind(&self) -> UpstreamBodyErrorKind {
        self.kind
    }

    /// Creates an upstream body stream error.
    #[must_use]
    pub(crate) fn stream(message: impl Into<String>) -> Self {
        Self {
            kind: UpstreamBodyErrorKind::Stream,
            message: UpstreamErrorMessage::new(
                message,
                default_upstream_body_error_message(UpstreamBodyErrorKind::Stream),
            ),
        }
    }

    /// Creates an upstream body timeout error.
    #[must_use]
    pub(crate) fn timeout(message: impl Into<String>) -> Self {
        Self {
            kind: UpstreamBodyErrorKind::Timeout,
            message: UpstreamErrorMessage::new(
                message,
                default_upstream_body_error_message(UpstreamBodyErrorKind::Timeout),
            ),
        }
    }
}

impl UpstreamError {
    /// Returns the stable failure kind.
    #[must_use]
    pub(crate) const fn kind(&self) -> UpstreamErrorKind {
        self.kind
    }

    /// Creates an upstream request error.
    #[must_use]
    pub(crate) fn new(kind: UpstreamErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: UpstreamErrorMessage::new(message, default_upstream_error_message(kind)),
        }
    }
}

impl UpstreamErrorMessage {
    /// Creates a bounded non-empty diagnostic message.
    fn new(raw_message: impl Into<String>, fallback: &'static str) -> Self {
        let message = bounded_message(raw_message.into(), fallback);
        Self {
            value: NonEmptyString::new(message)
                .expect("bounded upstream message should be non-empty"),
        }
    }
}

impl UpstreamRequest {
    /// Returns the upstream request body.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the upstream request deadline.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn deadline(&self) -> UpstreamDeadline {
        self.deadline
    }

    /// Creates an upstream request from proof-carrying forwarding inputs.
    #[must_use]
    pub(crate) fn from_target(
        origin: &UpstreamOrigin,
        target: &AllowedTarget,
        headers: ForwardedRequestHeaders,
        body: &AccountedBody,
        deadline: UpstreamDeadline,
    ) -> Self {
        Self {
            body: body.bytes().to_vec(),
            deadline,
            headers: headers.into_header_map(),
            method: target.method().clone(),
            url: origin.join_path_query(
                target.target().origin_form_path(),
                target.target().origin_form_query(),
            ),
        }
    }

    /// Returns the upstream request headers.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Consumes the request into upstream adapter parts.
    #[must_use]
    pub(crate) fn into_parts(self) -> (Method, Url, HeaderMap, Vec<u8>, UpstreamDeadline) {
        (
            self.method,
            self.url,
            self.headers,
            self.body,
            self.deadline,
        )
    }

    /// Returns the upstream request method.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the upstream request URL.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn url(&self) -> &Url {
        &self.url
    }
}

impl UpstreamResponse {
    /// Returns the upstream response headers.
    #[must_use]
    pub(crate) const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Consumes the response and returns its body stream.
    #[must_use]
    pub(crate) fn into_body(self) -> UpstreamBody {
        self.body
    }

    /// Creates an upstream response.
    #[must_use]
    pub(crate) const fn new(status: StatusCode, headers: HeaderMap, body: UpstreamBody) -> Self {
        Self {
            body,
            headers,
            status,
        }
    }

    /// Returns the upstream response status.
    #[must_use]
    pub(crate) const fn status(&self) -> StatusCode {
        self.status
    }
}

impl fmt::Debug for UpstreamResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpstreamResponse")
            .field("headers", &self.headers)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for UpstreamErrorMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(f)
    }
}

/// Returns a bounded non-empty upstream error message.
fn bounded_message(mut message: String, fallback: &'static str) -> String {
    if message.is_empty() {
        message.push_str(fallback);
    }
    if message.len() > MAX_UPSTREAM_ERROR_MESSAGE_BYTES {
        truncate_utf8(&mut message, MAX_UPSTREAM_ERROR_MESSAGE_BYTES);
    }
    message
}

/// Returns the fallback message for an upstream request failure kind.
const fn default_upstream_error_message(kind: UpstreamErrorKind) -> &'static str {
    match kind {
        UpstreamErrorKind::Connect => "upstream connection failed",
        UpstreamErrorKind::Request => "upstream request failed",
        UpstreamErrorKind::Timeout => "upstream request timed out",
    }
}

/// Returns the fallback message for an upstream body failure kind.
const fn default_upstream_body_error_message(kind: UpstreamBodyErrorKind) -> &'static str {
    match kind {
        UpstreamBodyErrorKind::Stream => "upstream response body failed",
        UpstreamBodyErrorKind::Timeout => "upstream response body timed out",
    }
}

/// Truncates a string to a byte limit without splitting a UTF-8 code point.
fn truncate_utf8(message: &mut String, max_bytes: usize) {
    let mut end = max_bytes.min(message.len());
    while !message.is_char_boundary(end) {
        end = end
            .checked_sub(1)
            .expect("string start should always be a char boundary");
    }
    message.truncate(end);
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[expect(
    clippy::inline_modules,
    reason = "inline tests keep file-local coverage ownership explicit"
)]
mod tests {
    use super::{
        MAX_UPSTREAM_ERROR_MESSAGE_BYTES, UpstreamBodyError, UpstreamBodyErrorKind, UpstreamError,
        UpstreamErrorKind, UpstreamResponse,
    };
    use futures_util::{StreamExt as _, stream};
    use http::{HeaderMap, StatusCode};
    use pretty_assertions::assert_eq;

    #[test]
    fn upstream_response_debug_reports_headers_and_status() {
        let mut headers = HeaderMap::new();
        headers.insert("x-test", "present".parse().expect("header should parse"));
        let response = UpstreamResponse::new(StatusCode::OK, headers, stream::empty().boxed());

        let output = format!("{response:?}");

        assert_eq!(
            output,
            "UpstreamResponse { headers: {\"x-test\": \"present\"}, status: 200, .. }"
        );
    }

    #[test]
    fn upstream_body_error_preserves_non_empty_messages() {
        let error = UpstreamBodyError::stream("stream failed");

        assert_eq!(error.kind(), UpstreamBodyErrorKind::Stream);
        assert_eq!(error.to_string(), "stream failed");
    }

    #[test]
    fn upstream_body_error_replaces_empty_messages_by_kind() {
        let cases = [
            (
                UpstreamBodyError::stream(""),
                UpstreamBodyErrorKind::Stream,
                "upstream response body failed",
            ),
            (
                UpstreamBodyError::timeout(""),
                UpstreamBodyErrorKind::Timeout,
                "upstream response body timed out",
            ),
        ];

        for (error, kind, expected) in cases {
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn upstream_body_error_truncates_long_unicode_messages() {
        let error = UpstreamBodyError::stream("\u{20ac}".repeat(2_000));

        assert_eq!(
            error.to_string().len(),
            MAX_UPSTREAM_ERROR_MESSAGE_BYTES - 1
        );
        assert!(
            error
                .to_string()
                .chars()
                .all(|character| character == '\u{20ac}')
        );
    }

    #[test]
    fn upstream_error_preserves_non_empty_messages() {
        let error = UpstreamError::new(UpstreamErrorKind::Request, "protocol failed");

        assert_eq!(error.kind(), UpstreamErrorKind::Request);
        assert_eq!(error.to_string(), "protocol failed");
    }

    #[test]
    fn upstream_error_truncates_long_messages() {
        let error = UpstreamError::new(
            UpstreamErrorKind::Request,
            "x".repeat(MAX_UPSTREAM_ERROR_MESSAGE_BYTES + 1),
        );

        assert_eq!(error.kind(), UpstreamErrorKind::Request);
        assert_eq!(
            error.to_string(),
            "x".repeat(MAX_UPSTREAM_ERROR_MESSAGE_BYTES)
        );
    }

    #[test]
    fn upstream_error_replaces_empty_messages_by_kind() {
        let cases = [
            (UpstreamErrorKind::Connect, "upstream connection failed"),
            (UpstreamErrorKind::Request, "upstream request failed"),
            (UpstreamErrorKind::Timeout, "upstream request timed out"),
        ];

        for (kind, expected) in cases {
            let error = UpstreamError::new(kind, "");

            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), expected);
        }
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
        MAX_UPSTREAM_ERROR_MESSAGE_BYTES, UpstreamBodyError, UpstreamBodyErrorKind,
        UpstreamDeadline, UpstreamRequest,
    };
    use crate::allowlist::{AcceptedTarget, allow_target};
    use crate::body::AccountedBody;
    use crate::config::{GatewayConfig, RequestBodyBytes, RequestHeaderBytes, UpstreamOrigin};
    use crate::headers::forward_request_headers;
    use crate::target::testing::origin_form_query_valid;
    use ::http::{HeaderMap, Method};
    use axum::body::Body;
    use core::num::NonZeroUsize;
    use proptest::prelude::*;
    use std::path::PathBuf;
    use tokio::runtime::Runtime;

    fn request_body_limit(value: usize) -> RequestBodyBytes {
        RequestBodyBytes::for_test(NonZeroUsize::new(value).expect("limit should be non-zero"))
    }

    fn request_header_limit(value: usize) -> RequestHeaderBytes {
        RequestHeaderBytes::for_test(NonZeroUsize::new(value).expect("limit should be non-zero"))
    }

    #[test]
    fn upstream_body_errors_bound_every_message_shape() {
        let short_message = "body failed".to_owned();
        let long_ascii_message = "x".repeat(MAX_UPSTREAM_ERROR_MESSAGE_BYTES + 1);
        let long_unicode_message = "\u{20ac}".repeat(MAX_UPSTREAM_ERROR_MESSAGE_BYTES);
        let cases = [
            (UpstreamBodyErrorKind::Stream, ""),
            (UpstreamBodyErrorKind::Stream, short_message.as_str()),
            (UpstreamBodyErrorKind::Stream, long_ascii_message.as_str()),
            (UpstreamBodyErrorKind::Stream, long_unicode_message.as_str()),
            (UpstreamBodyErrorKind::Timeout, ""),
            (UpstreamBodyErrorKind::Timeout, short_message.as_str()),
            (UpstreamBodyErrorKind::Timeout, long_ascii_message.as_str()),
            (
                UpstreamBodyErrorKind::Timeout,
                long_unicode_message.as_str(),
            ),
        ];

        for (kind, message) in cases {
            let error = match kind {
                UpstreamBodyErrorKind::Stream => UpstreamBodyError::stream(message),
                UpstreamBodyErrorKind::Timeout => UpstreamBodyError::timeout(message),
            };
            let rendered = error.to_string();

            assert_eq!(error.kind(), kind);
            assert!(!rendered.is_empty());
            assert!(rendered.len() <= MAX_UPSTREAM_ERROR_MESSAGE_BYTES);
        }
    }

    proptest! {
        #[test]
        fn from_target_preserves_accepted_target(
            query in prop::option::of(origin_form_query_valid()),
        ) {
            let runtime = Runtime::new()
                .expect("runtime should build");
            let body = runtime.block_on(AccountedBody::read_request(
                Body::from("payload"),
                request_body_limit(16),
            ))
                .expect("request body should be accounted");
            let origin = UpstreamOrigin::parse("https://api.openai.com")
                .expect("origin should parse");
            let config = GatewayConfig::for_runtime_test(
                PathBuf::from("/unused/audit.ndjson"),
                origin.as_str(),
            );
            let target = AcceptedTarget::new("/v1/models", query.as_deref())
                .expect("target should parse");
            let allowed = allow_target(&config, &Method::GET, target.clone())
                .expect("target should be allowed");
            let headers = forward_request_headers(
                &HeaderMap::new(),
                request_header_limit(1024),
            )
                .expect("headers should be forwarded");

            let request = UpstreamRequest::from_target(
                &origin,
                &allowed,
                headers,
                &body,
                UpstreamDeadline::from_timeout(config.request_timeout()),
            );
            let expected_url =
                origin.join_path_query(target.origin_form_path(), target.origin_form_query());

            prop_assert_eq!(request.method(), &Method::GET);
            prop_assert_eq!(request.url(), &expected_url);
            prop_assert_eq!(request.url().path(), expected_url.path());
            prop_assert_eq!(request.url().query(), expected_url.query());
            prop_assert_eq!(request.body(), b"payload");
            prop_assert_eq!(
                request.deadline().timeout(),
                config.request_timeout().as_duration()
            );
        }
    }
}
