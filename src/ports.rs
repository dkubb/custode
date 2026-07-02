//! Runtime port traits and values.

use crate::allowlist::AllowedTarget;
use crate::audit::{AuditError, AuditEvent, AuditTimestamp, RequestId};
use crate::body::AccountedBody;
use crate::config::UpstreamOrigin;
use crate::headers::ForwardedRequestHeaders;
use axum::body::Bytes;
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use futures_util::stream::BoxStream;
use http::{HeaderMap, Method, StatusCode};
use thiserror::Error;
use url::Url;

/// Boxed future returned by runtime ports.
pub(crate) type BoxFuture<'future, T> = Pin<Box<dyn Future<Output = T> + Send + 'future>>;

/// Streaming upstream response body.
pub(crate) type UpstreamBody = BoxStream<'static, Result<Bytes, UpstreamBodyError>>;

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
    fn next_request_id(&self) -> RequestId;
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
    message: String,
}

/// Upstream response body streaming failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub(crate) struct UpstreamBodyError {
    /// Source error message.
    message: String,
}

impl UpstreamBodyError {
    /// Creates an upstream body error.
    #[must_use]
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
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
            message: message.into(),
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

    /// Creates an upstream request from proof-carrying forwarding inputs.
    #[must_use]
    pub(crate) fn from_target(
        origin: &UpstreamOrigin,
        target: &AllowedTarget,
        headers: ForwardedRequestHeaders,
        body: &AccountedBody,
    ) -> Self {
        Self {
            body: body.bytes().to_vec(),
            headers: headers.into_header_map(),
            method: target.method().clone(),
            url: origin.join_path_query(target.target().path(), target.target().query()),
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
    pub(crate) fn into_parts(self) -> (Method, Url, HeaderMap, Vec<u8>) {
        (self.method, self.url, self.headers, self.body)
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[expect(
    clippy::inline_modules,
    reason = "inline tests keep file-local coverage ownership explicit"
)]
mod tests {
    use super::UpstreamResponse;
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
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[expect(
    clippy::inline_modules,
    reason = "inline proptests keep file-local coverage ownership explicit"
)]
mod proptests {
    use super::UpstreamRequest;
    use crate::allowlist::{AcceptedTarget, allow_target};
    use crate::body::AccountedBody;
    use crate::config::{GatewayConfig, UpstreamOrigin};
    use crate::headers::forward_request_headers;
    use ::http::{HeaderMap, Method};
    use axum::body::Body;
    use core::num::NonZeroUsize;
    use proptest::prelude::*;
    use std::path::PathBuf;
    use tokio::runtime::Runtime;

    proptest! {
        #[test]
        fn from_target_preserves_accepted_target(query in prop::option::of("[a-z0-9=&]{0,16}")) {
            let runtime = Runtime::new()
                .expect("runtime should build");
            let body = runtime.block_on(AccountedBody::read_request(
                Body::from("payload"),
                NonZeroUsize::new(16).expect("limit should be non-zero"),
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
                NonZeroUsize::new(1024).expect("limit should be non-zero"),
            )
                .expect("headers should be forwarded");

            let request = UpstreamRequest::from_target(
                &origin,
                &allowed,
                headers,
                &body,
            );

            prop_assert_eq!(request.method(), &Method::GET);
            prop_assert_eq!(request.url().path(), target.path());
            prop_assert_eq!(request.url().query(), target.query());
            prop_assert_eq!(request.body(), b"payload");
        }
    }
}
