//! Production runtime adapters.

use crate::audit::{AuditError, AuditEvent, AuditTimestamp, AuditWriter, RequestId, RunToken};
use crate::ports::{
    AuditSink, BoxFuture, Clock, RequestIdSource, UpstreamBodyError, UpstreamClient, UpstreamError,
    UpstreamErrorKind, UpstreamRequest, UpstreamResponse,
};
use core::sync::atomic::{AtomicU64, Ordering};
use futures_util::StreamExt as _;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Production audit timestamp source.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SystemClock;

/// Production monotonic request identity source.
#[derive(Debug)]
pub(crate) struct SequentialRequestIds {
    /// Next request sequence.
    next: AtomicU64,
    /// Per-process run token embedded in request identities.
    run_token: RunToken,
}

/// Production reqwest-backed upstream client.
#[derive(Clone, Debug)]
pub(crate) struct ReqwestUpstreamClient {
    /// Inner reqwest client.
    client: reqwest::Client,
}

/// Error building the production upstream client.
#[derive(Debug, Error)]
#[error("failed to build upstream client: {source}")]
pub(crate) struct UpstreamClientBuildError {
    /// Reqwest build source.
    source: reqwest::Error,
}

/// Minimal view of reqwest error classification.
trait ReqwestErrorView {
    /// Returns true when reqwest classified the failure as a connection error.
    fn is_connect(&self) -> bool;

    /// Returns true when reqwest classified the failure as a timeout.
    fn is_timeout(&self) -> bool;
}

impl AuditSink for AuditWriter {
    fn append_event<'future>(
        &'future self,
        event: &'future AuditEvent,
    ) -> BoxFuture<'future, Result<(), AuditError>> {
        Box::pin(Self::write_event(self, event))
    }
}

impl Clock for SystemClock {
    fn now(&self) -> AuditTimestamp {
        AuditTimestamp::now()
    }
}

impl ReqwestUpstreamClient {
    /// Builds an upstream client from a reqwest client build result.
    fn from_build_result(
        result: Result<reqwest::Client, reqwest::Error>,
    ) -> Result<Self, UpstreamClientBuildError> {
        let client = result.map_err(upstream_client_build_error)?;
        Ok(Self { client })
    }

    /// Builds a reqwest-backed upstream client.
    #[must_use]
    pub(crate) fn new() -> Self {
        let result = reqwest::Client::builder().no_proxy().build();
        Self::from_build_result(result).expect("no-proxy rustls reqwest client should build")
    }
}

impl RequestIdSource for SequentialRequestIds {
    fn next_request_id(&self) -> RequestId {
        let sequence = self.next.fetch_add(1, Ordering::Relaxed);
        RequestId::from_parts(&self.run_token, sequence)
    }
}

impl SequentialRequestIds {
    /// Creates a sequence source that starts at request 1 with a run token.
    #[must_use]
    pub(crate) const fn new(run_token: RunToken) -> Self {
        Self {
            next: AtomicU64::new(1),
            run_token,
        }
    }

    /// Creates a production request identity source.
    #[must_use]
    pub(crate) fn production() -> Self {
        let run_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should not be before the Unix epoch")
            .as_nanos();
        // The process id disambiguates runs whose wall clocks collide, such
        // as restored snapshots or stepped clocks.
        let run_token = format!("{:x}-{run_nanos:x}", process::id());
        Self::new(RunToken::new(run_token).expect("production run token should be non-empty"))
    }
}

impl UpstreamClient for ReqwestUpstreamClient {
    fn send(
        &self,
        request: UpstreamRequest,
    ) -> BoxFuture<'_, Result<UpstreamResponse, UpstreamError>> {
        Box::pin(async move {
            let (source_method, url, request_headers, request_body, deadline) =
                request.into_parts();
            let upstream_method = reqwest::Method::from_bytes(source_method.as_str().as_bytes())
                .expect("http and reqwest method parsing should agree");
            let response = self
                .client
                .request(upstream_method, url)
                .headers(request_headers)
                .body(request_body)
                .timeout(deadline.timeout())
                .send()
                .await
                .map_err(|error| upstream_error_from_reqwest(&error))?;
            let status = response.status();
            let response_headers = response.headers().clone();
            let response_body = response
                .bytes_stream()
                .map(|result| result.map_err(|error| upstream_body_error_from_reqwest(&error)))
                .boxed();
            Ok(UpstreamResponse::new(
                status,
                response_headers,
                response_body,
            ))
        })
    }
}

impl ReqwestErrorView for reqwest::Error {
    fn is_connect(&self) -> bool {
        self.is_connect()
    }

    fn is_timeout(&self) -> bool {
        self.is_timeout()
    }
}

/// Creates an upstream body error from reqwest.
fn upstream_body_error_from_reqwest(error: &reqwest::Error) -> UpstreamBodyError {
    UpstreamBodyError::new(error.to_string())
}

/// Creates an upstream client build error from reqwest.
const fn upstream_client_build_error(source: reqwest::Error) -> UpstreamClientBuildError {
    UpstreamClientBuildError { source }
}

/// Creates an upstream request error from reqwest.
fn upstream_error_from_reqwest(error: &reqwest::Error) -> UpstreamError {
    UpstreamError::new(upstream_error_kind_from_reqwest(error), error.to_string())
}

/// Classifies an upstream request error from reqwest's stable predicates.
fn upstream_error_kind_from_reqwest(error: &impl ReqwestErrorView) -> UpstreamErrorKind {
    if error.is_timeout() {
        UpstreamErrorKind::Timeout
    } else if error.is_connect() {
        UpstreamErrorKind::Connect
    } else {
        UpstreamErrorKind::Request
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
        ReqwestErrorView, ReqwestUpstreamClient, SystemClock, upstream_error_kind_from_reqwest,
    };
    use crate::allowlist::{AcceptedTarget, allow_target};
    use crate::body::AccountedBody;
    use crate::config::{GatewayConfig, RequestTimeout, UpstreamOrigin};
    use crate::headers::forward_request_headers;
    use crate::ports::{
        Clock as _, UpstreamClient as _, UpstreamDeadline, UpstreamErrorKind, UpstreamRequest,
    };
    use ::http::{HeaderMap, Method};
    use axum::body::Body;
    use core::error::Error as _;
    use core::num::NonZeroUsize;
    use core::time::Duration;
    use futures_util::StreamExt as _;
    use pretty_assertions::assert_eq;
    use std::path::PathBuf;
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::TcpListener;
    use tokio::time::sleep;

    #[derive(Clone, Copy, Debug)]
    struct ErrorView {
        connect: bool,
        timeout: bool,
    }

    impl ReqwestErrorView for ErrorView {
        fn is_connect(&self) -> bool {
            self.connect
        }

        fn is_timeout(&self) -> bool {
            self.timeout
        }
    }

    async fn empty_upstream_request(origin_text: &str, timeout: RequestTimeout) -> UpstreamRequest {
        let origin = UpstreamOrigin::parse(origin_text).expect("test origin should parse");
        let config =
            GatewayConfig::for_runtime_test(PathBuf::from("/unused/audit.ndjson"), origin_text);
        let accepted_target = AcceptedTarget::new("/v1/models", None).expect("target should parse");
        let allowed_target =
            allow_target(&config, &Method::GET, accepted_target).expect("target should be allowed");
        let headers = forward_request_headers(
            &HeaderMap::new(),
            NonZeroUsize::new(1024).expect("limit should be non-zero"),
        )
        .expect("headers should be forwarded");
        let request_body = AccountedBody::read_request(
            Body::empty(),
            NonZeroUsize::new(1).expect("limit should be non-zero"),
        )
        .await
        .expect("request body should be accounted");
        UpstreamRequest::from_target(
            &origin,
            &allowed_target,
            headers,
            &request_body,
            UpstreamDeadline::from_timeout(timeout),
        )
    }

    async fn released_origin() -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind an ephemeral port");
        let address = listener
            .local_addr()
            .expect("listener should expose its address");
        drop(listener);
        format!("http://{address}")
    }

    #[test]
    fn build_error_display_includes_context() {
        let source =
            reqwest::Proxy::all("not a proxy URL").expect_err("invalid proxy URL should fail");
        let error = ReqwestUpstreamClient::from_build_result(Err(source))
            .expect_err("builder errors should be mapped");

        assert!(
            error
                .to_string()
                .starts_with("failed to build upstream client:"),
            "display should include adapter context"
        );
        assert!(
            error.source().is_some(),
            "display error should expose the reqwest source"
        );
    }

    #[test]
    fn reqwest_error_classification_prefers_timeouts() {
        let error = ErrorView {
            connect: true,
            timeout: true,
        };

        let kind = upstream_error_kind_from_reqwest(&error);

        assert_eq!(kind, UpstreamErrorKind::Timeout);
    }

    #[test]
    fn reqwest_error_classification_detects_connect_failures() {
        let error = ErrorView {
            connect: true,
            timeout: false,
        };

        let kind = upstream_error_kind_from_reqwest(&error);

        assert_eq!(kind, UpstreamErrorKind::Connect);
    }

    #[test]
    fn reqwest_error_classification_falls_back_to_request_failures() {
        let error = ErrorView {
            connect: false,
            timeout: false,
        };

        let kind = upstream_error_kind_from_reqwest(&error);

        assert_eq!(kind, UpstreamErrorKind::Request);
    }

    #[test]
    fn system_clock_returns_parseable_timestamps() {
        let timestamp = SystemClock.now();

        humantime::parse_rfc3339(timestamp.as_str())
            .expect("system clock timestamp should parse as RFC 3339");
    }

    #[tokio::test]
    async fn reqwest_upstream_client_classifies_connect_failures() {
        let origin = released_origin().await;
        let client = ReqwestUpstreamClient::new();
        let request = empty_upstream_request(
            &origin,
            RequestTimeout::from_duration(Duration::from_secs(1)),
        )
        .await;

        let error = client
            .send(request)
            .await
            .expect_err("released port should refuse the connection");

        assert_eq!(error.kind(), UpstreamErrorKind::Connect);
    }

    #[tokio::test]
    async fn reqwest_upstream_client_classifies_protocol_failures() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind an ephemeral port");
        let address = listener
            .local_addr()
            .expect("listener should expose its address");
        drop(tokio::spawn(async move {
            let (mut socket, _peer) = listener
                .accept()
                .await
                .expect("garbage upstream should accept");
            socket
                .write_all(b"garbage\r\n\r\n")
                .await
                .expect("garbage upstream should write");
        }));
        let client = ReqwestUpstreamClient::new();
        let request = empty_upstream_request(
            &format!("http://{address}"),
            RequestTimeout::from_duration(Duration::from_secs(1)),
        )
        .await;

        let error = client
            .send(request)
            .await
            .expect_err("garbage response should fail");

        assert_eq!(error.kind(), UpstreamErrorKind::Request);
    }

    #[tokio::test]
    async fn reqwest_upstream_client_classifies_timeouts() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind an ephemeral port");
        let address = listener
            .local_addr()
            .expect("listener should expose its address");
        drop(tokio::spawn(async move {
            let (_socket, _peer) = listener
                .accept()
                .await
                .expect("silent upstream should accept");
            sleep(Duration::from_secs(10)).await;
        }));
        let client = ReqwestUpstreamClient::new();
        let request = empty_upstream_request(
            &format!("http://{address}"),
            RequestTimeout::from_duration(Duration::from_millis(50)),
        )
        .await;

        let error = client
            .send(request)
            .await
            .expect_err("silent upstream should time out");

        assert_eq!(error.kind(), UpstreamErrorKind::Timeout);
    }

    #[tokio::test]
    async fn reqwest_upstream_client_maps_body_stream_errors() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind an ephemeral port");
        let address = listener
            .local_addr()
            .expect("listener should expose its address");
        drop(tokio::spawn(async move {
            let (mut socket, _peer) = listener
                .accept()
                .await
                .expect("chunked upstream should accept");
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n")
                .await
                .expect("chunked upstream should write");
        }));
        let client = ReqwestUpstreamClient::new();
        let request = empty_upstream_request(
            &format!("http://{address}"),
            RequestTimeout::from_duration(Duration::from_secs(1)),
        )
        .await;

        let response = client
            .send(request)
            .await
            .expect("invalid chunk response should still return headers");
        let chunk = response
            .into_body()
            .next()
            .await
            .expect("invalid chunk should produce a body item");

        assert!(chunk.is_err(), "invalid chunk should map to a body error");
    }
}
