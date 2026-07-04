//! Production runtime adapters.

use crate::audit::{
    AuditError, AuditEvent, AuditTimestamp, AuditWriter, RUN_TOKEN_RANDOM_BYTES, RequestId,
    RunToken,
};
use crate::ports::{
    AuditSink, BoxFuture, Clock, RequestIdError, RequestIdSource, UpstreamBodyError,
    UpstreamClient, UpstreamError, UpstreamErrorKind, UpstreamRequest, UpstreamResponse,
};
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};
use futures_util::StreamExt as _;
use reqwest::redirect::Policy;
use thiserror::Error;

/// Production audit timestamp source.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SystemClock;

/// Production monotonic request identity source.
#[derive(Debug)]
pub(crate) struct SequentialRequestIds {
    /// Last allocated request sequence, or zero before the first request.
    last_allocated: AtomicU64,
    /// Per-run random token embedded in request identities.
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

impl UpstreamClientBuildError {
    /// Creates a build error for tests.
    #[cfg(test)]
    pub(crate) const fn for_test(source: reqwest::Error) -> Self {
        Self { source }
    }
}

/// Error building the production request id source.
#[derive(Debug, Error)]
#[error("failed to read request id run-token entropy: {source}")]
pub(crate) struct RequestIdSourceBuildError {
    /// Entropy read source.
    source: getrandom::Error,
}

impl RequestIdSourceBuildError {
    /// Creates a build error for tests.
    #[cfg(test)]
    pub(crate) const fn for_test(source: getrandom::Error) -> Self {
        Self { source }
    }
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
    pub(crate) fn new() -> Result<Self, UpstreamClientBuildError> {
        let result = reqwest::Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .build();
        Self::from_build_result(result)
    }
}

impl RequestIdSource for SequentialRequestIds {
    fn next_request_id(&self) -> Result<RequestId, RequestIdError> {
        let previous = self
            .last_allocated
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_current| RequestIdError::SequenceExhausted)?;
        let sequence = NonZeroU64::new(
            previous
                .checked_add(1)
                .expect("checked transition should allocate a request sequence"),
        )
        .expect("allocated request sequence should be non-zero");

        Ok(RequestId::from_parts(&self.run_token, sequence))
    }
}

impl SequentialRequestIds {
    /// Creates a sequence source from an entropy read result.
    fn from_entropy_result(
        result: Result<[u8; RUN_TOKEN_RANDOM_BYTES], getrandom::Error>,
    ) -> Result<Self, RequestIdSourceBuildError> {
        let entropy = result.map_err(request_id_source_build_error)?;
        Ok(Self::new(run_token_from_entropy(entropy)))
    }

    /// Creates a sequence source that starts at request 1 with a run token.
    #[must_use]
    pub(crate) const fn new(run_token: RunToken) -> Self {
        Self {
            last_allocated: AtomicU64::new(0),
            run_token,
        }
    }

    /// Creates a production request identity source.
    pub(crate) fn production() -> Result<Self, RequestIdSourceBuildError> {
        Self::from_entropy_result(read_run_token_entropy())
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

/// Builds a run token from 128 bits of entropy.
const fn run_token_from_entropy(entropy: [u8; RUN_TOKEN_RANDOM_BYTES]) -> RunToken {
    RunToken::from_entropy(entropy)
}

/// Reads run-token entropy from the operating system.
fn read_run_token_entropy() -> Result<[u8; RUN_TOKEN_RANDOM_BYTES], getrandom::Error> {
    let mut entropy = [0; RUN_TOKEN_RANDOM_BYTES];
    getrandom::fill(&mut entropy)?;
    Ok(entropy)
}

/// Creates a request id source build error from an entropy read error.
const fn request_id_source_build_error(source: getrandom::Error) -> RequestIdSourceBuildError {
    RequestIdSourceBuildError { source }
}

/// Creates an upstream body error from reqwest.
fn upstream_body_error_from_reqwest(error: &reqwest::Error) -> UpstreamBodyError {
    if error.is_timeout() {
        UpstreamBodyError::timeout(error.to_string())
    } else {
        UpstreamBodyError::stream(error.to_string())
    }
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
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[expect(
        clippy::inline_modules,
        reason = "inline proptests keep file-local coverage ownership explicit"
    )]
    mod proptests {
        use super::super::{RUN_TOKEN_RANDOM_BYTES, run_token_from_entropy};
        use core::str;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn run_token_from_entropy_round_trips_bytes(
                entropy in any::<[u8; RUN_TOKEN_RANDOM_BYTES]>()
            ) {
                let token = run_token_from_entropy(entropy);
                let token_text = token.to_string();
                let (first, second) = token_text
                    .split_once('-')
                    .expect("run token should contain the separator");
                let chunks = first
                    .as_bytes()
                    .chunks_exact(2)
                    .chain(second.as_bytes().chunks_exact(2));

                prop_assert_eq!(first.len(), 16);
                prop_assert_eq!(second.len(), 16);
                for (actual, expected) in chunks.zip(entropy) {
                    let text = str::from_utf8(actual)
                        .expect("hex chunk should be valid UTF-8");
                    let byte = u8::from_str_radix(text, 16)
                        .expect("hex chunk should parse as a byte");

                    prop_assert_eq!(byte, expected);
                }
            }
        }
    }

    use super::{
        RUN_TOKEN_RANDOM_BYTES, ReqwestErrorView, ReqwestUpstreamClient, SequentialRequestIds,
        SystemClock, run_token_from_entropy, upstream_error_kind_from_reqwest,
    };
    use crate::allowlist::{AcceptedTarget, allow_target};
    use crate::audit::{RequestId, RunToken};
    use crate::body::AccountedBody;
    use crate::config::{GatewayConfig, RequestBodyBytes, RequestHeaderBytes, RequestTimeout};
    use crate::headers::forward_request_headers;
    use crate::ports::{
        Clock as _, RequestIdError, RequestIdSource as _, UpstreamBodyErrorKind,
        UpstreamClient as _, UpstreamDeadline, UpstreamErrorKind, UpstreamRequest,
    };
    use ::http::{HeaderMap, Method};
    use axum::body::Body;
    use core::error::Error as _;
    use core::num::{NonZeroU64, NonZeroUsize};
    use core::sync::atomic::AtomicU64;
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

    fn request_body_limit(value: usize) -> RequestBodyBytes {
        RequestBodyBytes::for_test(NonZeroUsize::new(value).expect("limit should be non-zero"))
    }

    fn request_header_limit(value: usize) -> RequestHeaderBytes {
        RequestHeaderBytes::for_test(NonZeroUsize::new(value).expect("limit should be non-zero"))
    }

    async fn empty_upstream_request(origin_text: &str, timeout: RequestTimeout) -> UpstreamRequest {
        let config =
            GatewayConfig::for_runtime_test(PathBuf::from("/unused/audit.ndjson"), origin_text);
        let accepted_target = AcceptedTarget::new("/v1/models", None).expect("target should parse");
        let allowed_target =
            allow_target(&config, &Method::GET, accepted_target).expect("target should be allowed");
        let headers = forward_request_headers(&HeaderMap::new(), request_header_limit(1024))
            .expect("headers should be forwarded");
        let request_body = AccountedBody::read_request(Body::empty(), request_body_limit(1))
            .await
            .expect("request body should be accounted");
        UpstreamRequest::from_target(
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
    fn request_id_source_build_error_display_includes_context() {
        let error = SequentialRequestIds::from_entropy_result(Err(getrandom::Error::UNSUPPORTED))
            .expect_err("entropy read failures should be mapped");

        assert_eq!(
            error.to_string(),
            "failed to read request id run-token entropy: getrandom: this target is not supported"
        );
        assert!(
            error.source().is_some(),
            "display error should expose the getrandom source"
        );
    }

    #[test]
    fn request_id_source_accepts_entropy_result() {
        let entropy = [0x42; RUN_TOKEN_RANDOM_BYTES];
        let request_ids = SequentialRequestIds::from_entropy_result(Ok(entropy))
            .expect("entropy should build request ids");

        let id = request_ids
            .next_request_id()
            .expect("request id should allocate");

        assert_eq!(
            id,
            RequestId::from_parts(
                &run_token_from_entropy(entropy),
                NonZeroU64::new(1).expect("literal should be non-zero"),
            ),
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

    #[test]
    fn run_token_from_entropy_formats_lower_hex_halves() {
        let token = run_token_from_entropy([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]);

        assert_eq!(token.to_string(), "0001020304050607-08090a0b0c0d0e0f");
    }

    #[test]
    fn distinct_run_token_entropy_produces_distinct_request_ids() {
        let first = run_token_from_entropy([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);
        let second = run_token_from_entropy([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        let sequence = NonZeroU64::new(1).expect("literal should be non-zero");

        assert_ne!(
            RequestId::from_parts(&first, sequence),
            RequestId::from_parts(&second, sequence)
        );
    }

    #[test]
    fn production_request_id_sources_start_with_distinct_ids() {
        let first_source =
            SequentialRequestIds::production().expect("first production source should build");
        let second_source =
            SequentialRequestIds::production().expect("second production source should build");

        let first = first_source
            .next_request_id()
            .expect("first production id should allocate");
        let second = second_source
            .next_request_id()
            .expect("second production id should allocate");

        assert_ne!(first, second);
    }

    #[test]
    fn sequential_request_ids_report_exhaustion_without_wrapping() {
        let run_token = RunToken::for_test("000000000000000a-000000000000000b");
        let request_ids = SequentialRequestIds {
            last_allocated: AtomicU64::new(u64::MAX - 1),
            run_token,
        };

        let final_id = request_ids
            .next_request_id()
            .expect("final request id should allocate");
        let exhausted = request_ids
            .next_request_id()
            .expect_err("sequence should be exhausted");

        assert_eq!(
            final_id,
            RequestId::from_parts(
                &run_token,
                NonZeroU64::new(u64::MAX).expect("max sequence should be non-zero"),
            ),
        );
        assert_eq!(exhausted, RequestIdError::SequenceExhausted);
    }

    #[tokio::test]
    async fn reqwest_upstream_client_classifies_connect_failures() {
        let origin = released_origin().await;
        let client = ReqwestUpstreamClient::new().expect("upstream client should build");
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
        let client = ReqwestUpstreamClient::new().expect("upstream client should build");
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
        let client = ReqwestUpstreamClient::new().expect("upstream client should build");
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
        let client = ReqwestUpstreamClient::new().expect("upstream client should build");
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
        let error = chunk.expect_err("invalid chunk should map to a body error");

        assert_eq!(error.kind(), UpstreamBodyErrorKind::Stream);
    }

    #[tokio::test]
    async fn reqwest_upstream_client_classifies_body_stream_timeouts() {
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
                .expect("stalling upstream should accept");
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
                .await
                .expect("stalling upstream should write headers");
            sleep(Duration::from_secs(10)).await;
        }));
        let client = ReqwestUpstreamClient::new().expect("upstream client should build");
        let request = empty_upstream_request(
            &format!("http://{address}"),
            RequestTimeout::from_duration(Duration::from_millis(50)),
        )
        .await;

        let response = client
            .send(request)
            .await
            .expect("stalling body response should still return headers");
        let chunk = response
            .into_body()
            .next()
            .await
            .expect("stalling body should produce a body item");
        let error = chunk.expect_err("stalling body should time out");

        assert_eq!(error.kind(), UpstreamBodyErrorKind::Timeout);
    }
}
