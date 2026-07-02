//! Production runtime adapters.

use crate::ports::{
    BoxFuture, UpstreamBodyError, UpstreamClient, UpstreamError, UpstreamErrorKind,
    UpstreamRequest, UpstreamResponse,
};
use core::time::Duration;
use futures_util::StreamExt as _;
use thiserror::Error;

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

impl ReqwestUpstreamClient {
    /// Builds a reqwest-backed upstream client.
    ///
    /// # Errors
    ///
    /// Returns an error when reqwest client construction fails.
    pub(crate) fn new(timeout: Duration) -> Result<Self, UpstreamClientBuildError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(upstream_client_build_error)?;
        Ok(Self { client })
    }
}

impl UpstreamClient for ReqwestUpstreamClient {
    fn send(
        &self,
        request: UpstreamRequest,
    ) -> BoxFuture<'_, Result<UpstreamResponse, UpstreamError>> {
        Box::pin(async move {
            let (source_method, url, request_headers, request_body) = request.into_parts();
            let upstream_method = reqwest::Method::from_bytes(source_method.as_str().as_bytes())
                .expect("http and reqwest method parsing should agree");
            let response = self
                .client
                .request(upstream_method, url)
                .headers(request_headers)
                .body(request_body)
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
mod tests {
    use super::{
        ReqwestErrorView, ReqwestUpstreamClient, upstream_client_build_error,
        upstream_error_kind_from_reqwest,
    };
    use crate::allowlist::AcceptedTarget;
    use crate::body::AccountedBody;
    use crate::config::UpstreamOrigin;
    use crate::ports::{UpstreamClient as _, UpstreamErrorKind, UpstreamRequest};
    use ::http::{HeaderMap, Method};
    use axum::body::Body;
    use core::error::Error as _;
    use core::num::NonZeroUsize;
    use core::time::Duration;
    use futures_util::StreamExt as _;
    use pretty_assertions::assert_eq;
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

    async fn empty_upstream_request(origin_text: &str) -> UpstreamRequest {
        let origin = UpstreamOrigin::parse(origin_text).expect("test origin should parse");
        let target = AcceptedTarget::new("/v1/models", None).expect("target should parse");
        let request_body = AccountedBody::read_request(
            Body::empty(),
            NonZeroUsize::new(1).expect("limit should be non-zero"),
        )
        .await
        .expect("request body should be accounted");
        UpstreamRequest::from_target(
            Method::GET,
            &origin,
            &target,
            HeaderMap::new(),
            &request_body,
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
        let error = upstream_client_build_error(source);

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

    #[tokio::test]
    async fn reqwest_upstream_client_classifies_connect_failures() {
        let origin = released_origin().await;
        let client = ReqwestUpstreamClient::new(Duration::from_secs(1))
            .expect("upstream client should build");
        let request = empty_upstream_request(&origin).await;

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
        let client = ReqwestUpstreamClient::new(Duration::from_secs(1))
            .expect("upstream client should build");
        let request = empty_upstream_request(&format!("http://{address}")).await;

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
        let client = ReqwestUpstreamClient::new(Duration::from_millis(50))
            .expect("upstream client should build");
        let request = empty_upstream_request(&format!("http://{address}")).await;

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
        let client = ReqwestUpstreamClient::new(Duration::from_secs(1))
            .expect("upstream client should build");
        let request = empty_upstream_request(&format!("http://{address}")).await;

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
