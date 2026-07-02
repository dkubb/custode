//! Axum and Reqwest runtime edges.

use crate::allowlist::{AcceptedTarget, RejectionReason, is_allowed, rejection_for};
use crate::audit::{AuditDecision, AuditTarget, RequestId};
use crate::body::{AccountedBody, RequestBodyError, ResponseAccount};
use crate::config::GatewayConfig;
use crate::gateway::{Gateway, GatewayError, ResponseAuditInput};
use crate::headers::{HeaderError, forward_request_headers, forward_response_headers};
use ::http::{HeaderMap, Method, Uri};
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::response::IntoResponse as _;
use axum::{Router, routing::any};
use core::convert::Infallible;
use core::future::IntoFuture;
use futures_util::StreamExt as _;
use futures_util::future::{self, Either};
use reqwest::Client;
use std::io;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Serving runtime error.
#[derive(Debug, Error)]
pub(crate) enum ServeError {
    /// Upstream client could not be built.
    #[error("failed to build upstream client: {0}")]
    Client(reqwest::Error),

    /// Gateway request handling failed fatally.
    #[error("{0}")]
    Gateway(#[from] GatewayError),

    /// Gateway server failed.
    #[error("gateway server failed: {0}")]
    Server(io::Error),

    /// Gateway listener could not bind.
    #[error("failed to bind gateway listener: {0}")]
    ServerBind(io::Error),
}

/// Shared Axum application state.
#[derive(Clone, Debug)]
struct AppState {
    /// Upstream HTTP client.
    client: Client,
    /// Request concurrency limiter.
    concurrency: Arc<Semaphore>,
    /// Fatal error channel for failures detected after responses start.
    fatal_errors: mpsc::UnboundedSender<GatewayError>,
    /// Gateway state.
    gateway: Gateway,
}

/// Response audit state carried until the terminal stream decision.
#[derive(Debug)]
struct ResponseAuditContext {
    /// Fatal error channel for failures detected after responses start.
    fatal_errors: mpsc::UnboundedSender<GatewayError>,
    /// Gateway state.
    gateway: Gateway,
    /// Request method.
    method: Method,
    /// Accounted request body.
    request_body: AccountedBody,
    /// Request identity.
    request_id: RequestId,
    /// Accounted response body.
    response_account: ResponseAccount,
    /// Upstream response status.
    status: u16,
    /// Accepted target.
    target: AcceptedTarget,
    /// Upstream request path.
    upstream_path: String,
    /// Upstream request query.
    upstream_query: Option<String>,
}

impl ResponseAuditContext {
    /// Writes the terminal response audit event.
    async fn audit(
        self,
        decision: AuditDecision,
        error_class: Option<String>,
    ) -> Result<(), GatewayError> {
        let input = ResponseAuditInput {
            decision,
            error_class,
            method: self.method.to_string(),
            request_body: self.request_body,
            request_id: self.request_id,
            response_account: self.response_account,
            status: Some(self.status),
            target: self.target,
            upstream_path: self.upstream_path,
            upstream_query: self.upstream_query,
        };
        self.gateway.audit_response(input).await
    }

    /// Writes the terminal response audit event or reports a fatal error.
    async fn audit_after_response_started(
        self,
        decision: AuditDecision,
        error_class: Option<String>,
    ) -> Result<(), String> {
        let fatal_errors = self.fatal_errors.clone();
        match self.audit(decision, error_class).await {
            Ok(()) => Ok(()),
            Err(error) => {
                let message = error.to_string();
                report_fatal_error(&fatal_errors, error);
                Err(message)
            }
        }
    }
}

/// Accepts an origin-form target that is present in the allowlist.
async fn accept_allowed_target(
    gateway: &Gateway,
    request_id: &RequestId,
    method: &Method,
    uri: &Uri,
) -> Result<Result<AcceptedTarget, Response<Body>>, GatewayError> {
    if method == Method::CONNECT {
        let target = synthetic_target(uri);
        gateway
            .audit_denial(
                request_id.clone(),
                method,
                target,
                None,
                RejectionReason::ConnectUnsupported.error_class(),
                StatusCode::METHOD_NOT_ALLOWED.as_u16(),
            )
            .await?;
        return Ok(Err(status_response(StatusCode::METHOD_NOT_ALLOWED)));
    }

    if uri.scheme().is_some() || uri.authority().is_some() {
        let target = synthetic_target(uri);
        gateway
            .audit_denial(
                request_id.clone(),
                method,
                target,
                None,
                RejectionReason::AbsoluteFormUnsupported.error_class(),
                StatusCode::BAD_REQUEST.as_u16(),
            )
            .await?;
        return Ok(Err(status_response(StatusCode::BAD_REQUEST)));
    }

    let target = match AcceptedTarget::new(uri.path(), uri.query()) {
        Ok(target) => target,
        Err(reason) => {
            let target = synthetic_target(uri);
            gateway
                .audit_denial(
                    request_id.clone(),
                    method,
                    target,
                    None,
                    reason.error_class(),
                    StatusCode::BAD_REQUEST.as_u16(),
                )
                .await?;
            return Ok(Err(status_response(StatusCode::BAD_REQUEST)));
        }
    };

    if !is_allowed(gateway.config(), method, &target) {
        let reason = rejection_for(gateway.config(), method);
        gateway
            .audit_denial(
                request_id.clone(),
                method,
                target.into(),
                None,
                reason.error_class(),
                StatusCode::FORBIDDEN.as_u16(),
            )
            .await?;
        return Ok(Err(status_response(StatusCode::FORBIDDEN)));
    }

    Ok(Ok(target))
}

/// Handles one proxied request.
async fn proxy(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    let _permit = match Arc::clone(&state.concurrency).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_error) => {
            let request_id = state.gateway.next_request_id();
            let method = request.method().clone();
            let target = synthetic_target(request.uri());
            if state
                .gateway
                .audit_denial(
                    request_id,
                    &method,
                    target,
                    None,
                    "too_many_requests",
                    StatusCode::TOO_MANY_REQUESTS.as_u16(),
                )
                .await
                .is_err()
            {
                return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
            return Ok(StatusCode::TOO_MANY_REQUESTS.into_response());
        }
    };

    Ok(
        match handle_request(state.fatal_errors, state.gateway, state.client, request).await {
            Ok(response) => response,
            Err(error) => {
                tracing::error!(%error, "request failed");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        },
    )
}

/// Handles an accepted HTTP request after the concurrency permit is acquired.
async fn handle_request(
    fatal_errors: mpsc::UnboundedSender<GatewayError>,
    gateway: Gateway,
    client: Client,
    request: Request<Body>,
) -> Result<Response<Body>, GatewayError> {
    let request_id = gateway.next_request_id();
    let (parts, body) = request.into_parts();
    let method = parts.method;
    let uri = parts.uri;
    let headers = parts.headers;

    let target = match accept_allowed_target(&gateway, &request_id, &method, &uri).await? {
        Ok(target) => target,
        Err(response) => return Ok(response),
    };

    let request_headers =
        match forward_request_headers(&headers, gateway.config().max_request_header_bytes()) {
            Ok(request_headers) => request_headers,
            Err(error) => {
                let status = request_header_error_status(error);
                gateway
                    .audit_denial(
                        request_id,
                        &method,
                        target.into(),
                        None,
                        request_header_error_class(error),
                        status.as_u16(),
                    )
                    .await?;
                return Ok(status_response(status));
            }
        };

    let request_body =
        match AccountedBody::read_request(body, gateway.config().max_request_bytes()).await {
            Ok(request_body) => request_body,
            Err(error) => {
                let status = request_body_error_status(&error);
                gateway
                    .audit_denial(
                        request_id,
                        &method,
                        target.into(),
                        None,
                        error.error_class(),
                        status.as_u16(),
                    )
                    .await?;
                return Ok(status_response(status));
            }
        };

    forward_request(
        fatal_errors,
        gateway,
        client,
        request_id,
        method,
        target,
        request_headers,
        request_body,
    )
    .await
}

/// Forwards an accepted request to the configured upstream.
#[expect(
    clippy::too_many_arguments,
    reason = "the forwarding step threads every accepted request component"
)]
async fn forward_request(
    fatal_errors: mpsc::UnboundedSender<GatewayError>,
    gateway: Gateway,
    client: Client,
    request_id: RequestId,
    method: Method,
    target: AcceptedTarget,
    request_headers: HeaderMap,
    request_body: AccountedBody,
) -> Result<Response<Body>, GatewayError> {
    let upstream = gateway
        .config()
        .upstream_origin()
        .join_path_query(target.path(), target.query());
    let upstream_path = target.path().to_owned();
    let upstream_query = target.query().map(str::to_owned);
    let reqwest_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .expect("http and reqwest method parsing should agree");
    let upstream_response = match client
        .request(reqwest_method, upstream)
        .headers(request_headers)
        .body(request_body.bytes().to_vec())
        .send()
        .await
    {
        Ok(upstream_response) => upstream_response,
        Err(error) => {
            let status = upstream_error_status(&error);
            let input = ResponseAuditInput {
                decision: AuditDecision::UpstreamError,
                error_class: Some(upstream_error_class(&error).to_owned()),
                method: method.to_string(),
                request_body,
                request_id,
                response_account: ResponseAccount::new(gateway.config().max_response_bytes()),
                status: Some(status.as_u16()),
                target,
                upstream_path,
                upstream_query,
            };
            gateway.audit_response(input).await?;
            return Ok(status_response(status));
        }
    };
    let status = upstream_response.status();
    let response_headers = match forward_response_headers(
        upstream_response.headers(),
        gateway.config().max_response_header_bytes(),
    ) {
        Ok(response_headers) => response_headers,
        Err(error) => {
            let input = ResponseAuditInput {
                decision: AuditDecision::ResponseError,
                error_class: Some(response_header_error_class(error).to_owned()),
                method: method.to_string(),
                request_body,
                request_id,
                response_account: ResponseAccount::new(gateway.config().max_response_bytes()),
                // The audited status is what the harness receives, not the
                // discarded upstream status.
                status: Some(StatusCode::BAD_GATEWAY.as_u16()),
                target,
                upstream_path,
                upstream_query,
            };
            gateway.audit_response(input).await?;
            return Ok(status_response(StatusCode::BAD_GATEWAY));
        }
    };
    let response_account = ResponseAccount::new(gateway.config().max_response_bytes());
    let context = ResponseAuditContext {
        fatal_errors,
        gateway,
        method,
        request_body,
        request_id,
        response_account,
        status: status.as_u16(),
        target,
        upstream_path,
        upstream_query,
    };
    let stream = response_stream(context, upstream_response);

    let mut response = Response::builder().status(status);
    for (name, value) in &response_headers {
        response = response.header(name, value);
    }
    response
        .body(Body::from_stream(stream))
        .map_err(GatewayError::ResponseBuild)
}

/// Streams the upstream response and writes exactly one terminal audit event.
fn response_stream(
    mut context: ResponseAuditContext,
    upstream_response: reqwest::Response,
) -> ReceiverStream<Result<Bytes, io::Error>> {
    let (sender, receiver) = mpsc::channel(8);

    tokio::spawn(async move {
        let mut stream = upstream_response.bytes_stream();
        while let Some(chunk_result) = stream.next().await {
            let chunk = match chunk_result {
                Ok(bytes) => bytes,
                Err(error) => {
                    let error_class = "upstream_response_stream_failed".to_owned();
                    send_stream_error(
                        &sender,
                        context
                            .audit_after_response_started(
                                AuditDecision::ResponseError,
                                Some(error_class),
                            )
                            .await,
                        error.to_string(),
                    )
                    .await;
                    return;
                }
            };

            if let Err(_error) = context.response_account.add_chunk(&chunk) {
                let error_class = "response_body_too_large".to_owned();
                send_stream_error(
                    &sender,
                    context
                        .audit_after_response_started(
                            AuditDecision::ResponseError,
                            Some(error_class.clone()),
                        )
                        .await,
                    error_class,
                )
                .await;
                return;
            }

            if sender.send(Ok(chunk)).await.is_err() {
                if let Err(error) = context
                    .audit_after_response_started(
                        AuditDecision::ResponseError,
                        Some("downstream_closed".to_owned()),
                    )
                    .await
                {
                    tracing::error!(%error, "failed to audit downstream close");
                }
                return;
            }
        }

        if let Err(error) = context
            .audit_after_response_started(AuditDecision::Allowed, None)
            .await
        {
            tracing::error!(%error, "failed to audit completed response");
        }
    });

    ReceiverStream::new(receiver)
}

/// Sends a stream error, preferring audit failure over upstream failure.
async fn send_stream_error(
    sender: &mpsc::Sender<Result<Bytes, io::Error>>,
    audit_result: Result<(), String>,
    stream_error: String,
) {
    let message = match audit_result {
        Ok(()) => stream_error,
        Err(error) => error,
    };
    let send_result = sender.send(Err(io::Error::other(message))).await;
    if send_result.is_err() {
        tracing::debug!("failed to send terminal stream error");
    }
}

/// Reports a fatal error to the serving task.
fn report_fatal_error(fatal_errors: &mpsc::UnboundedSender<GatewayError>, error: GatewayError) {
    if fatal_errors.send(error).is_err() {
        tracing::error!("fatal error channel closed");
    }
}

/// Starts the gateway HTTP server.
///
/// # Errors
///
/// Returns an error when the gateway cannot bind or serve.
pub(crate) async fn serve(config: GatewayConfig) -> Result<(), ServeError> {
    let bind = config.bind();
    let max_concurrent_requests = config.max_concurrent_requests().get();
    let client = Client::builder()
        .timeout(config.request_timeout())
        .build()
        .map_err(ServeError::Client)?;
    let gateway = Gateway::new(config).await.map_err(ServeError::Gateway)?;
    let (fatal_errors, fatal_receiver) = mpsc::unbounded_channel();
    let state = AppState {
        client,
        concurrency: Arc::new(Semaphore::new(max_concurrent_requests)),
        fatal_errors,
        gateway,
    };
    let app = Router::new().fallback(any(proxy)).with_state(state);
    let listener = TcpListener::bind(bind)
        .await
        .map_err(ServeError::ServerBind)?;

    run_until_server_stops(axum::serve(listener, app), fatal_receiver).await
}

/// Runs a server until it stops or a fatal stream task error arrives.
async fn run_until_server_stops(
    server_task: impl IntoFuture<Output = Result<(), io::Error>>,
    mut fatal_receiver: mpsc::UnboundedReceiver<GatewayError>,
) -> Result<(), ServeError> {
    let server =
        Box::pin(async move { server_task.into_future().await.map_err(ServeError::Server) });
    let fatal = Box::pin(async move {
        fatal_receiver
            .recv()
            .await
            .map_or_else(|| Ok(()), |error| Err(ServeError::Gateway(error)))
    });

    match future::select(server, fatal).await {
        Either::Left((result, _)) | Either::Right((result, _)) => result,
    }
}

/// Builds a synthetic target for audit events before target parsing succeeds.
fn synthetic_target(uri: &Uri) -> AuditTarget {
    AuditTarget::from_uri_parts(
        if uri.path().is_empty() {
            "/"
        } else {
            uri.path()
        },
        uri.query(),
    )
}

/// Builds an empty response with the supplied status.
fn status_response(status: StatusCode) -> Response<Body> {
    status.into_response()
}

/// Maps request body errors to response statuses.
const fn request_body_error_status(error: &RequestBodyError) -> StatusCode {
    if matches!(error, RequestBodyError::Read { .. }) {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::PAYLOAD_TOO_LARGE
    }
}

/// Maps request header errors to audit classes.
const fn request_header_error_class(error: HeaderError) -> &'static str {
    match error {
        HeaderError::InvalidConnectionHeader => "invalid_request_connection_header",
        HeaderError::TooLarge => "request_headers_too_large",
    }
}

/// Maps request header errors to response statuses.
const fn request_header_error_status(error: HeaderError) -> StatusCode {
    match error {
        HeaderError::InvalidConnectionHeader => StatusCode::BAD_REQUEST,
        HeaderError::TooLarge => StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
    }
}

/// Maps response header errors to audit classes.
const fn response_header_error_class(error: HeaderError) -> &'static str {
    match error {
        HeaderError::InvalidConnectionHeader => "invalid_response_connection_header",
        HeaderError::TooLarge => "response_headers_too_large",
    }
}

/// Maps upstream request errors to audit classes.
fn upstream_error_class(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "upstream_timeout"
    } else if error.is_connect() {
        "upstream_connect_failed"
    } else {
        "upstream_request_failed"
    }
}

/// Maps upstream request errors to response statuses.
fn upstream_error_status(error: &reqwest::Error) -> StatusCode {
    if error.is_timeout() {
        StatusCode::GATEWAY_TIMEOUT
    } else {
        StatusCode::BAD_GATEWAY
    }
}

#[cfg(test)]
mod tests {
    use super::{ResponseAuditContext, ServeError, run_until_server_stops};
    use crate::allowlist::AcceptedTarget;
    use crate::audit::{AuditDecision, AuditError, RequestId};
    use crate::body::{AccountedBody, ResponseAccount};
    use crate::config::GatewayConfig;
    use crate::gateway::{Gateway, GatewayError};
    use ::http::Method;
    use axum::body::Body;
    use core::future;
    use core::num::{NonZeroU64, NonZeroUsize};
    use std::io;
    use tempfile::tempdir;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn audit_after_response_started_reports_fatal_error() {
        let directory = tempdir().expect("temporary directory should be created");
        let config = GatewayConfig::for_test(
            directory.path().join("audit.ndjson"),
            NonZeroUsize::new(1).expect("limit should be non-zero"),
        );
        let gateway = Gateway::new(config)
            .await
            .expect("gateway should initialize");
        let request_body = AccountedBody::read_request(
            Body::empty(),
            NonZeroUsize::new(1).expect("limit should be non-zero"),
        )
        .await
        .expect("request body should be accounted");
        let mut response_account =
            ResponseAccount::new(NonZeroU64::new(1_024).expect("limit should be non-zero"));
        response_account
            .add_chunk(b"hello")
            .expect("response chunk should be accounted");
        let (fatal_errors, mut fatal_receiver) = mpsc::unbounded_channel();
        let context = ResponseAuditContext {
            fatal_errors,
            gateway,
            method: Method::GET,
            request_body,
            request_id: RequestId::from_parts("test", 1),
            response_account,
            status: 200,
            target: AcceptedTarget::new("/v1/models", None).expect("target should parse"),
            upstream_path: "/v1/models".to_owned(),
            upstream_query: None,
        };

        let result = context
            .audit_after_response_started(AuditDecision::Allowed, None)
            .await;
        let fatal = fatal_receiver
            .recv()
            .await
            .expect("fatal error should be reported");

        assert!(result.is_err());
        assert!(matches!(
            fatal,
            GatewayError::Audit(AuditError::EventTooLarge { .. }),
        ));
    }

    #[tokio::test]
    async fn run_until_server_stops_returns_fatal_error() {
        let (fatal_errors, fatal_receiver) = mpsc::unbounded_channel();
        fatal_errors
            .send(GatewayError::Audit(AuditError::EventTooLarge {
                bytes: 2,
                max: 1,
            }))
            .expect("fatal error should be sent");

        let result =
            run_until_server_stops(future::pending::<Result<(), io::Error>>(), fatal_receiver)
                .await;

        assert!(matches!(
            result,
            Err(ServeError::Gateway(GatewayError::Audit(
                AuditError::EventTooLarge { bytes: 2, max: 1 },
            ))),
        ));
    }
}
