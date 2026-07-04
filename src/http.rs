//! Axum request and response wiring.

use crate::adapters::{
    RequestIdSourceBuildError, ReqwestUpstreamClient, SequentialRequestIds, SystemClock,
    UpstreamClientBuildError,
};
use crate::allowlist::{AcceptedTarget, AllowedTarget, RejectionReason, allow_target};
use crate::audit::{
    AuditDenial, AuditDenialReason, AuditResponseHeaderError, AuditTarget, AuditUpstreamError,
    AuditWriter, RequestId,
};
use crate::body::{AccountedBody, RequestBodyError, ResponseAccount};
use crate::config::GatewayConfig;
use crate::gateway::{Gateway, GatewayError, ResponseAuditInput, ResponseAuditOutcome};
use crate::headers::{
    ForwardedRequestHeaders, HeaderError, forward_request_headers, forward_response_headers,
};
use crate::ports::{
    UpstreamBodyErrorKind, UpstreamClient, UpstreamDeadline, UpstreamError, UpstreamErrorKind,
    UpstreamRequest, UpstreamResponse,
};
use ::http::{Method, Uri};
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::response::IntoResponse as _;
use axum::{Router, routing::any};
use core::convert::Infallible;
use core::future::{Future, IntoFuture as _};
use core::pin::Pin;
use futures_util::StreamExt as _;
use futures_util::future::{self, Either};
use std::io;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;

/// Serving runtime error.
#[derive(Debug, Error)]
pub(crate) enum ServeError {
    /// Gateway request handling failed fatally.
    #[error("{0}")]
    Gateway(#[from] GatewayError),

    /// Production request id source could not be built.
    #[error("{0}")]
    RequestIds(#[from] RequestIdSourceBuildError),

    /// Gateway server failed.
    #[error("gateway server failed: {0}")]
    Server(io::Error),

    /// Gateway listener could not bind.
    #[error("failed to bind gateway listener: {0}")]
    ServerBind(io::Error),

    /// Production upstream client could not be built.
    #[error("{0}")]
    UpstreamClient(#[from] UpstreamClientBuildError),
}

/// Shared Axum application state.
#[derive(Clone, Debug)]
struct AppState {
    /// Upstream HTTP client.
    client: Arc<dyn UpstreamClient>,
    /// Request concurrency limiter.
    concurrency: Arc<Semaphore>,
    /// Fatal error channel for failures detected after responses start.
    fatal_errors: mpsc::UnboundedSender<GatewayError>,
    /// Gateway state.
    gateway: Gateway,
}

/// Real production adapters created at startup.
#[derive(Debug)]
struct ProductionAdapters {
    /// Upstream HTTP client.
    client: ReqwestUpstreamClient,
    /// Request identity source.
    request_ids: SequentialRequestIds,
}

impl ProductionAdapters {
    /// Builds production adapters from adapter construction results.
    fn from_results(
        client: Result<ReqwestUpstreamClient, UpstreamClientBuildError>,
        request_ids: Result<SequentialRequestIds, RequestIdSourceBuildError>,
    ) -> Result<Self, ServeError> {
        Ok(Self {
            client: client?,
            request_ids: request_ids?,
        })
    }

    /// Builds real production adapters.
    fn new() -> Result<Self, ServeError> {
        Self::from_results(
            ReqwestUpstreamClient::new(),
            SequentialRequestIds::production(),
        )
    }
}

/// Response audit state carried until the terminal stream decision.
#[derive(Debug)]
struct ResponseAuditContext {
    /// Fatal error channel for failures detected after responses start.
    fatal_errors: mpsc::UnboundedSender<GatewayError>,
    /// Gateway state.
    gateway: Gateway,
    /// Accounted request body.
    request_body: AccountedBody,
    /// Request identity.
    request_id: RequestId,
    /// Accounted response body.
    response_account: ResponseAccount,
    /// Upstream response status.
    status: StatusCode,
    /// Allowlist witness for the accepted method and target.
    target: AllowedTarget,
}

/// Accepted request state ready for upstream forwarding.
struct ForwardRequestInput {
    /// Admission permit held until this request completes.
    permit: OwnedSemaphorePermit,
    /// Accounted request body.
    request_body: AccountedBody,
    /// Forwarded request headers.
    request_headers: ForwardedRequestHeaders,
    /// Request identity.
    request_id: RequestId,
    /// Allowlist witness for the accepted method and target.
    target: AllowedTarget,
}

/// Audit failure observed after response streaming started.
#[derive(Debug, Error)]
#[error("audit_failed")]
struct ResponseAuditFailure;

/// Terminal response stream outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseStreamOutcome {
    /// Response completed successfully.
    Allowed,

    /// Downstream closed before the response completed.
    DownstreamClosed,

    /// Response body exceeded the configured byte limit.
    ResponseBodyTooLarge,

    /// Upstream response stream failed after upstream I/O started.
    UpstreamResponseStreamFailed,

    /// Upstream response stream timed out after upstream I/O started.
    UpstreamResponseTimeout,
}

/// Server task future shape observed by the shutdown coordinator.
type ServerFuture = Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send>>;

/// Terminal stream error reason sent to the harness.
#[derive(Debug, Error)]
enum StreamAbortReason {
    /// Audit failed after response streaming started.
    #[error("{0}")]
    Audit(ResponseAuditFailure),

    /// Response body exceeded the configured byte limit.
    #[error("response_body_too_large")]
    ResponseBodyTooLarge,

    /// Upstream response body stream failed.
    #[error("upstream_response_stream_failed")]
    UpstreamBody,

    /// Upstream response body stream timed out.
    #[error("upstream_response_timeout")]
    UpstreamBodyTimeout,
}

impl ResponseAuditContext {
    /// Writes the terminal response audit event.
    async fn audit(&self, stream_outcome: ResponseStreamOutcome) -> Result<(), GatewayError> {
        let audit_outcome = match stream_outcome {
            ResponseStreamOutcome::Allowed => {
                ResponseAuditOutcome::allowed(&self.response_account, self.status)
            }
            ResponseStreamOutcome::DownstreamClosed => {
                ResponseAuditOutcome::downstream_closed(&self.response_account, self.status)
            }
            ResponseStreamOutcome::ResponseBodyTooLarge => {
                ResponseAuditOutcome::response_body_too_large(&self.response_account, self.status)
            }
            ResponseStreamOutcome::UpstreamResponseStreamFailed => {
                ResponseAuditOutcome::upstream_response_stream_failed(
                    &self.response_account,
                    self.status,
                )
            }
            ResponseStreamOutcome::UpstreamResponseTimeout => {
                ResponseAuditOutcome::upstream_response_timeout(&self.response_account, self.status)
            }
        };
        let input = ResponseAuditInput::new(
            &self.target,
            audit_outcome,
            &self.request_body,
            self.request_id.clone(),
        );
        self.gateway.audit_response(input).await
    }

    /// Writes the terminal response audit event or reports a fatal error.
    async fn audit_after_response_started(
        &self,
        outcome: ResponseStreamOutcome,
    ) -> Result<(), ResponseAuditFailure> {
        let fatal_errors = self.fatal_errors.clone();
        match self.audit(outcome).await {
            Ok(()) => Ok(()),
            Err(error) => {
                report_fatal_error(&fatal_errors, error);
                Err(ResponseAuditFailure)
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
) -> Result<Result<AllowedTarget, Response<Body>>, GatewayError> {
    if method == Method::CONNECT {
        return reject_allowed_target(
            gateway,
            request_id,
            AuditDenial::connect_unsupported(synthetic_target(uri)),
        )
        .await;
    }

    if uri.authority().is_some() {
        return reject_allowed_target(
            gateway,
            request_id,
            AuditDenial::absolute_form_unsupported(method.clone(), synthetic_target(uri)),
        )
        .await;
    }

    let target = match AcceptedTarget::new(uri.path(), uri.query()) {
        Ok(target) => target,
        Err(reason) => {
            let target = synthetic_target(uri);
            return reject_allowed_target(
                gateway,
                request_id,
                audit_denial_from_rejection(method.clone(), target, reason),
            )
            .await;
        }
    };

    match allow_target(gateway.config(), method, target.clone()) {
        Ok(allowed_target) => Ok(Ok(allowed_target)),
        Err(reason) => {
            reject_allowed_target(
                gateway,
                request_id,
                audit_denial_from_rejection(method.clone(), target.into(), reason),
            )
            .await
        }
    }
}

/// Audits an allowlist rejection and returns the rejected target response.
async fn reject_allowed_target(
    gateway: &Gateway,
    request_id: &RequestId,
    denial: AuditDenial,
) -> Result<Result<AllowedTarget, Response<Body>>, GatewayError> {
    let response = audit_denial_status(gateway, request_id.clone(), denial, None).await?;
    Ok(Err(response))
}

/// Audits a request denial and returns its status response.
async fn audit_denial_status(
    gateway: &Gateway,
    request_id: RequestId,
    denial: AuditDenial,
    request_body: Option<&AccountedBody>,
) -> Result<Response<Body>, GatewayError> {
    let status = denial.status();
    gateway
        .audit_denial(request_id, denial, request_body)
        .await?;
    Ok(status_response(status))
}

/// Handles one proxied request.
async fn proxy(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Result<Response<Body>, Infallible> {
    let permit = match Arc::clone(&state.concurrency).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_error) => {
            let request_id = match allocate_request_id(&state.gateway, &state.fatal_errors) {
                Ok(request_id) => request_id,
                Err(error) => {
                    tracing::error!(%error, "request failed");
                    return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
                }
            };
            let method = request.method().clone();
            let denial = AuditDenial::too_many_requests(method, synthetic_target(request.uri()));
            if state
                .gateway
                .audit_denial(request_id, denial, None)
                .await
                .is_err()
            {
                return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
            return Ok(AuditDenialReason::TooManyRequests.status().into_response());
        }
    };

    Ok(
        match handle_request(
            state.fatal_errors,
            state.gateway,
            state.client,
            permit,
            request,
        )
        .await
        {
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
    client: Arc<dyn UpstreamClient>,
    permit: OwnedSemaphorePermit,
    request: Request<Body>,
) -> Result<Response<Body>, GatewayError> {
    let request_id = allocate_request_id(&gateway, &fatal_errors)?;
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
                let reason = denial_reason_from_request_header(error);
                return audit_denial_status(
                    &gateway,
                    request_id,
                    audit_denial_from_reason(method, target.target().clone().into(), reason),
                    None,
                )
                .await;
            }
        };

    let request_body = match timeout(
        gateway.config().request_timeout().as_duration(),
        AccountedBody::read_request(body, gateway.config().max_request_bytes()),
    )
    .await
    {
        Ok(Ok(request_body)) => request_body,
        Ok(Err(error)) => {
            let reason = denial_reason_from_request_body(&error);
            return audit_denial_status(
                &gateway,
                request_id,
                audit_denial_from_reason(method, target.target().clone().into(), reason),
                None,
            )
            .await;
        }
        Err(_elapsed) => {
            return audit_denial_status(
                &gateway,
                request_id,
                AuditDenial::request_body_timeout(method, target.target().clone().into()),
                None,
            )
            .await;
        }
    };

    let input = ForwardRequestInput {
        permit,
        request_body,
        request_headers,
        request_id,
        target,
    };
    forward_request(fatal_errors, gateway, client, input).await
}

/// Allocates a request identity or reports an unauditable fatal failure.
fn allocate_request_id(
    gateway: &Gateway,
    fatal_errors: &mpsc::UnboundedSender<GatewayError>,
) -> Result<RequestId, GatewayError> {
    match gateway.next_request_id() {
        Ok(request_id) => Ok(request_id),
        Err(error) => {
            report_fatal_error(fatal_errors, GatewayError::from(error));
            Err(GatewayError::from(error))
        }
    }
}

/// Forwards an accepted request to the configured upstream.
async fn forward_request(
    fatal_errors: mpsc::UnboundedSender<GatewayError>,
    gateway: Gateway,
    client: Arc<dyn UpstreamClient>,
    accepted_request: ForwardRequestInput,
) -> Result<Response<Body>, GatewayError> {
    let ForwardRequestInput {
        permit,
        request_body,
        request_headers,
        request_id,
        target,
    } = accepted_request;
    let upstream_request = UpstreamRequest::from_target(
        gateway.config().upstream_origin(),
        &target,
        request_headers,
        &request_body,
        UpstreamDeadline::from_timeout(gateway.config().request_timeout()),
    );
    let upstream_response = match client.send(upstream_request).await {
        Ok(upstream_response) => upstream_response,
        Err(error) => {
            let audit_error = audit_upstream_error(&error);
            let outcome = ResponseAuditOutcome::upstream_error(audit_error);
            let input = ResponseAuditInput::new(&target, outcome, &request_body, request_id);
            return audit_response_status(&gateway, input, audit_error.status()).await;
        }
    };
    let status = upstream_response.status();
    let response_headers = match forward_response_headers(
        upstream_response.headers(),
        gateway.config().max_response_header_bytes(),
    ) {
        Ok(response_headers) => response_headers,
        Err(error) => {
            let audit_error = audit_response_header_error(error);
            let outcome = ResponseAuditOutcome::response_header_error(audit_error);
            let input = ResponseAuditInput::new(&target, outcome, &request_body, request_id);
            return audit_response_status(&gateway, input, audit_error.status()).await;
        }
    };
    let response_account = ResponseAccount::new(gateway.config().max_response_bytes());
    let context = ResponseAuditContext {
        fatal_errors,
        gateway,
        request_body,
        request_id,
        response_account,
        status,
        target,
    };
    let response_header_map = response_headers.into_header_map();

    let mut response = Response::builder().status(status);
    for (name, value) in &response_header_map {
        response = response.header(name, value);
    }
    let stream = response_stream(context, upstream_response, permit);
    response
        .body(Body::from_stream(stream))
        .map_err(GatewayError::ResponseBuild)
}

/// Audits a response failure and returns its status response.
async fn audit_response_status(
    gateway: &Gateway,
    input: ResponseAuditInput<'_>,
    status: StatusCode,
) -> Result<Response<Body>, GatewayError> {
    gateway.audit_response(input).await?;
    Ok(status_response(status))
}

/// Maps an upstream response body error to terminal stream and audit outcomes.
const fn upstream_body_error_outcome(
    error_kind: UpstreamBodyErrorKind,
) -> (ResponseStreamOutcome, StreamAbortReason) {
    match error_kind {
        UpstreamBodyErrorKind::Stream => (
            ResponseStreamOutcome::UpstreamResponseStreamFailed,
            StreamAbortReason::UpstreamBody,
        ),
        UpstreamBodyErrorKind::Timeout => (
            ResponseStreamOutcome::UpstreamResponseTimeout,
            StreamAbortReason::UpstreamBodyTimeout,
        ),
    }
}

/// Streams the upstream response and writes exactly one terminal audit event.
fn response_stream(
    mut context: ResponseAuditContext,
    upstream_response: UpstreamResponse,
    permit: OwnedSemaphorePermit,
) -> ReceiverStream<Result<Bytes, io::Error>> {
    let (sender, receiver) = mpsc::channel(8);

    tokio::spawn(async move {
        let _permit = permit;
        let mut stream = upstream_response.into_body();
        let mut pending = None;
        while let Some(chunk_result) = stream.next().await {
            let chunk = match chunk_result {
                Ok(bytes) => bytes,
                Err(upstream_body_error) => {
                    let (outcome, stream_error) =
                        upstream_body_error_outcome(upstream_body_error.kind());
                    if let Some(previous_chunk) = pending.take()
                        && sender.send(Ok(previous_chunk)).await.is_err()
                    {
                        if let Err(audit_error) =
                            context.audit_after_response_started(outcome).await
                        {
                            tracing::error!(%audit_error, "failed to audit upstream body error");
                        }
                        return;
                    }
                    send_stream_error(
                        &sender,
                        context.audit_after_response_started(outcome).await,
                        stream_error,
                    )
                    .await;
                    return;
                }
            };

            if let Some(previous_chunk) = pending.take()
                && sender.send(Ok(previous_chunk)).await.is_err()
            {
                if let Err(audit_error) = context
                    .audit_after_response_started(ResponseStreamOutcome::DownstreamClosed)
                    .await
                {
                    tracing::error!(%audit_error, "failed to audit downstream close");
                }
                return;
            }

            if let Err(_error) = context.response_account.add_chunk(&chunk) {
                send_stream_error(
                    &sender,
                    context
                        .audit_after_response_started(ResponseStreamOutcome::ResponseBodyTooLarge)
                        .await,
                    StreamAbortReason::ResponseBodyTooLarge,
                )
                .await;
                return;
            }

            pending = Some(chunk);
        }

        let Some(final_chunk) = pending else {
            let audit_result = context
                .audit_after_response_started(ResponseStreamOutcome::Allowed)
                .await;
            if let Err(error) = audit_result {
                send_terminal_stream_error(&sender, StreamAbortReason::Audit(error)).await;
            }
            return;
        };

        let Ok(final_permit) = sender.reserve().await else {
            if let Err(audit_error) = context
                .audit_after_response_started(ResponseStreamOutcome::DownstreamClosed)
                .await
            {
                tracing::error!(%audit_error, "failed to audit downstream close");
            }
            return;
        };

        let audit_result = context
            .audit_after_response_started(ResponseStreamOutcome::Allowed)
            .await;
        match audit_result {
            Ok(()) => final_permit.send(Ok(final_chunk)),
            Err(error) => {
                drop(final_permit);
                send_terminal_stream_error(&sender, StreamAbortReason::Audit(error)).await;
            }
        }
    });

    ReceiverStream::new(receiver)
}

/// Sends a stream error, preferring audit failure over upstream failure.
async fn send_stream_error(
    sender: &mpsc::Sender<Result<Bytes, io::Error>>,
    audit_result: Result<(), ResponseAuditFailure>,
    stream_error: StreamAbortReason,
) {
    let terminal_error = audit_result.map_or_else(StreamAbortReason::Audit, |_ok| stream_error);
    send_terminal_stream_error(sender, terminal_error).await;
}

/// Sends one terminal stream error to the harness.
async fn send_terminal_stream_error(
    sender: &mpsc::Sender<Result<Bytes, io::Error>>,
    stream_error: StreamAbortReason,
) {
    let send_result = sender
        .send(Err(io::Error::other(stream_error.to_string())))
        .await;
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
    serve_with_adapter_result(config, ProductionAdapters::new()).await
}

/// Starts the gateway HTTP server with an adapter construction result.
async fn serve_with_adapter_result(
    config: GatewayConfig,
    adapter_result: Result<ProductionAdapters, ServeError>,
) -> Result<(), ServeError> {
    let bind = config.bind();
    let max_concurrent_requests = config.max_concurrent_requests().get();
    let adapters = adapter_result?;
    let gateway = production_gateway(config, adapters.request_ids).await?;
    let (fatal_errors, fatal_receiver) = mpsc::unbounded_channel();
    let state = AppState {
        client: Arc::new(adapters.client),
        concurrency: Arc::new(Semaphore::new(max_concurrent_requests)),
        fatal_errors,
        gateway,
    };
    let app = Router::new().fallback(any(proxy)).with_state(state);
    let listener = TcpListener::bind(bind)
        .await
        .map_err(ServeError::ServerBind)?;

    let server_task = Box::pin(axum::serve(listener, app).into_future());
    run_until_server_stops(server_task, fatal_receiver).await
}

/// Builds a gateway from production adapters.
///
/// # Errors
///
/// Returns an error when the audit log cannot be opened.
async fn production_gateway(
    config: GatewayConfig,
    request_ids: SequentialRequestIds,
) -> Result<Gateway, ServeError> {
    let audit = AuditWriter::open(&config)
        .await
        .map_err(GatewayError::from)?;
    Ok(Gateway::from_ports(config, audit, SystemClock, request_ids))
}

/// Runs a server until it stops or a fatal stream task error arrives.
async fn run_until_server_stops(
    server_task: ServerFuture,
    mut fatal_receiver: mpsc::UnboundedReceiver<GatewayError>,
) -> Result<(), ServeError> {
    let server = Box::pin(async move { server_task.await.map_err(ServeError::Server) });
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
///
/// Non-origin-form targets audit the full raw request target as the path so
/// denial events preserve the requested authority for forensics.
fn synthetic_target(uri: &Uri) -> AuditTarget {
    uri.authority().map_or_else(
        || AuditTarget::from_uri_parts(uri.path(), uri.query()),
        |authority| {
            let raw_target = uri.scheme_str().map_or_else(
                || authority.as_str().to_owned(),
                |scheme| format!("{scheme}://{authority}{}", uri.path()),
            );
            AuditTarget::from_uri_parts(&raw_target, uri.query())
        },
    )
}

/// Builds an empty response with the supplied status.
fn status_response(status: StatusCode) -> Response<Body> {
    status.into_response()
}

/// Maps request body errors to closed denial reasons.
const fn denial_reason_from_request_body(error: &RequestBodyError) -> AuditDenialReason {
    if matches!(error, RequestBodyError::Read { .. }) {
        AuditDenialReason::RequestBodyReadFailed
    } else {
        AuditDenialReason::RequestBodyTooLarge
    }
}

/// Maps request header errors to closed denial reasons.
const fn denial_reason_from_request_header(error: HeaderError) -> AuditDenialReason {
    match error {
        HeaderError::InvalidConnectionHeader => AuditDenialReason::InvalidRequestConnectionHeader,
        HeaderError::TooLarge => AuditDenialReason::RequestHeadersTooLarge,
    }
}

/// Creates a closed audit denial from a denial reason.
fn audit_denial_from_reason(
    method: Method,
    target: AuditTarget,
    reason: AuditDenialReason,
) -> AuditDenial {
    match reason {
        AuditDenialReason::AbsoluteFormUnsupported => {
            AuditDenial::absolute_form_unsupported(method, target)
        }
        AuditDenialReason::ConnectUnsupported => AuditDenial::connect_unsupported(target),
        AuditDenialReason::DotSegment => AuditDenial::dot_segment(method, target),
        AuditDenialReason::EncodedSeparator => AuditDenial::encoded_separator(method, target),
        AuditDenialReason::InvalidPercentEncoding => {
            AuditDenial::invalid_percent_encoding(method, target)
        }
        AuditDenialReason::InvalidRequestConnectionHeader => {
            AuditDenial::invalid_request_connection_header(method, target)
        }
        AuditDenialReason::MethodDenied => AuditDenial::method_denied(method, target),
        AuditDenialReason::NonOriginForm => AuditDenial::non_origin_form(method, target),
        AuditDenialReason::PathDenied => AuditDenial::path_denied(method, target),
        AuditDenialReason::PathTooLong => AuditDenial::path_too_long(method, target),
        AuditDenialReason::QueryTooLong => AuditDenial::query_too_long(method, target),
        AuditDenialReason::RequestBodyReadFailed => {
            AuditDenial::request_body_read_failed(method, target)
        }
        AuditDenialReason::RequestBodyTimeout => AuditDenial::request_body_timeout(method, target),
        AuditDenialReason::RequestBodyTooLarge => {
            AuditDenial::request_body_too_large(method, target)
        }
        AuditDenialReason::RequestHeadersTooLarge => {
            AuditDenial::request_headers_too_large(method, target)
        }
        AuditDenialReason::TooManyRequests => AuditDenial::too_many_requests(method, target),
    }
}

/// Maps accepted-target rejection reasons to closed audit denials.
fn audit_denial_from_rejection(
    method: Method,
    target: AuditTarget,
    rejection: RejectionReason,
) -> AuditDenial {
    let reason = match rejection {
        RejectionReason::DotSegment => AuditDenialReason::DotSegment,
        RejectionReason::EncodedSeparator => AuditDenialReason::EncodedSeparator,
        RejectionReason::InvalidPercentEncoding => AuditDenialReason::InvalidPercentEncoding,
        RejectionReason::MethodDenied => AuditDenialReason::MethodDenied,
        RejectionReason::NonOriginForm => AuditDenialReason::NonOriginForm,
        RejectionReason::PathDenied => AuditDenialReason::PathDenied,
        RejectionReason::PathTooLong => AuditDenialReason::PathTooLong,
        RejectionReason::QueryTooLong => AuditDenialReason::QueryTooLong,
    };
    audit_denial_from_reason(method, target, reason)
}

/// Maps accepted-target rejection reasons to closed denial reasons.
#[cfg(test)]
const fn denial_reason_from_rejection(reason: RejectionReason) -> AuditDenialReason {
    match reason {
        RejectionReason::DotSegment => AuditDenialReason::DotSegment,
        RejectionReason::EncodedSeparator => AuditDenialReason::EncodedSeparator,
        RejectionReason::InvalidPercentEncoding => AuditDenialReason::InvalidPercentEncoding,
        RejectionReason::MethodDenied => AuditDenialReason::MethodDenied,
        RejectionReason::NonOriginForm => AuditDenialReason::NonOriginForm,
        RejectionReason::PathDenied => AuditDenialReason::PathDenied,
        RejectionReason::PathTooLong => AuditDenialReason::PathTooLong,
        RejectionReason::QueryTooLong => AuditDenialReason::QueryTooLong,
    }
}

/// Maps response header errors to closed response-header errors.
const fn audit_response_header_error(error: HeaderError) -> AuditResponseHeaderError {
    match error {
        HeaderError::InvalidConnectionHeader => AuditResponseHeaderError::InvalidConnectionHeader,
        HeaderError::TooLarge => AuditResponseHeaderError::TooLarge,
    }
}

/// Maps upstream request errors to closed audit errors.
const fn audit_upstream_error(error: &UpstreamError) -> AuditUpstreamError {
    match error.kind() {
        UpstreamErrorKind::Timeout => AuditUpstreamError::Timeout,
        UpstreamErrorKind::Connect => AuditUpstreamError::Connect,
        UpstreamErrorKind::Request => AuditUpstreamError::Request,
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
        reason = "inline proptests keep scenario runner ownership explicit"
    )]
    mod proptests {
        use super::{
            SCRIPTED_AUDIT_WRITE_ERROR, ScenarioBody, ScenarioFatalError, ScenarioRun,
            audit_denial_from_reason, audit_denial_from_rejection,
            run_request_id_exhaustion_scenario, run_scenario,
        };
        use crate::allowlist::RejectionReason;
        use crate::audit::{
            AuditDenial, AuditDenialReason, AuditEvent, AuditEventInput, AuditRequestInput,
            AuditTarget, AuditTimestamp, RequestId, RunToken,
        };
        use crate::config::UpstreamOrigin;
        use crate::ports::AuditSink as _;
        use crate::sim::{
            MemoryAuditSink, Scenario, ScenarioAdmission, ScenarioAudit, ScenarioBounds,
            ScenarioClass, ScenarioDownstream, ScenarioRequest, ScenarioTarget, ScenarioUpstream,
            scenario_any,
        };
        use crate::target::{OriginFormPath, OriginFormQuery};
        use axum::body::Bytes;
        use core::num::{NonZeroU64, NonZeroUsize};
        use http::{Method, StatusCode};
        use proptest::prelude::*;
        use serde_json::{Map, Value};
        use tokio::runtime::Builder;

        /// Serialized audit event field names.
        const AUDIT_FIELDS: [&str; 14] = [
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

        /// Returns one denial reason by index.
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

        /// Returns one rejection reason and its expected denial by index.
        const fn rejection_reason(index: u8) -> (RejectionReason, AuditDenialReason) {
            match index {
                0 => (RejectionReason::DotSegment, AuditDenialReason::DotSegment),
                1 => (
                    RejectionReason::EncodedSeparator,
                    AuditDenialReason::EncodedSeparator,
                ),
                2 => (
                    RejectionReason::InvalidPercentEncoding,
                    AuditDenialReason::InvalidPercentEncoding,
                ),
                3 => (
                    RejectionReason::MethodDenied,
                    AuditDenialReason::MethodDenied,
                ),
                4 => (
                    RejectionReason::NonOriginForm,
                    AuditDenialReason::NonOriginForm,
                ),
                5 => (RejectionReason::PathDenied, AuditDenialReason::PathDenied),
                6 => (RejectionReason::PathTooLong, AuditDenialReason::PathTooLong),
                _ => (
                    RejectionReason::QueryTooLong,
                    AuditDenialReason::QueryTooLong,
                ),
            }
        }

        /// Returns the serialized audit body summary for observed body bytes.
        fn audit_body_value(body: &[u8]) -> Result<Value, TestCaseError> {
            if body.is_empty() {
                Ok(empty_body_value())
            } else {
                Ok(Value::Object(Map::from_iter([
                    (
                        "blake3".to_owned(),
                        Value::String(blake3::hash(body).to_hex().to_string()),
                    ),
                    (
                        "bytes".to_owned(),
                        Value::from(
                            u64::try_from(body.len()).map_err(|_error| {
                                TestCaseError::fail("body length should fit u64")
                            })?,
                        ),
                    ),
                    ("state".to_owned(), Value::String("non_empty".to_owned())),
                ])))
            }
        }

        /// Returns lower-case headers named by generated connection headers.
        fn connection_header_names(headers: &[(String, String)]) -> Vec<String> {
            headers
                .iter()
                .filter(|header| header.0 == "connection")
                .flat_map(|header| {
                    header
                        .1
                        .split(',')
                        .map(|raw| raw.trim().to_ascii_lowercase())
                })
                .collect()
        }

        /// Returns the expected forwarded headers for generated headers.
        fn expected_forwarded_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
            let connection_headers = connection_header_names(headers);
            let mut forwarded = headers
                .iter()
                .filter(|header| request_header_is_forwarded(&header.0, &connection_headers))
                .cloned()
                .collect::<Vec<_>>();
            forwarded.sort();
            forwarded
        }

        /// Returns the expected audit decision tuple for a recording scenario.
        fn expected_audit_outcome(
            scenario: &Scenario,
        ) -> Result<(&'static str, Value, StatusCode, u64, Value, bool), TestCaseError> {
            match (
                scenario.admission(),
                scenario.bounds(),
                scenario.downstream(),
                scenario.upstream(),
            ) {
                (ScenarioAdmission::Saturated, _, _, _) => Ok((
                    "denied",
                    Value::String("too_many_requests".to_owned()),
                    StatusCode::TOO_MANY_REQUESTS,
                    0,
                    not_observed_body_value(),
                    false,
                )),
                (ScenarioAdmission::Open, _, _, ScenarioUpstream::Timeout) => Ok((
                    "upstream_error",
                    Value::String("upstream_timeout".to_owned()),
                    StatusCode::GATEWAY_TIMEOUT,
                    0,
                    not_observed_body_value(),
                    true,
                )),
                (ScenarioAdmission::Open, ScenarioBounds::TinyResponse, _, _) => Ok((
                    "response_error",
                    Value::String("response_body_too_large".to_owned()),
                    StatusCode::CREATED,
                    0,
                    not_observed_body_value(),
                    true,
                )),
                (
                    ScenarioAdmission::Open,
                    ScenarioBounds::Roomy,
                    _,
                    ScenarioUpstream::StreamError,
                ) => Ok((
                    "response_error",
                    Value::String("upstream_response_stream_failed".to_owned()),
                    StatusCode::CREATED,
                    5,
                    audit_body_value(b"first")?,
                    true,
                )),
                (
                    ScenarioAdmission::Open,
                    ScenarioBounds::Roomy,
                    _,
                    ScenarioUpstream::BodyTimeout,
                ) => Ok((
                    "response_error",
                    Value::String("upstream_response_timeout".to_owned()),
                    StatusCode::CREATED,
                    5,
                    audit_body_value(b"first")?,
                    true,
                )),
                (
                    ScenarioAdmission::Open,
                    ScenarioBounds::Roomy,
                    ScenarioDownstream::ConsumeAll,
                    ScenarioUpstream::Respond,
                ) => Ok((
                    "allowed",
                    Value::Null,
                    StatusCode::CREATED,
                    8,
                    audit_body_value(b"scripted")?,
                    true,
                )),
                (
                    ScenarioAdmission::Open,
                    ScenarioBounds::Roomy,
                    ScenarioDownstream::DropBeforeFirstChunk,
                    ScenarioUpstream::Respond,
                ) => Ok((
                    "response_error",
                    Value::String("downstream_closed".to_owned()),
                    StatusCode::CREATED,
                    6,
                    audit_body_value(b"script")?,
                    true,
                )),
                (
                    ScenarioAdmission::Open,
                    ScenarioBounds::Roomy,
                    ScenarioDownstream::DropBeforeFinalChunk,
                    ScenarioUpstream::Respond,
                ) => Ok((
                    "response_error",
                    Value::String("downstream_closed".to_owned()),
                    StatusCode::CREATED,
                    8,
                    audit_body_value(b"scripted")?,
                    true,
                )),
            }
        }

        /// Returns the expected body observation for a generated scenario.
        fn expected_body(scenario: &Scenario) -> ScenarioBody {
            match (
                scenario.admission(),
                scenario.audit(),
                scenario.bounds(),
                scenario.downstream(),
                scenario.upstream(),
            ) {
                (ScenarioAdmission::Saturated, _, _, _, _)
                | (ScenarioAdmission::Open, _, _, _, ScenarioUpstream::Timeout) => {
                    ScenarioBody::Complete(Bytes::new())
                }
                (
                    ScenarioAdmission::Open,
                    _,
                    ScenarioBounds::Roomy,
                    ScenarioDownstream::DropBeforeFirstChunk,
                    ScenarioUpstream::Respond
                    | ScenarioUpstream::StreamError
                    | ScenarioUpstream::BodyTimeout,
                ) => ScenarioBody::Dropped(Bytes::new()),
                (
                    ScenarioAdmission::Open,
                    _,
                    ScenarioBounds::Roomy,
                    ScenarioDownstream::DropBeforeFinalChunk,
                    ScenarioUpstream::Respond,
                ) => ScenarioBody::Dropped(Bytes::from_static(b"script")),
                (
                    ScenarioAdmission::Open,
                    _,
                    ScenarioBounds::Roomy,
                    ScenarioDownstream::DropBeforeFinalChunk,
                    ScenarioUpstream::StreamError | ScenarioUpstream::BodyTimeout,
                ) => ScenarioBody::Dropped(Bytes::from_static(b"first")),
                (
                    ScenarioAdmission::Open,
                    ScenarioAudit::EventTooLarge | ScenarioAudit::FailFirst,
                    ScenarioBounds::Roomy | ScenarioBounds::TinyResponse,
                    _,
                    ScenarioUpstream::Respond
                    | ScenarioUpstream::StreamError
                    | ScenarioUpstream::BodyTimeout,
                ) => ScenarioBody::Error("audit_failed".to_owned()),
                (
                    ScenarioAdmission::Open,
                    ScenarioAudit::Record,
                    ScenarioBounds::Roomy,
                    ScenarioDownstream::ConsumeAll,
                    ScenarioUpstream::Respond,
                ) => ScenarioBody::Complete(Bytes::from_static(b"scripted")),
                (
                    ScenarioAdmission::Open,
                    ScenarioAudit::Record,
                    ScenarioBounds::TinyResponse,
                    _,
                    ScenarioUpstream::Respond
                    | ScenarioUpstream::StreamError
                    | ScenarioUpstream::BodyTimeout,
                ) => ScenarioBody::Error("response_body_too_large".to_owned()),
                (
                    ScenarioAdmission::Open,
                    ScenarioAudit::Record,
                    ScenarioBounds::Roomy,
                    _,
                    ScenarioUpstream::StreamError,
                ) => ScenarioBody::Error("upstream_response_stream_failed".to_owned()),
                (
                    ScenarioAdmission::Open,
                    ScenarioAudit::Record,
                    ScenarioBounds::Roomy,
                    _,
                    ScenarioUpstream::BodyTimeout,
                ) => ScenarioBody::Error("upstream_response_timeout".to_owned()),
            }
        }

        /// Asserts the fatal post-start errors expected for a scenario.
        fn prop_assert_fatal_errors(
            scenario: &Scenario,
            fatal_errors: &[ScenarioFatalError],
        ) -> Result<(), TestCaseError> {
            match (scenario.admission(), scenario.audit(), scenario.upstream()) {
                (
                    ScenarioAdmission::Open,
                    ScenarioAudit::EventTooLarge,
                    ScenarioUpstream::Respond
                    | ScenarioUpstream::StreamError
                    | ScenarioUpstream::BodyTimeout,
                ) => {
                    prop_assert_eq!(fatal_errors.len(), 1);
                    prop_assert!(
                        matches!(
                            fatal_errors.first(),
                            Some(ScenarioFatalError::AuditEventTooLarge { bytes, max: 1 })
                                if *bytes > 1
                        ),
                        "unexpected fatal errors: {fatal_errors:?}"
                    );
                }
                (
                    ScenarioAdmission::Open,
                    ScenarioAudit::FailFirst,
                    ScenarioUpstream::Respond
                    | ScenarioUpstream::StreamError
                    | ScenarioUpstream::BodyTimeout,
                ) => {
                    prop_assert_eq!(
                        fatal_errors,
                        [ScenarioFatalError::AuditWrite {
                            message: SCRIPTED_AUDIT_WRITE_ERROR.to_owned(),
                        }]
                    );
                }
                (
                    ScenarioAdmission::Open,
                    ScenarioAudit::Record,
                    ScenarioUpstream::Respond
                    | ScenarioUpstream::StreamError
                    | ScenarioUpstream::BodyTimeout,
                )
                | (
                    ScenarioAdmission::Saturated | ScenarioAdmission::Open,
                    ScenarioAudit::Record | ScenarioAudit::EventTooLarge | ScenarioAudit::FailFirst,
                    ScenarioUpstream::Timeout,
                )
                | (
                    ScenarioAdmission::Saturated,
                    ScenarioAudit::Record | ScenarioAudit::EventTooLarge | ScenarioAudit::FailFirst,
                    ScenarioUpstream::Respond
                    | ScenarioUpstream::StreamError
                    | ScenarioUpstream::BodyTimeout,
                ) => {
                    prop_assert!(fatal_errors.is_empty());
                }
            }
            Ok(())
        }

        /// Returns the expected status for the harness response.
        fn expected_status(scenario: &Scenario) -> StatusCode {
            match (scenario.admission(), scenario.audit(), scenario.upstream()) {
                (
                    ScenarioAdmission::Saturated,
                    ScenarioAudit::EventTooLarge | ScenarioAudit::FailFirst,
                    _,
                )
                | (
                    ScenarioAdmission::Open,
                    ScenarioAudit::EventTooLarge | ScenarioAudit::FailFirst,
                    ScenarioUpstream::Timeout,
                ) => StatusCode::INTERNAL_SERVER_ERROR,
                (ScenarioAdmission::Saturated, ScenarioAudit::Record, _) => {
                    StatusCode::TOO_MANY_REQUESTS
                }
                (ScenarioAdmission::Open, _, ScenarioUpstream::Timeout) => {
                    StatusCode::GATEWAY_TIMEOUT
                }
                (
                    ScenarioAdmission::Open,
                    _,
                    ScenarioUpstream::Respond
                    | ScenarioUpstream::StreamError
                    | ScenarioUpstream::BodyTimeout,
                ) => StatusCode::CREATED,
            }
        }

        /// Returns the configured response body bound for the scenario.
        const fn max_response_bytes(scenario: &Scenario) -> u64 {
            match scenario.bounds() {
                ScenarioBounds::Roomy => 0x0010_0000,
                ScenarioBounds::TinyResponse => 4,
            }
        }

        /// Returns the request query field from a generated query.
        fn query_value(query: Option<&str>) -> Value {
            query.map_or(Value::Null, |query_text| {
                Value::String(query_text.to_owned())
            })
        }

        /// Returns the serialized upstream URL expected for a scenario.
        fn expected_upstream_url(scenario: &Scenario) -> url::Url {
            let origin =
                UpstreamOrigin::parse("https://api.openai.com").expect("origin should parse");
            let path = OriginFormPath::parse(scenario.request().target_path())
                .expect("scenario path should parse");
            let query = scenario
                .request()
                .target_query()
                .map(OriginFormQuery::parse)
                .transpose()
                .expect("scenario query should parse");

            origin.join_path_query(&path, query.as_ref())
        }

        /// Returns true when a generated request header should be forwarded.
        fn request_header_is_forwarded(name: &str, connection_headers: &[String]) -> bool {
            !matches!(
                name,
                "connection"
                    | "host"
                    | "keep-alive"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailer"
                    | "transfer-encoding"
                    | "upgrade"
            ) && !connection_headers.iter().any(|dynamic| dynamic == name)
        }

        /// Returns the body state that should be represented in the audit log.
        fn request_body_value_for_audit(scenario: &Scenario) -> Result<Value, TestCaseError> {
            if scenario.admission() == ScenarioAdmission::Saturated {
                Ok(not_observed_body_value())
            } else {
                audit_body_value(scenario.request().body())
            }
        }

        /// Returns the serialized audit body summary for unobserved body bytes.
        fn not_observed_body_value() -> Value {
            Value::Object(Map::from_iter([(
                "state".to_owned(),
                Value::String("not_observed".to_owned()),
            )]))
        }

        /// Returns the serialized audit body summary for observed empty body bytes.
        fn empty_body_value() -> Value {
            Value::Object(Map::from_iter([(
                "state".to_owned(),
                Value::String("empty".to_owned()),
            )]))
        }

        /// Asserts the audit event invariants for one generated scenario.
        fn prop_assert_audit_event(
            scenario: &Scenario,
            run: &ScenarioRun,
        ) -> Result<(), TestCaseError> {
            prop_assert_eq!(run.audit_attempts, 1);
            let expected_events = usize::from(scenario.audit() == ScenarioAudit::Record);
            prop_assert_eq!(run.audit_events.len(), expected_events);
            if expected_events == 0 {
                return Ok(());
            }

            let event = run
                .audit_events
                .first()
                .expect("event count was asserted above");
            let object = event
                .as_object()
                .ok_or_else(|| TestCaseError::fail("audit event should be an object"))?;
            prop_assert_eq!(object.len(), AUDIT_FIELDS.len());
            for field in AUDIT_FIELDS {
                prop_assert!(object.contains_key(field), "missing audit field {field}");
            }

            let (decision, error_class, status, response_bytes, response_body, has_upstream) =
                expected_audit_outcome(scenario)?;
            let path = scenario.request().target_path();
            let query = query_value(scenario.request().target_query());
            prop_assert_eq!(&object["decision"], &Value::String(decision.to_owned()));
            prop_assert_eq!(&object["error_class"], &error_class);
            prop_assert_eq!(
                &object["method"],
                &Value::String(ScenarioRequest::method().as_str().to_owned())
            );
            prop_assert_eq!(&object["path"], &Value::String(path.to_owned()));
            prop_assert_eq!(&object["query"], &query);
            prop_assert_eq!(
                &object["request_body"],
                &request_body_value_for_audit(scenario)?
            );
            prop_assert_eq!(&object["response_body"], &response_body);
            prop_assert!(
                response_bytes <= max_response_bytes(scenario),
                "audited response bytes exceeded scenario bound"
            );
            prop_assert_eq!(&object["status"], &Value::from(status.as_u16()));
            prop_assert_eq!(
                &object["timestamp"],
                &Value::String("2026-07-02T00:00:00.000000000Z".to_owned())
            );
            prop_assert_eq!(
                &object["upstream_origin"],
                &Value::String("https://api.openai.com".to_owned())
            );
            if has_upstream {
                let upstream_url = expected_upstream_url(scenario);
                prop_assert_eq!(
                    &object["upstream_path"],
                    &Value::String(upstream_url.path().to_owned())
                );
                prop_assert_eq!(
                    &object["upstream_query"],
                    &query_value(upstream_url.query())
                );
            } else {
                prop_assert_eq!(&object["upstream_path"], &Value::Null);
                prop_assert_eq!(&object["upstream_query"], &Value::Null);
            }
            prop_assert_eq!(&object["version"], &Value::from(3_u64));
            Ok(())
        }

        /// Asserts the body and fatal-channel invariants for one scenario.
        fn prop_assert_response_outcome(
            scenario: &Scenario,
            run: &ScenarioRun,
        ) -> Result<(), TestCaseError> {
            prop_assert_eq!(run.status, expected_status(scenario));
            prop_assert_eq!(&run.response_body, &expected_body(scenario));
            prop_assert_fatal_errors(scenario, &run.fatal_errors)?;
            Ok(())
        }

        /// Asserts the upstream request invariants for one generated scenario.
        fn prop_assert_upstream_request(
            scenario: &Scenario,
            run: &ScenarioRun,
        ) -> Result<(), TestCaseError> {
            if scenario.admission() == ScenarioAdmission::Saturated {
                prop_assert!(run.upstream_requests.is_empty());
                return Ok(());
            }
            prop_assert_eq!(run.upstream_requests.len(), 1);
            let request = run
                .upstream_requests
                .first()
                .expect("request count was asserted above");
            prop_assert_eq!(request.body(), scenario.request().body());
            prop_assert_eq!(request.deadline(), run.deadline);
            prop_assert_eq!(
                request.headers(),
                expected_forwarded_headers(scenario.request().headers())
            );
            let expected_method = ScenarioRequest::method();
            prop_assert_eq!(request.method(), &expected_method);
            let expected_url = expected_upstream_url(scenario);
            prop_assert_eq!(request.url(), expected_url.as_str());
            for header in request.headers() {
                let name = &header.0;
                prop_assert!(
                    request_header_is_forwarded(
                        name,
                        &connection_header_names(scenario.request().headers())
                    ),
                    "forbidden header forwarded: {name}"
                );
            }
            Ok(())
        }

        /// Asserts all generated gateway scenario invariants.
        fn prop_assert_scenario(
            scenario: &Scenario,
            run: &ScenarioRun,
        ) -> Result<(), TestCaseError> {
            prop_assert_response_outcome(scenario, run)?;
            prop_assert_upstream_request(scenario, run)?;
            prop_assert_audit_event(scenario, run)?;
            Ok(())
        }

        /// Runs a generated scenario on a paused single-thread runtime.
        fn run_generated_scenario(scenario: Scenario) -> ScenarioRun {
            Builder::new_current_thread()
                .enable_time()
                .start_paused(true)
                .build()
                .expect("paused scenario runtime should build")
                .block_on(run_scenario(scenario))
        }

        /// Runs a request-id exhaustion scenario on a paused runtime.
        fn run_exhaustion_scenario(permits: usize) -> ScenarioRun {
            Builder::new_current_thread()
                .enable_time()
                .start_paused(true)
                .build()
                .expect("paused scenario runtime should build")
                .block_on(run_request_id_exhaustion_scenario(permits))
        }

        /// Builds one denied audit event for direct audit-sink coverage.
        fn denied_event() -> AuditEvent {
            let request_id = RequestId::from_parts(
                &RunToken::for_test("0000000000007e57-000000000000c0de"),
                NonZeroU64::new(1).expect("sequence should be non-zero"),
            );
            let denial = AuditDenial::too_many_requests(
                Method::GET,
                AuditTarget::from_uri_parts("/v1/models", None),
            );
            let denied_request = AuditRequestInput::for_denial(
                denial,
                request_id,
                None,
                UpstreamOrigin::parse("https://api.openai.com").expect("origin should parse"),
            );

            AuditEvent::new_at(
                AuditEventInput::denied(denied_request),
                AuditTimestamp::for_test("2026-07-02T00:00:00.000000000Z"),
            )
        }

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 32,
                ..ProptestConfig::default()
            })]

            #[test]
            fn audit_denial_reason_mapping_preserves_status(index in 0_u8..16) {
                let reason = denial_reason(index);
                let denial = audit_denial_from_reason(
                    Method::POST,
                    AuditTarget::from_uri_parts("/v1/models", None),
                    reason,
                );

                prop_assert_eq!(denial.status(), reason.status());
            }

            #[test]
            fn generated_scenarios_satisfy_gateway_invariants(scenario in scenario_any()) {
                let run = run_generated_scenario(scenario.clone());

                prop_assert_scenario(&scenario, &run)?;
            }

            #[test]
            fn rejection_mapping_preserves_status(index in 0_u8..8) {
                let (rejection, reason) = rejection_reason(index);
                let denial = audit_denial_from_rejection(
                    Method::POST,
                    AuditTarget::from_uri_parts("/v1/models", None),
                    rejection,
                );

                prop_assert_eq!(denial.status(), reason.status());
            }
        }

        #[tokio::test]
        async fn bounded_memory_audit_sink_accepts_exact_limit() {
            let event = denied_event();
            let event_bytes = serde_json::to_vec(&event)
                .expect("audit event should serialize")
                .len()
                .checked_add(1)
                .expect("serialized audit event length should not overflow");
            let (audit, audit_events) = MemoryAuditSink::limiting_event_bytes(
                NonZeroUsize::new(event_bytes).expect("event size should be non-zero"),
            );

            audit
                .append_event(&event)
                .await
                .expect("event at exact limit should record");

            assert_eq!(audit.event_count(), 1);
            assert_eq!(
                audit_events.lock().expect("audit events should lock").len(),
                1
            );
        }

        #[test]
        fn generated_fault_classes_cover_every_combination() {
            let classes = ScenarioClass::all();

            assert_eq!(classes.len(), ScenarioClass::count());
            for class in classes {
                let scenario = Scenario::with_class(
                    class,
                    ScenarioRequest::new(
                        b"class".to_vec(),
                        vec![
                            ("authorization".to_owned(), "Bearer harness".to_owned()),
                            ("connection".to_owned(), "te, x-drop".to_owned()),
                            ("host".to_owned(), "proxy:8080".to_owned()),
                            ("te".to_owned(), "trailers".to_owned()),
                            ("x-drop".to_owned(), "secret".to_owned()),
                            ("x-request-id".to_owned(), "trace-1".to_owned()),
                            ("x-visible".to_owned(), "ok".to_owned()),
                        ],
                        ScenarioTarget::models(Some(
                            OriginFormQuery::parse("limit=1").expect("test query should parse"),
                        )),
                    ),
                );
                let run = run_generated_scenario(scenario.clone());
                let result = prop_assert_scenario(&scenario, &run);

                assert!(
                    result.is_ok(),
                    "fault class {class:?} should satisfy invariants: {result:?}"
                );
            }
        }

        #[test]
        fn exhausted_request_ids_fail_closed_for_every_admission_state() {
            for permits in [0, 1] {
                let run = run_exhaustion_scenario(permits);

                assert_eq!(run.status, StatusCode::INTERNAL_SERVER_ERROR);
                assert_eq!(run.response_body, ScenarioBody::Complete(Bytes::new()));
                assert!(run.audit_events.is_empty());
                assert_eq!(run.audit_attempts, 0);
                assert!(run.upstream_requests.is_empty());
                assert_eq!(
                    run.fatal_errors,
                    vec![ScenarioFatalError::RequestIdSequenceExhausted]
                );
            }
        }
    }

    use super::{
        AppState, ProductionAdapters, ResponseAuditContext, ResponseAuditFailure,
        ResponseStreamOutcome, ServeError, StreamAbortReason, audit_denial_from_reason,
        audit_denial_from_rejection, audit_response_header_error, audit_upstream_error,
        denial_reason_from_rejection, denial_reason_from_request_body,
        denial_reason_from_request_header, production_gateway, proxy, report_fatal_error,
        response_stream, run_until_server_stops, send_stream_error, serve,
        serve_with_adapter_result, synthetic_target,
    };
    use crate::adapters::{
        RequestIdSourceBuildError, ReqwestUpstreamClient, SequentialRequestIds,
        UpstreamClientBuildError,
    };
    use crate::allowlist::{AcceptedTarget, AllowedTarget, RejectionReason, allow_target};
    use crate::audit::{
        AuditDenialReason, AuditError, AuditEvent, AuditResponseHeaderError, AuditTarget,
        AuditUpstreamError, RequestId, RunToken,
    };
    use crate::body::{AccountedBody, RequestBodyError, ResponseAccount};
    use crate::config::{
        AllowedOperation, GatewayConfig, RequestBodyBytes, ResponseBodyBytes, ServeArgs,
    };
    use crate::gateway::{Gateway, GatewayError};
    use crate::headers::HeaderError;
    use crate::ports::{
        AuditSink, BoxFuture, RequestIdError, RequestIdSource, UpstreamBodyError, UpstreamDeadline,
        UpstreamError, UpstreamErrorKind, UpstreamResponse,
    };
    use crate::sim::{
        FixedClock, MemoryAuditSink, RecordedUpstreamRequest, Scenario, ScenarioAdmission,
        ScenarioBounds, ScenarioDownstream, ScenarioRequest, ScenarioTarget, ScenarioUpstream,
        ScriptedUpstreamClient,
    };
    use crate::target::{MAX_ORIGIN_FORM_PATH_BYTES, MAX_ORIGIN_FORM_QUERY_BYTES, OriginFormQuery};
    use ::http::{Method, Uri};
    use axum::body::{Body, Bytes, to_bytes};
    use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
    use axum::{
        Router,
        routing::{any, get},
    };
    use clap::Parser;
    use core::future::{self, IntoFuture as _};
    use core::iter;
    use core::num::{NonZeroU64, NonZeroUsize};
    use core::time::Duration;
    use futures_util::StreamExt as _;
    use futures_util::stream;
    use http_body_util::BodyExt as _;
    use pretty_assertions::assert_eq;
    use reqwest::{Client, Proxy};
    use serde_json::{Map, Value};
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;
    use tokio::fs::read_to_string;
    use tokio::net::TcpListener;
    use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};
    use tokio::task::yield_now;
    use tokio::time::{Instant, advance, sleep};
    use tower::ServiceExt as _;

    /// Error string produced by the deterministic audit sink.
    const SCRIPTED_AUDIT_WRITE_ERROR: &str = "failed to write audit event: scripted audit failure";

    /// Closed fatal error observation for deterministic scenarios.
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum ScenarioFatalError {
        /// Audit event serialization exceeded the configured bound.
        AuditEventTooLarge {
            /// Serialized event bytes.
            bytes: usize,
            /// Maximum allowed bytes.
            max: usize,
        },

        /// Audit event write failed after the response started.
        AuditWrite {
            /// Rendered audit write failure.
            message: String,
        },

        /// Request id sequence exhausted.
        RequestIdSequenceExhausted,
    }

    /// Test wrapper that parses serve arguments.
    #[derive(Debug, Parser)]
    struct ServeCommand {
        /// Parsed serve arguments.
        #[command(flatten)]
        args: ServeArgs,
    }

    /// Observations from a deterministic gateway scenario.
    #[derive(Debug, Eq, PartialEq)]
    struct ScenarioRun {
        /// Number of attempted audit writes.
        audit_attempts: usize,
        /// Captured audit events.
        audit_events: Vec<Value>,
        /// Upstream deadline used by the gateway.
        deadline: UpstreamDeadline,
        /// Fatal gateway errors reported after response start.
        fatal_errors: Vec<ScenarioFatalError>,
        /// Captured response body outcome.
        response_body: ScenarioBody,
        /// Captured response status.
        status: StatusCode,
        /// Captured upstream requests.
        upstream_requests: Vec<RecordedUpstreamRequest>,
    }

    /// Captured response body outcome for deterministic scenarios.
    #[derive(Debug, Eq, PartialEq)]
    enum ScenarioBody {
        /// Response body completed successfully.
        Complete(Bytes),

        /// Response body was dropped before completion.
        Dropped(Bytes),

        /// Response body ended with an error.
        Error(String),
    }

    /// Audit sink that blocks the first audit attempt until released.
    #[derive(Clone, Debug)]
    struct BlockingFirstAuditSink {
        /// Number of audit events attempted by this sink.
        event_count: Arc<Mutex<usize>>,
        /// Captured serialized audit events after the blocked first attempt.
        events: Arc<Mutex<Vec<Value>>>,
        /// First append notification.
        first_append_started: Arc<Notify>,
        /// Release notification for the first append.
        release_first_append: Arc<Notify>,
    }

    /// Observer handles for a blocking audit sink.
    #[derive(Debug)]
    struct BlockingFirstAuditSinkObservers {
        /// Captured serialized audit events after the blocked first attempt.
        events: Arc<Mutex<Vec<Value>>>,
        /// First append notification.
        first_append_started: Arc<Notify>,
        /// Release notification for the first append.
        release_first_append: Arc<Notify>,
    }

    impl AuditSink for BlockingFirstAuditSink {
        fn append_event<'future>(
            &'future self,
            event: &'future AuditEvent,
        ) -> BoxFuture<'future, Result<(), AuditError>> {
            let event_count = Arc::clone(&self.event_count);
            let events = Arc::clone(&self.events);
            let first_append_started = Arc::clone(&self.first_append_started);
            let release_first_append = Arc::clone(&self.release_first_append);

            Box::pin(async move {
                let event_number = {
                    let mut count = event_count
                        .lock()
                        .expect("blocking audit event count should not be poisoned");
                    let next = count
                        .checked_add(1)
                        .expect("blocking audit event count should not overflow");
                    *count = next;
                    next
                };
                if event_number == 1 {
                    first_append_started.notify_one();
                    release_first_append.notified().await;
                }

                let value = serde_json::to_value(event)
                    .expect("audit events contain only infallible JSON values");
                events
                    .lock()
                    .expect("blocking audit sink should not be poisoned")
                    .push(value);
                Ok(())
            })
        }
    }

    impl BlockingFirstAuditSink {
        /// Returns the number of attempted audit events.
        #[must_use]
        fn event_count(&self) -> usize {
            *self
                .event_count
                .lock()
                .expect("blocking audit event count should not be poisoned")
        }

        /// Builds a blocking sink and its observers.
        #[must_use]
        fn new() -> (Self, BlockingFirstAuditSinkObservers) {
            let events = Arc::new(Mutex::new(Vec::new()));
            let first_append_started = Arc::new(Notify::new());
            let release_first_append = Arc::new(Notify::new());
            (
                Self {
                    event_count: Arc::new(Mutex::new(0)),
                    events: Arc::clone(&events),
                    first_append_started: Arc::clone(&first_append_started),
                    release_first_append: Arc::clone(&release_first_append),
                },
                BlockingFirstAuditSinkObservers {
                    events,
                    first_append_started,
                    release_first_append,
                },
            )
        }
    }

    /// Request id source that always reports exhaustion.
    #[derive(Debug)]
    struct ExhaustedRequestIds;

    impl RequestIdSource for ExhaustedRequestIds {
        fn next_request_id(&self) -> Result<RequestId, RequestIdError> {
            Err(RequestIdError::SequenceExhausted)
        }
    }

    /// Test stream state for a two-chunk upstream response.
    #[derive(Clone, Copy, Debug)]
    enum TwoChunkStep {
        /// Terminal delay before stream completion.
        End,

        /// First response chunk.
        First,

        /// Second response chunk.
        Second,
    }

    /// Reads and parses every event in the audit log.
    async fn audit_events(path: &Path) -> Vec<serde_json::Value> {
        read_to_string(path)
            .await
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("audit events should be JSON"))
            .collect()
    }

    /// Returns the audit log path inside the directory and its UTF-8 form.
    fn audit_paths(directory: &Path) -> (PathBuf, String) {
        let audit_log = directory.join("audit.ndjson");
        let text = audit_log
            .to_str()
            .expect("temporary path should be UTF-8")
            .to_owned();
        (audit_log, text)
    }

    /// Asserts an exact fatal audit event-size failure.
    fn assert_fatal_event_too_large(
        fatal: &GatewayError,
        expected_bytes: usize,
        expected_max: usize,
    ) {
        assert_eq!(
            fatal.to_string(),
            format!("audit event has {expected_bytes} bytes, maximum is {expected_max}")
        );
        assert!(
            matches!(
                fatal,
                GatewayError::Audit(AuditError::EventTooLarge { bytes, max })
                    if *bytes == expected_bytes && *max == expected_max
            ),
            "unexpected fatal error: {fatal:?}"
        );
    }

    /// Asserts an exact scripted fatal audit-write failure.
    fn assert_scripted_fatal_audit_write(fatal: &GatewayError) {
        assert_eq!(fatal.to_string(), SCRIPTED_AUDIT_WRITE_ERROR);
        assert!(
            matches!(fatal, GatewayError::Audit(AuditError::Write(_error))),
            "unexpected fatal error: {fatal:?}"
        );
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

    /// Builds an empty-body request for the supplied method and target.
    fn build_request(method: Method, target: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(target)
            .body(Body::empty())
            .expect("request should build")
    }

    /// Builds a deterministic request id source for tests.
    fn fixed_request_ids() -> SequentialRequestIds {
        SequentialRequestIds::new(RunToken::for_test("0000000000007e57-000000000000c0de"))
    }

    /// Builds a request id source construction error for startup tests.
    fn request_id_source_build_error() -> RequestIdSourceBuildError {
        RequestIdSourceBuildError::for_test(io::Error::other("entropy failed"))
    }

    /// Builds an upstream client construction error for startup tests.
    fn upstream_client_build_error() -> UpstreamClientBuildError {
        let source = Proxy::all("not a proxy URL").expect_err("invalid proxy URL should fail");
        UpstreamClientBuildError::for_test(source)
    }

    /// Builds a request body byte limit for tests.
    fn request_body_limit(value: usize) -> RequestBodyBytes {
        RequestBodyBytes::for_test(NonZeroUsize::new(value).expect("limit should be non-zero"))
    }

    /// Builds a response body byte limit for tests.
    fn response_body_limit(value: u64) -> ResponseBodyBytes {
        ResponseBodyBytes::for_test(NonZeroU64::new(value).expect("limit should be non-zero"))
    }

    /// Builds an admission permit for direct response-stream tests.
    fn test_permit() -> OwnedSemaphorePermit {
        Arc::new(Semaphore::new(1))
            .try_acquire_owned()
            .expect("test permit should be available")
    }

    /// Builds an allowlist witness for response audit tests.
    fn allowed_target(config: &GatewayConfig, path: &str) -> AllowedTarget {
        let target = AcceptedTarget::new(path, None).expect("target should parse");
        allow_target(config, &Method::GET, target).expect("target should be allowed")
    }

    /// Builds response audit state for direct stream tests.
    async fn response_audit_context(
        audit: impl AuditSink + 'static,
        max_response_bytes: ResponseBodyBytes,
    ) -> (ResponseAuditContext, mpsc::UnboundedReceiver<GatewayError>) {
        let config = GatewayConfig::for_runtime_test(
            PathBuf::from("unused-audit.ndjson"),
            "https://api.openai.com",
        );
        let target = allowed_target(&config, "/v1/models");
        let gateway = Gateway::from_ports(
            config,
            audit,
            FixedClock,
            SequentialRequestIds::new(RunToken::for_test("0000000000007e57-000000000000c0de")),
        );
        let request_body = AccountedBody::read_request(Body::empty(), request_body_limit(1))
            .await
            .expect("request body should be accounted");
        let response_account = ResponseAccount::new(max_response_bytes);
        let (fatal_errors, fatal_receiver) = mpsc::unbounded_channel();
        let context = ResponseAuditContext {
            fatal_errors,
            gateway,
            request_body,
            request_id: RequestId::from_parts(
                &RunToken::for_test("0000000000007e57-000000000000c0de"),
                NonZeroU64::new(1).expect("sequence should be non-zero"),
            ),
            response_account,
            status: StatusCode::OK,
            target,
        };
        (context, fatal_receiver)
    }

    /// Returns the origin of a bound-then-released local port.
    async fn closed_origin() -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind an ephemeral port");
        let addr = listener
            .local_addr()
            .expect("listener should expose its address");
        drop(listener);
        format!("http://{addr}")
    }

    /// Parses a gateway configuration from serve-style command-line arguments.
    fn config_from_args(arguments: &[&str]) -> GatewayConfig {
        let command =
            ServeCommand::try_parse_from(iter::once("serve").chain(arguments.iter().copied()))
                .expect("serve arguments should parse");
        GatewayConfig::try_from(command.args).expect("serve arguments should form a valid config")
    }

    /// Builds an upstream router answering the models route with `hello`.
    fn hello_upstream_router() -> Router {
        Router::new().route(
            "/v1/models",
            get(|| async { ([("x-upstream-observed", "yes")], "hello") }),
        )
    }

    /// Returns the expected deterministic audit event for the injected-port test.
    fn injected_allowed_event() -> Value {
        Value::Object(Map::from_iter([
            ("decision".to_owned(), Value::String("allowed".to_owned())),
            ("error_class".to_owned(), Value::Null),
            ("method".to_owned(), Value::String("GET".to_owned())),
            ("path".to_owned(), Value::String("/v1/models".to_owned())),
            ("query".to_owned(), Value::String("limit=1".to_owned())),
            ("request_body".to_owned(), non_empty_body_value(b"hello")),
            (
                "request_id".to_owned(),
                Value::String("req-0000000000007e57-000000000000c0de-0000000000000001".to_owned()),
            ),
            (
                "response_body".to_owned(),
                non_empty_body_value(b"scripted"),
            ),
            ("status".to_owned(), Value::from(201_u64)),
            (
                "timestamp".to_owned(),
                Value::String("2026-07-02T00:00:00.000000000Z".to_owned()),
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
                Value::String("limit=1".to_owned()),
            ),
            ("version".to_owned(), Value::from(3_u64)),
        ]))
    }

    /// Returns the expected deterministic audit event for an injected timeout.
    fn injected_timeout_event() -> Value {
        Value::Object(Map::from_iter([
            (
                "decision".to_owned(),
                Value::String("upstream_error".to_owned()),
            ),
            (
                "error_class".to_owned(),
                Value::String("upstream_timeout".to_owned()),
            ),
            ("method".to_owned(), Value::String("GET".to_owned())),
            ("path".to_owned(), Value::String("/v1/models".to_owned())),
            ("query".to_owned(), Value::Null),
            ("request_body".to_owned(), empty_body_value()),
            (
                "request_id".to_owned(),
                Value::String("req-0000000000007e57-000000000000c0de-0000000000000001".to_owned()),
            ),
            ("response_body".to_owned(), not_observed_body_value()),
            ("status".to_owned(), Value::from(504_u64)),
            (
                "timestamp".to_owned(),
                Value::String("2026-07-02T00:00:00.000000000Z".to_owned()),
            ),
            (
                "upstream_origin".to_owned(),
                Value::String("https://api.openai.com".to_owned()),
            ),
            (
                "upstream_path".to_owned(),
                Value::String("/v1/models".to_owned()),
            ),
            ("upstream_query".to_owned(), Value::Null),
            ("version".to_owned(), Value::from(3_u64)),
        ]))
    }

    /// Returns the expected deterministic audit event for a body-read timeout.
    fn injected_request_body_timeout_event() -> Value {
        Value::Object(Map::from_iter([
            ("decision".to_owned(), Value::String("denied".to_owned())),
            (
                "error_class".to_owned(),
                Value::String("request_body_timeout".to_owned()),
            ),
            ("method".to_owned(), Value::String("POST".to_owned())),
            ("path".to_owned(), Value::String("/v1/responses".to_owned())),
            ("query".to_owned(), Value::Null),
            ("request_body".to_owned(), not_observed_body_value()),
            (
                "request_id".to_owned(),
                Value::String("req-0000000000007e57-000000000000c0de-0000000000000001".to_owned()),
            ),
            ("response_body".to_owned(), not_observed_body_value()),
            ("status".to_owned(), Value::from(408_u64)),
            (
                "timestamp".to_owned(),
                Value::String("2026-07-02T00:00:00.000000000Z".to_owned()),
            ),
            (
                "upstream_origin".to_owned(),
                Value::String("https://api.openai.com".to_owned()),
            ),
            ("upstream_path".to_owned(), Value::Null),
            ("upstream_query".to_owned(), Value::Null),
            ("version".to_owned(), Value::from(3_u64)),
        ]))
    }

    /// Builds the proxy router and fatal error channel around a configuration.
    async fn proxy_router(
        config: GatewayConfig,
        permits: usize,
    ) -> (Router, mpsc::UnboundedReceiver<GatewayError>) {
        let client = ReqwestUpstreamClient::new().expect("upstream client should build");
        let gateway = production_gateway(config, fixed_request_ids())
            .await
            .expect("gateway should initialize");
        let (fatal_errors, fatal_receiver) = mpsc::unbounded_channel();
        let state = AppState {
            client: Arc::new(client),
            concurrency: Arc::new(Semaphore::new(permits)),
            fatal_errors,
            gateway,
        };
        let router = Router::new().fallback(any(proxy)).with_state(state);
        (router, fatal_receiver)
    }

    /// Runs one deterministic gateway scenario.
    async fn run_scenario(scenario: Scenario) -> ScenarioRun {
        let request_shape = scenario.request();
        let (audit, audit_recorder) = MemoryAuditSink::from_audit(scenario.audit());
        let audit_observer = audit.clone();
        let (client, upstream_recorder) =
            ScriptedUpstreamClient::from_upstream(scenario.upstream());
        let allowed_operation = AllowedOperation::parse(&format!(
            "{}:exact:{}",
            ScenarioRequest::method(),
            request_shape.target_path()
        ))
        .expect("generated scenario operation should parse");
        let mut config = GatewayConfig::for_runtime_test(
            PathBuf::from("unused-audit.ndjson"),
            "https://api.openai.com",
        )
        .with_allowed_operation(allowed_operation);
        if scenario.bounds() == ScenarioBounds::TinyResponse {
            config = config
                .with_max_response_bytes(NonZeroU64::new(4).expect("literal should be non-zero"));
        }
        let deadline = UpstreamDeadline::from_timeout(config.request_timeout());
        let gateway = Gateway::from_ports(
            config,
            audit,
            FixedClock,
            SequentialRequestIds::new(RunToken::for_test("0000000000007e57-000000000000c0de")),
        );
        let (fatal_errors, mut fatal_receiver) = mpsc::unbounded_channel();
        let permits = match scenario.admission() {
            ScenarioAdmission::Open => 1,
            ScenarioAdmission::Saturated => 0,
        };
        let state = AppState {
            client: Arc::new(client),
            concurrency: Arc::new(Semaphore::new(permits)),
            fatal_errors,
            gateway,
        };
        let router = Router::new().fallback(any(proxy)).with_state(state);
        let mut builder = Request::builder()
            .method(ScenarioRequest::method())
            .uri(request_shape.target());
        for header in request_shape.headers() {
            builder = builder.header(header.0.as_str(), header.1.as_str());
        }
        let request = builder
            .body(Body::from(request_shape.body().to_vec()))
            .expect("scenario request should build");

        let response = router
            .oneshot(request)
            .await
            .expect("scenario proxy should respond");

        let status = response.status();
        let response_body =
            consume_scenario_response(response.into_body(), scenario.downstream()).await;
        let captured_upstream_requests = upstream_recorder
            .lock()
            .expect("scripted upstream should not be poisoned")
            .clone();
        let captured_audit_events = audit_recorder
            .lock()
            .expect("memory audit sink should not be poisoned")
            .clone();
        yield_now().await;
        let audit_attempts = audit_observer.event_count();
        let reported_fatal_errors = drain_fatal_errors(&mut fatal_receiver)
            .expect("scenario fatal channel should contain only observed fatal variants");

        ScenarioRun {
            audit_attempts,
            audit_events: captured_audit_events,
            deadline,
            fatal_errors: reported_fatal_errors,
            response_body,
            status,
            upstream_requests: captured_upstream_requests,
        }
    }

    /// Runs a deterministic request-id exhaustion scenario.
    async fn run_request_id_exhaustion_scenario(permits: usize) -> ScenarioRun {
        let (audit, audit_recorder) = MemoryAuditSink::new();
        let audit_observer = audit.clone();
        let (client, upstream_recorder) = ScriptedUpstreamClient::new();
        let config = GatewayConfig::for_runtime_test(
            PathBuf::from("unused-audit.ndjson"),
            "https://api.openai.com",
        );
        let deadline = UpstreamDeadline::from_timeout(config.request_timeout());
        let gateway = Gateway::from_ports(config, audit, FixedClock, ExhaustedRequestIds);
        let (fatal_errors, mut fatal_receiver) = mpsc::unbounded_channel();
        let state = AppState {
            client: Arc::new(client),
            concurrency: Arc::new(Semaphore::new(permits)),
            fatal_errors,
            gateway,
        };
        let router = Router::new().fallback(any(proxy)).with_state(state);
        let request = build_request(Method::GET, "/v1/models");

        let response = router
            .oneshot(request)
            .await
            .expect("scenario proxy should respond");

        let status = response.status();
        let response_body = complete_scenario_response(response.into_body()).await;
        let captured_upstream_requests = upstream_recorder
            .lock()
            .expect("scripted upstream should not be poisoned")
            .clone();
        let captured_audit_events = audit_recorder
            .lock()
            .expect("memory audit sink should not be poisoned")
            .clone();
        yield_now().await;
        let audit_attempts = audit_observer.event_count();
        let reported_fatal_errors = drain_fatal_errors(&mut fatal_receiver)
            .expect("scenario fatal channel should contain only observed fatal variants");

        ScenarioRun {
            audit_attempts,
            audit_events: captured_audit_events,
            deadline,
            fatal_errors: reported_fatal_errors,
            response_body,
            status,
            upstream_requests: captured_upstream_requests,
        }
    }

    /// Drains every currently reported fatal error from a test receiver.
    fn drain_fatal_errors(
        fatal_receiver: &mut mpsc::UnboundedReceiver<GatewayError>,
    ) -> Result<Vec<ScenarioFatalError>, GatewayError> {
        let mut errors = Vec::new();
        while let Ok(error) = fatal_receiver.try_recv() {
            errors.push(scenario_fatal_error(error)?);
        }
        Ok(errors)
    }

    /// Maps a gateway fatal error into the closed scenario observation type.
    fn scenario_fatal_error(error: GatewayError) -> Result<ScenarioFatalError, GatewayError> {
        match error {
            GatewayError::Audit(AuditError::EventTooLarge { bytes, max }) => {
                Ok(ScenarioFatalError::AuditEventTooLarge { bytes, max })
            }
            GatewayError::Audit(AuditError::Write(write_error)) => {
                Ok(ScenarioFatalError::AuditWrite {
                    message: format!("failed to write audit event: {write_error}"),
                })
            }
            GatewayError::RequestId(RequestIdError::SequenceExhausted) => {
                Ok(ScenarioFatalError::RequestIdSequenceExhausted)
            }
            unexpected @ (GatewayError::Audit(_)
            | GatewayError::Body(_)
            | GatewayError::Header(_)
            | GatewayError::ResponseBuild(_)) => Err(unexpected),
        }
    }

    /// Consumes a scenario response according to downstream behavior.
    async fn consume_scenario_response(body: Body, downstream: ScenarioDownstream) -> ScenarioBody {
        match downstream {
            ScenarioDownstream::ConsumeAll => complete_scenario_response(body).await,
            ScenarioDownstream::DropBeforeFirstChunk => drop_before_first_chunk(body).await,
            ScenarioDownstream::DropBeforeFinalChunk => drop_before_final_chunk(body).await,
        }
    }

    /// Consumes the full scenario response body.
    async fn complete_scenario_response(body: Body) -> ScenarioBody {
        match to_bytes(body, 1_024).await {
            Ok(bytes) => ScenarioBody::Complete(bytes),
            Err(error) => ScenarioBody::Error(error.to_string()),
        }
    }

    /// Drops the scenario response before receiving any body bytes.
    async fn drop_before_first_chunk(body: Body) -> ScenarioBody {
        drop(body);
        advance(Duration::from_secs(1)).await;
        yield_now().await;
        ScenarioBody::Dropped(Bytes::new())
    }

    /// Receives the first data frame, then drops the scenario response body.
    async fn drop_before_final_chunk(mut body: Body) -> ScenarioBody {
        let first_chunk = loop {
            let frame = match body.frame().await {
                Some(Ok(frame)) => frame,
                Some(Err(error)) => return ScenarioBody::Error(error.to_string()),
                None => return ScenarioBody::Complete(Bytes::new()),
            };
            if let Ok(bytes) = frame.into_data() {
                break bytes;
            }
        };
        drop(body);
        advance(Duration::from_secs(1)).await;
        yield_now().await;
        ScenarioBody::Dropped(first_chunk)
    }

    /// Builds an upstream router that streams two chunks with a delay between.
    fn slow_upstream_router() -> Router {
        Router::new().route(
            "/v1/models",
            get(|| async {
                Body::from_stream(
                    stream::once(async { Ok::<Bytes, io::Error>(Bytes::from_static(b"first")) })
                        .chain(stream::once(async {
                            sleep(Duration::from_millis(200)).await;
                            Ok::<Bytes, io::Error>(Bytes::from_static(b"second"))
                        })),
                )
            }),
        )
    }

    /// Serves a router on an ephemeral local port and returns its origin.
    async fn spawn_upstream(router: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream listener should bind");
        let addr = listener
            .local_addr()
            .expect("upstream listener should expose its address");
        drop(tokio::spawn(axum::serve(listener, router).into_future()));
        format!("http://{addr}")
    }

    /// Builds a tiny-bound config and its audit log path.
    fn tiny_config(directory: &Path, max_audit_event_bytes: usize) -> (GatewayConfig, PathBuf) {
        let audit_log = directory.join("audit.ndjson");
        let config = GatewayConfig::for_test(
            audit_log.clone(),
            NonZeroUsize::new(max_audit_event_bytes).expect("limit should be non-zero"),
        );
        (config, audit_log)
    }

    /// Builds a roomy runtime config and its audit log path.
    fn runtime_config(directory: &Path, upstream_origin: &str) -> (GatewayConfig, PathBuf) {
        let audit_log = directory.join("audit.ndjson");
        let config = GatewayConfig::for_runtime_test(audit_log.clone(), upstream_origin);
        (config, audit_log)
    }

    /// Polls the audit log until it holds at least the expected event count.
    async fn wait_for_audit_events(path: &Path, expected: usize) -> Vec<serde_json::Value> {
        for _attempt in 0_u8..100 {
            if audit_events(path).await.len() >= expected {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        audit_events(path).await
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn scenario_runner_handles_allowed_requests() {
        let scenario = Scenario::new(
            ScenarioRequest::new(
                b"hello".to_vec(),
                vec![
                    ("authorization".to_owned(), "Bearer harness".to_owned()),
                    ("connection".to_owned(), "keep-alive".to_owned()),
                    ("host".to_owned(), "proxy:8080".to_owned()),
                    ("proxy-authorization".to_owned(), "Basic leak".to_owned()),
                    ("x-request-id".to_owned(), "trace-1".to_owned()),
                ],
                ScenarioTarget::models(Some(
                    OriginFormQuery::parse("limit=1").expect("test query should parse"),
                )),
            ),
            ScenarioUpstream::Respond,
        );

        let run = run_scenario(scenario).await;

        assert_eq!(run.status, StatusCode::CREATED);
        assert_eq!(
            run.response_body,
            ScenarioBody::Complete(Bytes::from_static(b"scripted"))
        );
        assert!(run.fatal_errors.is_empty());
        assert_eq!(
            run.upstream_requests,
            [RecordedUpstreamRequest::new(
                b"hello".to_vec(),
                run.deadline,
                vec![
                    ("authorization".to_owned(), "Bearer harness".to_owned()),
                    ("x-request-id".to_owned(), "trace-1".to_owned()),
                ],
                Method::GET,
                "https://api.openai.com/v1/models?limit=1",
            )]
        );
        assert_eq!(run.audit_events, [injected_allowed_event()]);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn scenario_runner_handles_upstream_stream_errors() {
        let scenario = Scenario::new(
            ScenarioRequest::new(
                b"hello".to_vec(),
                vec![("authorization".to_owned(), "Bearer harness".to_owned())],
                ScenarioTarget::models(Some(
                    OriginFormQuery::parse("limit=1").expect("test query should parse"),
                )),
            ),
            ScenarioUpstream::StreamError,
        );

        let run = run_scenario(scenario).await;

        assert_eq!(run.status, StatusCode::CREATED);
        assert_eq!(
            run.response_body,
            ScenarioBody::Error("upstream_response_stream_failed".to_owned())
        );
        assert!(run.fatal_errors.is_empty());
        assert_eq!(run.upstream_requests.len(), 1);
        assert_eq!(run.audit_events.len(), 1);
        let event = run
            .audit_events
            .first()
            .and_then(Value::as_object)
            .expect("audit event should be an object");
        assert_eq!(
            event["decision"],
            Value::String("response_error".to_owned())
        );
        assert_eq!(
            event["error_class"],
            Value::String("upstream_response_stream_failed".to_owned())
        );
        assert_eq!(event["response_body"], non_empty_body_value(b"first"));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn scenario_runner_handles_upstream_body_timeouts() {
        let scenario = Scenario::new(
            ScenarioRequest::new(
                b"hello".to_vec(),
                vec![("authorization".to_owned(), "Bearer harness".to_owned())],
                ScenarioTarget::models(Some(
                    OriginFormQuery::parse("limit=1").expect("test query should parse"),
                )),
            ),
            ScenarioUpstream::BodyTimeout,
        );

        let run = run_scenario(scenario).await;

        assert_eq!(run.status, StatusCode::CREATED);
        assert_eq!(
            run.response_body,
            ScenarioBody::Error("upstream_response_timeout".to_owned())
        );
        assert!(run.fatal_errors.is_empty());
        assert_eq!(run.upstream_requests.len(), 1);
        assert_eq!(run.audit_events.len(), 1);
        let event = run
            .audit_events
            .first()
            .and_then(Value::as_object)
            .expect("audit event should be an object");
        assert_eq!(
            event["decision"],
            Value::String("response_error".to_owned())
        );
        assert_eq!(
            event["error_class"],
            Value::String("upstream_response_timeout".to_owned())
        );
        assert_eq!(event["response_body"], non_empty_body_value(b"first"));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn proxy_uses_injected_ports_for_allowed_requests() {
        let (audit, audit_events) = MemoryAuditSink::new();
        let (client, upstream_requests) = ScriptedUpstreamClient::new();
        let config = GatewayConfig::for_runtime_test(
            PathBuf::from("unused-audit.ndjson"),
            "https://api.openai.com",
        );
        let deadline = UpstreamDeadline::from_timeout(config.request_timeout());
        let gateway = Gateway::from_ports(
            config,
            audit,
            FixedClock,
            SequentialRequestIds::new(RunToken::for_test("0000000000007e57-000000000000c0de")),
        );
        let (fatal_errors, mut fatal_receiver) = mpsc::unbounded_channel();
        let state = AppState {
            client: Arc::new(client),
            concurrency: Arc::new(Semaphore::new(1)),
            fatal_errors,
            gateway,
        };
        let router = Router::new().fallback(any(proxy)).with_state(state);
        let request = Request::builder()
            .method(Method::GET)
            .uri("/v1/models?limit=1")
            .header("authorization", "Bearer harness")
            .header("connection", "keep-alive")
            .header("host", "proxy:8080")
            .header("proxy-authorization", "Basic leak")
            .header("x-request-id", "trace-1")
            .body(Body::from("hello"))
            .expect("request should build");

        let response = router.oneshot(request).await.expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), 1_024)
            .await
            .expect("response body should stream");
        assert_eq!(body, Bytes::from_static(b"scripted"));
        let requests = upstream_requests
            .lock()
            .expect("scripted upstream should not be poisoned")
            .clone();
        assert_eq!(
            requests,
            [RecordedUpstreamRequest::new(
                b"hello".to_vec(),
                deadline,
                vec![
                    ("authorization".to_owned(), "Bearer harness".to_owned()),
                    ("x-request-id".to_owned(), "trace-1".to_owned()),
                ],
                Method::GET,
                "https://api.openai.com/v1/models?limit=1",
            )]
        );
        let events = audit_events
            .lock()
            .expect("memory audit sink should not be poisoned")
            .clone();
        assert_eq!(events, [injected_allowed_event()]);
        let fatal_result = fatal_receiver.try_recv();
        assert!(
            matches!(
                fatal_result,
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected)
            ),
            "unexpected fatal error: {fatal_result:?}"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn proxy_uses_injected_ports_for_upstream_timeouts() {
        let (audit, audit_events) = MemoryAuditSink::new();
        let (client, upstream_requests) = ScriptedUpstreamClient::stalling(Duration::from_secs(10));
        let config = GatewayConfig::for_runtime_test(
            PathBuf::from("unused-audit.ndjson"),
            "https://api.openai.com",
        );
        let deadline = UpstreamDeadline::from_timeout(config.request_timeout());
        let gateway = Gateway::from_ports(
            config,
            audit,
            FixedClock,
            SequentialRequestIds::new(RunToken::for_test("0000000000007e57-000000000000c0de")),
        );
        let (fatal_errors, mut fatal_receiver) = mpsc::unbounded_channel();
        let state = AppState {
            client: Arc::new(client),
            concurrency: Arc::new(Semaphore::new(1)),
            fatal_errors,
            gateway,
        };
        let router = Router::new().fallback(any(proxy)).with_state(state);
        let request = Request::builder()
            .method(Method::GET)
            .uri("/v1/models")
            .body(Body::empty())
            .expect("request should build");

        let started_at = Instant::now();
        let response = router.oneshot(request).await.expect("proxy should respond");

        assert_eq!(Instant::now(), started_at + deadline.timeout());
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        let body = to_bytes(response.into_body(), 1_024)
            .await
            .expect("response body should stream");
        assert_eq!(body, Bytes::new());
        let requests = upstream_requests
            .lock()
            .expect("scripted upstream should not be poisoned")
            .clone();
        assert_eq!(
            requests,
            [RecordedUpstreamRequest::new(
                Vec::new(),
                deadline,
                Vec::new(),
                Method::GET,
                "https://api.openai.com/v1/models",
            )]
        );
        let events = audit_events
            .lock()
            .expect("memory audit sink should not be poisoned")
            .clone();
        assert_eq!(events, [injected_timeout_event()]);
        let fatal_result = fatal_receiver.try_recv();
        assert!(
            matches!(
                fatal_result,
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected)
            ),
            "unexpected fatal error: {fatal_result:?}"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn proxy_allows_injected_upstream_stalls_inside_deadline() {
        let (audit, audit_events) = MemoryAuditSink::new();
        let (client, upstream_requests) = ScriptedUpstreamClient::stalling(Duration::from_secs(1));
        let config = GatewayConfig::for_runtime_test(
            PathBuf::from("unused-audit.ndjson"),
            "https://api.openai.com",
        );
        let deadline = UpstreamDeadline::from_timeout(config.request_timeout());
        let gateway = Gateway::from_ports(
            config,
            audit,
            FixedClock,
            SequentialRequestIds::new(RunToken::for_test("0000000000007e57-000000000000c0de")),
        );
        let (fatal_errors, mut fatal_receiver) = mpsc::unbounded_channel();
        let state = AppState {
            client: Arc::new(client),
            concurrency: Arc::new(Semaphore::new(1)),
            fatal_errors,
            gateway,
        };
        let router = Router::new().fallback(any(proxy)).with_state(state);
        let request = Request::builder()
            .method(Method::GET)
            .uri("/v1/models?limit=1")
            .header("authorization", "Bearer harness")
            .header("connection", "keep-alive")
            .header("host", "proxy:8080")
            .header("proxy-authorization", "Basic leak")
            .header("x-request-id", "trace-1")
            .body(Body::from("hello"))
            .expect("request should build");

        let started_at = Instant::now();
        let response = router.oneshot(request).await.expect("proxy should respond");

        assert_eq!(Instant::now(), started_at + Duration::from_secs(1));
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = to_bytes(response.into_body(), 1_024)
            .await
            .expect("response body should stream");
        assert_eq!(body, Bytes::from_static(b"scripted"));
        let requests = upstream_requests
            .lock()
            .expect("scripted upstream should not be poisoned")
            .clone();
        assert_eq!(
            requests,
            [RecordedUpstreamRequest::new(
                b"hello".to_vec(),
                deadline,
                vec![
                    ("authorization".to_owned(), "Bearer harness".to_owned()),
                    ("x-request-id".to_owned(), "trace-1".to_owned()),
                ],
                Method::GET,
                "https://api.openai.com/v1/models?limit=1",
            )]
        );
        let events = audit_events
            .lock()
            .expect("memory audit sink should not be poisoned")
            .clone();
        assert_eq!(events, [injected_allowed_event()]);
        let fatal_result = fatal_receiver.try_recv();
        assert!(
            matches!(
                fatal_result,
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected)
            ),
            "unexpected fatal error: {fatal_result:?}"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn proxy_times_out_slow_request_bodies_before_upstream() {
        let (audit, audit_events) = MemoryAuditSink::new();
        let (client, upstream_requests) = ScriptedUpstreamClient::new();
        let config = GatewayConfig::for_runtime_test(
            PathBuf::from("unused-audit.ndjson"),
            "https://api.openai.com",
        );
        let deadline = UpstreamDeadline::from_timeout(config.request_timeout());
        let gateway = Gateway::from_ports(
            config,
            audit,
            FixedClock,
            SequentialRequestIds::new(RunToken::for_test("0000000000007e57-000000000000c0de")),
        );
        let (fatal_errors, mut fatal_receiver) = mpsc::unbounded_channel();
        let state = AppState {
            client: Arc::new(client),
            concurrency: Arc::new(Semaphore::new(1)),
            fatal_errors,
            gateway,
        };
        let router = Router::new().fallback(any(proxy)).with_state(state);
        let slow_body = Body::from_stream(stream::once(async {
            sleep(Duration::from_secs(10)).await;
            Ok::<Bytes, io::Error>(Bytes::from_static(b"late"))
        }));
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/responses")
            .body(slow_body)
            .expect("request should build");

        let started_at = Instant::now();
        let response = router.oneshot(request).await.expect("proxy should respond");

        assert_eq!(Instant::now(), started_at + deadline.timeout());
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        let body = to_bytes(response.into_body(), 1_024)
            .await
            .expect("response body should stream");
        assert_eq!(body, Bytes::new());
        let requests = upstream_requests
            .lock()
            .expect("scripted upstream should not be poisoned")
            .clone();
        assert_eq!(requests, []);
        let events = audit_events
            .lock()
            .expect("memory audit sink should not be poisoned")
            .clone();
        assert_eq!(events, [injected_request_body_timeout_event()]);
        let fatal_result = fatal_receiver.try_recv();
        assert!(
            matches!(
                fatal_result,
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected)
            ),
            "unexpected fatal error: {fatal_result:?}"
        );
    }

    #[tokio::test]
    async fn proxy_denies_connect_requests() {
        let directory = tempdir().expect("temporary directory should be created");
        let (config, audit_log) = runtime_config(directory.path(), "https://api.openai.com");
        let (router, _fatal_receiver) = proxy_router(config, 1).await;

        let response = router
            .oneshot(build_request(Method::CONNECT, "example.com:443"))
            .await
            .expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let events = audit_events(&audit_log).await;
        let event = events.first().expect("denial should be audited");
        assert_eq!(event["decision"], "denied");
        assert_eq!(event["error_class"], "connect_unsupported");
        assert_eq!(event["path"], "example.com:443");
    }

    #[tokio::test]
    async fn proxy_denies_absolute_form_targets() {
        let directory = tempdir().expect("temporary directory should be created");
        let (config, audit_log) = runtime_config(directory.path(), "https://api.openai.com");
        let (router, _fatal_receiver) = proxy_router(config, 1).await;

        let response = router
            .oneshot(build_request(Method::GET, "http://example.com/v1/models"))
            .await
            .expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let events = audit_events(&audit_log).await;
        let event = events.first().expect("denial should be audited");
        assert_eq!(event["error_class"], "absolute_form_unsupported");
        assert_eq!(event["path"], "http://example.com/v1/models");
    }

    #[tokio::test]
    async fn proxy_denies_dot_segment_targets() {
        let directory = tempdir().expect("temporary directory should be created");
        let (config, audit_log) = runtime_config(directory.path(), "https://api.openai.com");
        let (router, _fatal_receiver) = proxy_router(config, 1).await;

        let response = router
            .oneshot(build_request(Method::GET, "/v1/../models"))
            .await
            .expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let events = audit_events(&audit_log).await;
        let event = events.first().expect("denial should be audited");
        assert_eq!(event["error_class"], "dot_segment");
    }

    #[tokio::test]
    async fn proxy_denies_encoded_path_separator_targets() {
        let directory = tempdir().expect("temporary directory should be created");
        let (audit_log, audit_text) = audit_paths(directory.path());
        let config = config_from_args(&[
            "--upstream-origin",
            "https://api.openai.com",
            "--allowed-operations",
            "GET:prefix:/v1/responses",
            "--audit-log",
            &audit_text,
            "--bind",
            "127.0.0.1:0",
        ]);
        let (router, _fatal_receiver) = proxy_router(config, 1).await;

        let response = router
            .oneshot(build_request(Method::GET, "/v1/responses/%2e%2e%2fmodels"))
            .await
            .expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let events = audit_events(&audit_log).await;
        let event = events.first().expect("denial should be audited");
        assert_eq!(event["error_class"], "encoded_path_separator");
        assert_eq!(event["path"], "/v1/responses/%2e%2e%2fmodels");
    }

    #[tokio::test]
    async fn proxy_denies_paths_over_the_supported_maximum() {
        let directory = tempdir().expect("temporary directory should be created");
        let (config, audit_log) = runtime_config(directory.path(), "https://api.openai.com");
        let (router, _fatal_receiver) = proxy_router(config, 1).await;
        let path = format!("/{}", "a".repeat(MAX_ORIGIN_FORM_PATH_BYTES));

        let response = router
            .oneshot(build_request(Method::GET, &path))
            .await
            .expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::URI_TOO_LONG);
        let events = audit_events(&audit_log).await;
        let event = events.first().expect("denial should be audited");
        assert_eq!(event["decision"], "denied");
        assert_eq!(event["error_class"], "path_too_long");
        let audited_path = event["path"].as_str().expect("path should be a string");
        assert_eq!(audited_path.len(), MAX_ORIGIN_FORM_PATH_BYTES);
        assert!(audited_path.ends_with(&format!("...[truncated original_bytes={}]", path.len())));
    }

    #[tokio::test]
    async fn proxy_denies_queries_over_the_supported_maximum() {
        let directory = tempdir().expect("temporary directory should be created");
        let (config, audit_log) = runtime_config(directory.path(), "https://api.openai.com");
        let (router, _fatal_receiver) = proxy_router(config, 1).await;
        let query = "a".repeat(MAX_ORIGIN_FORM_QUERY_BYTES + 1);
        let target = format!("/v1/models?{query}");

        let response = router
            .oneshot(build_request(Method::GET, &target))
            .await
            .expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::URI_TOO_LONG);
        let events = audit_events(&audit_log).await;
        let event = events.first().expect("denial should be audited");
        assert_eq!(event["decision"], "denied");
        assert_eq!(event["error_class"], "query_too_long");
        assert_eq!(event["path"], "/v1/models");
        let audited_query = event["query"].as_str().expect("query should be a string");
        assert_eq!(audited_query.len(), MAX_ORIGIN_FORM_QUERY_BYTES);
        assert!(audited_query.ends_with(&format!("...[truncated original_bytes={}]", query.len())));
    }

    #[tokio::test]
    async fn proxy_denies_operations_outside_the_allowlist() {
        let directory = tempdir().expect("temporary directory should be created");
        let (config, audit_log) = runtime_config(directory.path(), "https://api.openai.com");
        let (router, _fatal_receiver) = proxy_router(config, 1).await;
        let body = Bytes::from_static(b"denied");
        let request = Request::builder()
            .method(Method::DELETE)
            .uri("/v1/models")
            .body(Body::from(body.clone()))
            .expect("request should build");

        let response = router.oneshot(request).await.expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let events = audit_events(&audit_log).await;
        let event = events.first().expect("denial should be audited");
        assert_eq!(event["error_class"], "method_denied");
        assert_eq!(event["request_body"], not_observed_body_value());
    }

    #[tokio::test]
    async fn proxy_denies_oversized_request_headers() {
        let directory = tempdir().expect("temporary directory should be created");
        let (config, audit_log) = tiny_config(directory.path(), 0x4000);
        let (router, _fatal_receiver) = proxy_router(config, 1).await;
        let oversized = Request::builder()
            .method(Method::GET)
            .uri("/v1/models")
            .header("x-test", "value")
            .body(Body::empty())
            .expect("request should build");

        let response = router
            .oneshot(oversized)
            .await
            .expect("proxy should respond");

        assert_eq!(
            response.status(),
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
        let events = audit_events(&audit_log).await;
        let event = events.first().expect("denial should be audited");
        assert_eq!(event["error_class"], "request_headers_too_large");
        assert_eq!(event["request_body"], not_observed_body_value());
    }

    #[tokio::test]
    async fn proxy_denies_oversized_request_bodies() {
        let directory = tempdir().expect("temporary directory should be created");
        let (config, audit_log) = tiny_config(directory.path(), 0x4000);
        let (router, _fatal_receiver) = proxy_router(config, 1).await;
        let oversized = Request::builder()
            .method(Method::GET)
            .uri("/v1/models")
            .body(Body::from("ab"))
            .expect("request should build");

        let response = router
            .oneshot(oversized)
            .await
            .expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let events = audit_events(&audit_log).await;
        let event = events.first().expect("denial should be audited");
        assert_eq!(event["error_class"], "request_body_too_large");
    }

    #[tokio::test]
    async fn proxy_denies_unreadable_request_bodies() {
        let directory = tempdir().expect("temporary directory should be created");
        let (config, audit_log) = tiny_config(directory.path(), 0x4000);
        let (router, _fatal_receiver) = proxy_router(config, 1).await;
        let unreadable = Request::builder()
            .method(Method::GET)
            .uri("/v1/models")
            .body(Body::from_stream(stream::iter([Err::<Bytes, io::Error>(
                io::Error::other("read failed"),
            )])))
            .expect("request should build");

        let response = router
            .oneshot(unreadable)
            .await
            .expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let events = audit_events(&audit_log).await;
        let event = events.first().expect("denial should be audited");
        assert_eq!(event["error_class"], "request_body_read_failed");
    }

    #[tokio::test]
    async fn proxy_returns_bad_gateway_when_upstream_is_unreachable() {
        let directory = tempdir().expect("temporary directory should be created");
        let origin = closed_origin().await;
        let (config, audit_log) = runtime_config(directory.path(), &origin);
        let (router, _fatal_receiver) = proxy_router(config, 1).await;

        let response = router
            .oneshot(build_request(Method::GET, "/v1/models"))
            .await
            .expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let events = audit_events(&audit_log).await;
        let event = events.first().expect("failure should be audited");
        assert_eq!(event["decision"], "upstream_error");
        assert_eq!(event["error_class"], "upstream_connect_failed");
    }

    #[tokio::test]
    async fn proxy_returns_bad_gateway_for_oversized_response_headers() {
        let directory = tempdir().expect("temporary directory should be created");
        let upstream = spawn_upstream(hello_upstream_router()).await;
        let (audit_log, audit_text) = audit_paths(directory.path());
        let config = config_from_args(&[
            "--upstream-origin",
            &upstream,
            "--allowed-operations",
            "GET:exact:/v1/models",
            "--audit-log",
            &audit_text,
            "--bind",
            "127.0.0.1:0",
            "--max-response-header-bytes",
            "1",
        ]);
        let (router, _fatal_receiver) = proxy_router(config, 1).await;

        let response = router
            .oneshot(build_request(Method::GET, "/v1/models"))
            .await
            .expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let events = audit_events(&audit_log).await;
        let event = events.first().expect("failure should be audited");
        assert_eq!(event["decision"], "response_error");
        assert_eq!(event["error_class"], "response_headers_too_large");
        assert_eq!(
            event["status"], 502_u64,
            "the audited status is what the harness receives"
        );
    }

    #[tokio::test]
    async fn proxy_fails_when_response_header_audit_fails() {
        let directory = tempdir().expect("temporary directory should be created");
        let upstream = spawn_upstream(hello_upstream_router()).await;
        let (base_config, _audit_log) = runtime_config(directory.path(), &upstream);
        let config = base_config
            .with_max_audit_event_bytes(NonZeroUsize::new(1).expect("limit should be non-zero"))
            .with_max_response_header_bytes(
                NonZeroUsize::new(1).expect("limit should be non-zero"),
            );
        let (router, _fatal_receiver) = proxy_router(config, 1).await;

        let response = router
            .oneshot(build_request(Method::GET, "/v1/models"))
            .await
            .expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn proxy_streams_allowed_responses() {
        let directory = tempdir().expect("temporary directory should be created");
        let upstream = spawn_upstream(hello_upstream_router()).await;
        let (config, audit_log) = runtime_config(directory.path(), &upstream);
        let (router, _fatal_receiver) = proxy_router(config, 1).await;

        let response = router
            .oneshot(build_request(Method::GET, "/v1/models"))
            .await
            .expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-upstream-observed"),
            Some(&HeaderValue::from_static("yes"))
        );
        let body = to_bytes(response.into_body(), 1_024)
            .await
            .expect("response body should stream");
        assert_eq!(body, Bytes::from_static(b"hello"));
        let events = wait_for_audit_events(&audit_log, 1).await;
        let event = events.first().expect("completion should be audited");
        assert_eq!(event["decision"], "allowed");
        assert_eq!(event["status"], 200_u16);
        assert_eq!(event["response_body"], non_empty_body_value(b"hello"));
        assert_eq!(event["upstream_path"], "/v1/models");
    }

    #[tokio::test]
    async fn proxy_terminates_oversized_response_bodies() {
        let directory = tempdir().expect("temporary directory should be created");
        let upstream =
            spawn_upstream(Router::new().route("/v1/models", get(|| async { "0123456789abcdef" })))
                .await;
        let (audit_log, audit_text) = audit_paths(directory.path());
        let config = config_from_args(&[
            "--upstream-origin",
            &upstream,
            "--allowed-operations",
            "GET:exact:/v1/models",
            "--audit-log",
            &audit_text,
            "--bind",
            "127.0.0.1:0",
            "--max-response-bytes",
            "8",
        ]);
        let (router, _fatal_receiver) = proxy_router(config, 1).await;

        let response = router
            .oneshot(build_request(Method::GET, "/v1/models"))
            .await
            .expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::OK);
        let result = to_bytes(response.into_body(), 1_024).await;
        assert!(result.is_err(), "oversized response should end in an error");
        let events = wait_for_audit_events(&audit_log, 1).await;
        let event = events.first().expect("failure should be audited");
        assert_eq!(event["decision"], "response_error");
        assert_eq!(event["error_class"], "response_body_too_large");
        assert_eq!(event["response_body"], not_observed_body_value());
    }

    #[tokio::test]
    async fn proxy_reports_upstream_stream_failures() {
        let directory = tempdir().expect("temporary directory should be created");
        let upstream = spawn_upstream(Router::new().route(
            "/v1/models",
            get(|| async {
                Body::from_stream(
                    stream::once(async { Ok::<Bytes, io::Error>(Bytes::from_static(b"partial")) })
                        .chain(stream::once(async {
                            sleep(Duration::from_millis(100)).await;
                            Err::<Bytes, io::Error>(io::Error::other("upstream stream failed"))
                        })),
                )
            }),
        ))
        .await;
        let (config, audit_log) = runtime_config(directory.path(), &upstream);
        let (router, _fatal_receiver) = proxy_router(config, 1).await;

        let response = router
            .oneshot(build_request(Method::GET, "/v1/models"))
            .await
            .expect("proxy should respond");

        let result = to_bytes(response.into_body(), 1_024).await;
        assert!(
            result.is_err(),
            "failed upstream stream should end in an error"
        );
        let events = wait_for_audit_events(&audit_log, 1).await;
        let event = events.first().expect("failure should be audited");
        assert_eq!(event["decision"], "response_error");
        assert_eq!(event["error_class"], "upstream_response_stream_failed");
    }

    #[tokio::test]
    async fn proxy_audits_downstream_disconnects() {
        let directory = tempdir().expect("temporary directory should be created");
        let upstream = spawn_upstream(slow_upstream_router()).await;
        let (config, audit_log) = runtime_config(directory.path(), &upstream);
        let (router, _fatal_receiver) = proxy_router(config, 1).await;

        let response = router
            .oneshot(build_request(Method::GET, "/v1/models"))
            .await
            .expect("proxy should respond");
        drop(response);

        let events = wait_for_audit_events(&audit_log, 1).await;
        let event = events.first().expect("disconnect should be audited");
        assert_eq!(event["decision"], "response_error");
        assert_eq!(event["error_class"], "downstream_closed");
    }

    #[tokio::test]
    async fn proxy_reports_a_fatal_error_when_the_completion_audit_fails() {
        let directory = tempdir().expect("temporary directory should be created");
        let upstream = spawn_upstream(hello_upstream_router()).await;
        let (base_config, _audit_log) = runtime_config(directory.path(), &upstream);
        let config = base_config
            .with_max_audit_event_bytes(NonZeroUsize::new(1).expect("limit should be non-zero"));
        let (router, mut fatal_receiver) = proxy_router(config, 1).await;

        let response = router
            .oneshot(build_request(Method::GET, "/v1/models"))
            .await
            .expect("proxy should respond");

        let error = to_bytes(response.into_body(), 1_024)
            .await
            .expect_err("completion audit failure should fail the response body");
        assert_eq!(error.to_string(), "audit_failed");
        let fatal = fatal_receiver
            .recv()
            .await
            .expect("fatal error should be reported");
        assert_fatal_event_too_large(&fatal, 481, 1);
    }

    #[tokio::test]
    async fn proxy_reports_a_fatal_error_when_the_disconnect_audit_fails() {
        let directory = tempdir().expect("temporary directory should be created");
        let upstream = spawn_upstream(slow_upstream_router()).await;
        let (base_config, _audit_log) = runtime_config(directory.path(), &upstream);
        let config = base_config
            .with_max_audit_event_bytes(NonZeroUsize::new(1).expect("limit should be non-zero"));
        let (router, mut fatal_receiver) = proxy_router(config, 1).await;

        let response = router
            .oneshot(build_request(Method::GET, "/v1/models"))
            .await
            .expect("proxy should respond");
        drop(response);

        let fatal = fatal_receiver
            .recv()
            .await
            .expect("fatal error should be reported");
        assert_fatal_event_too_large(&fatal, 503, 1);
    }

    #[tokio::test]
    async fn proxy_rejects_requests_when_no_permits_are_available() {
        let directory = tempdir().expect("temporary directory should be created");
        let (config, audit_log) = runtime_config(directory.path(), "https://api.openai.com");
        let (router, _fatal_receiver) = proxy_router(config, 0).await;

        let response = router
            .oneshot(build_request(Method::GET, "/v1/models"))
            .await
            .expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let events = audit_events(&audit_log).await;
        let event = events.first().expect("denial should be audited");
        assert_eq!(event["error_class"], "too_many_requests");
    }

    #[tokio::test]
    async fn proxy_holds_request_permit_until_stream_completion() {
        let directory = tempdir().expect("temporary directory should be created");
        let upstream = spawn_upstream(slow_upstream_router()).await;
        let (config, _audit_log) = runtime_config(directory.path(), &upstream);
        let (router, _fatal_receiver) = proxy_router(config, 1).await;

        let first_response = router
            .clone()
            .oneshot(build_request(Method::GET, "/v1/models"))
            .await
            .expect("first request should respond");
        let second_response = router
            .oneshot(build_request(Method::GET, "/v1/models"))
            .await
            .expect("second request should respond");

        assert_eq!(second_response.status(), StatusCode::TOO_MANY_REQUESTS);
        let first_body = to_bytes(first_response.into_body(), 1_024)
            .await
            .expect("first response should complete");
        assert_eq!(first_body, Bytes::from_static(b"firstsecond"));
    }

    #[tokio::test]
    async fn proxy_fails_when_the_permit_denial_audit_fails() {
        let directory = tempdir().expect("temporary directory should be created");
        let (config, _audit_log) = tiny_config(directory.path(), 1);
        let (router, _fatal_receiver) = proxy_router(config, 0).await;

        let response = router
            .oneshot(build_request(Method::GET, "/v1/models"))
            .await
            .expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn proxy_fails_when_the_permit_denial_request_id_exhausts() {
        let config = GatewayConfig::for_runtime_test(
            PathBuf::from("unused-audit.ndjson"),
            "https://api.openai.com",
        );
        let (audit, audit_recorder) = MemoryAuditSink::new();
        let audit_observer = audit.clone();
        let (client, _upstream_recorder) = ScriptedUpstreamClient::new();
        let (fatal_errors, mut fatal_receiver) = mpsc::unbounded_channel();
        let gateway = Gateway::from_ports(config, audit, FixedClock, ExhaustedRequestIds);
        let state = AppState {
            client: Arc::new(client),
            concurrency: Arc::new(Semaphore::new(0)),
            fatal_errors,
            gateway,
        };
        let router = Router::new().fallback(any(proxy)).with_state(state);

        let response = router
            .oneshot(build_request(Method::GET, "/v1/models"))
            .await
            .expect("proxy should respond");
        let audit_events_empty = audit_recorder
            .lock()
            .expect("memory audit recorder should not be poisoned")
            .is_empty();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(audit_observer.event_count(), 0);
        assert!(audit_events_empty, "request id failure should not audit");
        let fatal = fatal_receiver
            .try_recv()
            .expect("request id exhaustion should be fatal");
        assert!(matches!(
            fatal,
            GatewayError::RequestId(RequestIdError::SequenceExhausted)
        ));
    }

    #[tokio::test]
    async fn proxy_fails_when_request_id_exhausts_after_admission() {
        let config = GatewayConfig::for_runtime_test(
            PathBuf::from("unused-audit.ndjson"),
            "https://api.openai.com",
        );
        let (audit, audit_recorder) = MemoryAuditSink::new();
        let audit_observer = audit.clone();
        let (client, _upstream_recorder) = ScriptedUpstreamClient::new();
        let (fatal_errors, mut fatal_receiver) = mpsc::unbounded_channel();
        let gateway = Gateway::from_ports(config, audit, FixedClock, ExhaustedRequestIds);
        let state = AppState {
            client: Arc::new(client),
            concurrency: Arc::new(Semaphore::new(1)),
            fatal_errors,
            gateway,
        };
        let router = Router::new().fallback(any(proxy)).with_state(state);

        let response = router
            .oneshot(build_request(Method::GET, "/v1/models"))
            .await
            .expect("proxy should respond");
        let audit_events_empty = audit_recorder
            .lock()
            .expect("memory audit recorder should not be poisoned")
            .is_empty();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(audit_observer.event_count(), 0);
        assert!(audit_events_empty, "request id failure should not audit");
        let fatal = fatal_receiver
            .try_recv()
            .expect("request id exhaustion should be fatal");
        assert!(matches!(
            fatal,
            GatewayError::RequestId(RequestIdError::SequenceExhausted)
        ));
    }

    #[tokio::test]
    async fn proxy_fails_when_the_denial_audit_fails() {
        let directory = tempdir().expect("temporary directory should be created");
        let (config, _audit_log) = tiny_config(directory.path(), 1);
        let (router, _fatal_receiver) = proxy_router(config, 1).await;

        let response = router
            .oneshot(build_request(Method::CONNECT, "example.com:443"))
            .await
            .expect("proxy should respond");

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn serve_handles_requests_until_aborted() {
        let directory = tempdir().expect("temporary directory should be created");
        let upstream = spawn_upstream(hello_upstream_router()).await;
        let (_audit_log, audit_text) = audit_paths(directory.path());
        let port_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind an ephemeral port");
        let bind = port_listener
            .local_addr()
            .expect("listener should expose its address")
            .to_string();
        drop(port_listener);
        let config = config_from_args(&[
            "--upstream-origin",
            &upstream,
            "--allowed-operations",
            "GET:exact:/v1/models",
            "--audit-log",
            &audit_text,
            "--bind",
            &bind,
        ]);
        let server = tokio::spawn(serve(config));
        let client = Client::builder()
            .no_proxy()
            .build()
            .expect("probe client should build");
        let url = format!("http://{bind}/v1/models");

        let mut status = None;
        for _attempt in 0_u8..100 {
            if let Ok(response) = client.get(&url).send().await {
                status = Some(response.status());
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        server.abort();

        assert_eq!(
            status,
            Some(StatusCode::OK),
            "gateway should proxy an allowed request"
        );
    }

    #[tokio::test]
    async fn serve_fails_when_audit_log_is_a_directory() {
        let directory = tempdir().expect("temporary directory should be created");
        let config = GatewayConfig::for_runtime_test(
            directory.path().to_path_buf(),
            "https://api.openai.com",
        );

        let result = serve(config).await;

        assert!(
            matches!(result, Err(ServeError::Gateway(_))),
            "a directory audit log should fail serving"
        );
    }

    #[test]
    fn production_adapters_report_request_id_source_build_errors() {
        let client = ReqwestUpstreamClient::new().expect("upstream client should build");

        let result =
            ProductionAdapters::from_results(Ok(client), Err(request_id_source_build_error()));

        assert!(
            matches!(result, Err(ServeError::RequestIds(_))),
            "request id source build failures should fail startup"
        );
    }

    #[test]
    fn production_adapters_report_upstream_client_build_errors() {
        let result = ProductionAdapters::from_results(
            Err(upstream_client_build_error()),
            Ok(fixed_request_ids()),
        );

        assert!(
            matches!(result, Err(ServeError::UpstreamClient(_))),
            "upstream client build failures should fail startup"
        );
    }

    #[tokio::test]
    async fn serve_reports_adapter_construction_errors() {
        let directory = tempdir().expect("temporary directory should be created");
        let config = GatewayConfig::for_runtime_test(
            directory.path().join("audit.ndjson"),
            "https://api.openai.com",
        );

        let result = serve_with_adapter_result(
            config,
            Err(ServeError::RequestIds(request_id_source_build_error())),
        )
        .await;

        assert!(
            matches!(result, Err(ServeError::RequestIds(_))),
            "adapter construction failures should stop serving before binding"
        );
    }

    #[tokio::test]
    async fn serve_fails_when_the_bind_address_is_taken() {
        let directory = tempdir().expect("temporary directory should be created");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind an ephemeral port");
        let bind = listener
            .local_addr()
            .expect("listener should expose its address")
            .to_string();
        let (_audit_log, audit_text) = audit_paths(directory.path());
        let config = config_from_args(&[
            "--upstream-origin",
            "https://api.openai.com",
            "--allowed-operations",
            "GET:exact:/v1/models",
            "--audit-log",
            &audit_text,
            "--bind",
            &bind,
        ]);

        let result = serve(config).await;

        assert!(
            matches!(result, Err(ServeError::ServerBind(_))),
            "an occupied bind address should fail serving"
        );
    }

    #[tokio::test]
    async fn run_until_server_stops_returns_server_success() {
        let (_fatal_errors, fatal_receiver) = mpsc::unbounded_channel::<GatewayError>();

        let server_task = Box::pin(future::ready(Ok::<(), io::Error>(())));
        let result = run_until_server_stops(server_task, fatal_receiver).await;

        assert!(result.is_ok(), "a finished server should stop serving");
    }

    #[tokio::test]
    async fn run_until_server_stops_returns_server_error() {
        let (_fatal_errors, fatal_receiver) = mpsc::unbounded_channel::<GatewayError>();

        let result = run_until_server_stops(
            Box::pin(future::ready(Err::<(), io::Error>(io::Error::other(
                "boom",
            )))),
            fatal_receiver,
        )
        .await;

        assert!(
            matches!(result, Err(ServeError::Server(_))),
            "a failed server should surface its error"
        );
    }

    #[tokio::test]
    async fn run_until_server_stops_returns_ok_when_fatal_channel_closes() {
        let (fatal_errors, fatal_receiver) = mpsc::unbounded_channel::<GatewayError>();
        drop(fatal_errors);

        let server_task = Box::pin(future::pending::<Result<(), io::Error>>());
        let result = run_until_server_stops(server_task, fatal_receiver).await;

        assert!(
            result.is_ok(),
            "a closed fatal channel should not stop the server with an error"
        );
    }

    #[test]
    fn request_body_errors_map_to_denial_reasons() {
        let error = RequestBodyError::Read {
            source: axum::Error::new(io::Error::other("read failed")),
        };

        assert_eq!(
            denial_reason_from_request_body(&error),
            AuditDenialReason::RequestBodyReadFailed
        );
        assert_eq!(
            denial_reason_from_request_body(&RequestBodyError::TooLarge),
            AuditDenialReason::RequestBodyTooLarge
        );
    }

    #[test]
    fn audit_denial_reason_mapping_preserves_statuses() {
        let reasons = [
            AuditDenialReason::AbsoluteFormUnsupported,
            AuditDenialReason::ConnectUnsupported,
            AuditDenialReason::DotSegment,
            AuditDenialReason::EncodedSeparator,
            AuditDenialReason::InvalidPercentEncoding,
            AuditDenialReason::InvalidRequestConnectionHeader,
            AuditDenialReason::MethodDenied,
            AuditDenialReason::NonOriginForm,
            AuditDenialReason::PathDenied,
            AuditDenialReason::PathTooLong,
            AuditDenialReason::QueryTooLong,
            AuditDenialReason::RequestBodyReadFailed,
            AuditDenialReason::RequestBodyTimeout,
            AuditDenialReason::RequestBodyTooLarge,
            AuditDenialReason::RequestHeadersTooLarge,
            AuditDenialReason::TooManyRequests,
        ];

        for reason in reasons {
            let denial = audit_denial_from_reason(
                Method::POST,
                AuditTarget::from_uri_parts("/v1/models", None),
                reason,
            );

            assert_eq!(denial.status(), reason.status());
        }
    }

    #[test]
    fn request_header_errors_map_to_denial_reasons() {
        assert_eq!(
            denial_reason_from_request_header(HeaderError::InvalidConnectionHeader),
            AuditDenialReason::InvalidRequestConnectionHeader
        );
        assert_eq!(
            denial_reason_from_request_header(HeaderError::TooLarge),
            AuditDenialReason::RequestHeadersTooLarge
        );
    }

    #[test]
    fn target_rejections_map_to_denial_reasons() {
        let cases = [
            (RejectionReason::DotSegment, AuditDenialReason::DotSegment),
            (
                RejectionReason::EncodedSeparator,
                AuditDenialReason::EncodedSeparator,
            ),
            (
                RejectionReason::InvalidPercentEncoding,
                AuditDenialReason::InvalidPercentEncoding,
            ),
            (
                RejectionReason::MethodDenied,
                AuditDenialReason::MethodDenied,
            ),
            (
                RejectionReason::NonOriginForm,
                AuditDenialReason::NonOriginForm,
            ),
            (RejectionReason::PathDenied, AuditDenialReason::PathDenied),
            (RejectionReason::PathTooLong, AuditDenialReason::PathTooLong),
            (
                RejectionReason::QueryTooLong,
                AuditDenialReason::QueryTooLong,
            ),
        ];

        for (rejection, denial) in cases {
            let audit_denial = audit_denial_from_rejection(
                Method::POST,
                AuditTarget::from_uri_parts("/v1/models", None),
                rejection,
            );

            assert_eq!(denial_reason_from_rejection(rejection), denial);
            assert_eq!(audit_denial.status(), denial.status());
        }
    }

    #[test]
    fn response_header_errors_map_to_audit_errors() {
        assert_eq!(
            audit_response_header_error(HeaderError::InvalidConnectionHeader),
            AuditResponseHeaderError::InvalidConnectionHeader
        );
        assert_eq!(
            audit_response_header_error(HeaderError::TooLarge),
            AuditResponseHeaderError::TooLarge
        );
    }

    #[test]
    fn upstream_errors_map_to_audit_errors() {
        let connect_error = UpstreamError::new(UpstreamErrorKind::Connect, "connect failed");

        assert_eq!(
            audit_upstream_error(&connect_error),
            AuditUpstreamError::Connect
        );
        let timeout_error = UpstreamError::new(UpstreamErrorKind::Timeout, "timed out");
        assert_eq!(
            audit_upstream_error(&timeout_error),
            AuditUpstreamError::Timeout
        );
        let request_error = UpstreamError::new(UpstreamErrorKind::Request, "protocol failed");
        assert_eq!(
            audit_upstream_error(&request_error),
            AuditUpstreamError::Request
        );
    }

    #[test]
    fn synthetic_target_preserves_absolute_form_targets() {
        let uri = Uri::from_static("http://evil.example/steal?limit=1");

        let target = synthetic_target(&uri);

        assert_eq!(target.path(), "http://evil.example/steal");
        assert_eq!(target.query(), Some("limit=1"));
    }

    #[test]
    fn synthetic_target_preserves_authority_form_targets() {
        let uri = Uri::from_static("evil.example:443");

        let target = synthetic_target(&uri);

        assert_eq!(target.path(), "evil.example:443");
        assert_eq!(target.query(), None);
    }

    #[test]
    fn synthetic_target_preserves_path_and_query() {
        let uri = Uri::from_static("/v1/models?limit=1");

        let target = synthetic_target(&uri);

        assert_eq!(target.path(), "/v1/models");
        assert_eq!(target.query(), Some("limit=1"));
    }

    #[tokio::test]
    async fn send_stream_error_prefers_audit_failures() {
        let (sender, mut receiver) = mpsc::channel(1);

        send_stream_error(
            &sender,
            Err(ResponseAuditFailure),
            StreamAbortReason::UpstreamBody,
        )
        .await;

        let outcome = receiver
            .recv()
            .await
            .expect("terminal error should be sent");
        let error = outcome.expect_err("terminal item should be an error");
        assert_eq!(error.to_string(), "audit_failed");
    }

    #[tokio::test]
    async fn send_stream_error_sends_the_stream_error_when_audit_succeeds() {
        let (sender, mut receiver) = mpsc::channel(1);

        send_stream_error(&sender, Ok(()), StreamAbortReason::UpstreamBody).await;

        let outcome = receiver
            .recv()
            .await
            .expect("terminal error should be sent");
        let error = outcome.expect_err("terminal item should be an error");
        assert_eq!(error.to_string(), "upstream_response_stream_failed");
    }

    #[tokio::test]
    async fn send_stream_error_tolerates_a_closed_receiver() {
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);

        send_stream_error(&sender, Ok(()), StreamAbortReason::ResponseBodyTooLarge).await;

        assert!(sender.is_closed(), "receiver should be gone");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn response_stream_audits_final_chunk_disconnects_before_allowed_completion() {
        let (audit, audit_events) = MemoryAuditSink::new();
        let config = GatewayConfig::for_runtime_test(
            PathBuf::from("unused-audit.ndjson"),
            "https://api.openai.com",
        );
        let target = allowed_target(&config, "/v1/models");
        let gateway = Gateway::from_ports(
            config,
            audit,
            FixedClock,
            SequentialRequestIds::new(RunToken::for_test("0000000000007e57-000000000000c0de")),
        );
        let request_body = AccountedBody::read_request(Body::empty(), request_body_limit(1))
            .await
            .expect("request body should be accounted");
        let response_account = ResponseAccount::new(response_body_limit(1_024));
        let (fatal_errors, mut fatal_receiver) = mpsc::unbounded_channel();
        let context = ResponseAuditContext {
            fatal_errors,
            gateway,
            request_body,
            request_id: RequestId::from_parts(
                &RunToken::for_test("0000000000007e57-000000000000c0de"),
                NonZeroU64::new(1).expect("sequence should be non-zero"),
            ),
            response_account,
            status: StatusCode::OK,
            target,
        };
        let upstream_body = stream::unfold(TwoChunkStep::First, |step| async move {
            match step {
                TwoChunkStep::End => {
                    sleep(Duration::from_secs(1)).await;
                    None
                }
                TwoChunkStep::First => Some((
                    Ok::<Bytes, UpstreamBodyError>(Bytes::from_static(b"first")),
                    TwoChunkStep::Second,
                )),
                TwoChunkStep::Second => Some((
                    Ok::<Bytes, UpstreamBodyError>(Bytes::from_static(b"second")),
                    TwoChunkStep::End,
                )),
            }
        });
        let upstream_response =
            UpstreamResponse::new(StatusCode::OK, HeaderMap::new(), upstream_body.boxed());
        let mut response_body = response_stream(context, upstream_response, test_permit());

        let first = response_body
            .next()
            .await
            .expect("first response chunk should be sent")
            .expect("first response chunk should be ok");
        assert_eq!(first, Bytes::from_static(b"first"));
        drop(response_body);
        advance(Duration::from_secs(1)).await;
        yield_now().await;

        let events = audit_events
            .lock()
            .expect("memory audit sink should not be poisoned")
            .clone();
        assert_eq!(events.len(), 1);
        let event = events.first().expect("disconnect should be audited");
        assert_eq!(event["decision"], "response_error");
        assert_eq!(event["error_class"], "downstream_closed");
        assert_eq!(event["response_body"], non_empty_body_value(b"firstsecond"));
        let fatal_result = fatal_receiver.try_recv();
        assert!(
            matches!(
                fatal_result,
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected)
            ),
            "unexpected fatal error: {fatal_result:?}"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn response_stream_reports_stream_errors_without_pending_chunks() {
        let (audit, audit_events) = MemoryAuditSink::new();
        let max_response_bytes = response_body_limit(1_024);
        let (context, mut fatal_receiver) = response_audit_context(audit, max_response_bytes).await;
        let upstream_body = stream::iter([Err(UpstreamBodyError::stream(
            "scripted upstream stream failed",
        ))]);
        let upstream_response =
            UpstreamResponse::new(StatusCode::OK, HeaderMap::new(), upstream_body.boxed());
        let mut response_body = response_stream(context, upstream_response, test_permit());

        let result = response_body
            .next()
            .await
            .expect("terminal stream error should be sent");

        let error = result.expect_err("terminal item should be an error");
        assert_eq!(error.to_string(), "upstream_response_stream_failed");
        assert!(
            response_body.next().await.is_none(),
            "stream should close after terminal error"
        );
        let events = audit_events
            .lock()
            .expect("memory audit sink should not be poisoned")
            .clone();
        assert_eq!(events.len(), 1);
        let event = events.first().expect("stream error should be audited");
        assert_eq!(event["decision"], "response_error");
        assert_eq!(event["error_class"], "upstream_response_stream_failed");
        let fatal_result = fatal_receiver.try_recv();
        assert!(
            matches!(
                fatal_result,
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected)
            ),
            "unexpected fatal error: {fatal_result:?}"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn response_stream_reports_body_timeouts_without_pending_chunks() {
        let (audit, audit_events) = MemoryAuditSink::new();
        let max_response_bytes = response_body_limit(1_024);
        let (context, mut fatal_receiver) = response_audit_context(audit, max_response_bytes).await;
        let upstream_body = stream::iter([Err(UpstreamBodyError::timeout(
            "scripted upstream body timeout",
        ))]);
        let upstream_response =
            UpstreamResponse::new(StatusCode::OK, HeaderMap::new(), upstream_body.boxed());
        let mut response_body = response_stream(context, upstream_response, test_permit());

        let result = response_body
            .next()
            .await
            .expect("terminal stream error should be sent");

        let error = result.expect_err("terminal item should be an error");
        assert_eq!(error.to_string(), "upstream_response_timeout");
        assert!(
            response_body.next().await.is_none(),
            "stream should close after terminal error"
        );
        let events = audit_events
            .lock()
            .expect("memory audit sink should not be poisoned")
            .clone();
        assert_eq!(events.len(), 1);
        let event = events.first().expect("timeout should be audited");
        assert_eq!(event["decision"], "response_error");
        assert_eq!(event["error_class"], "upstream_response_timeout");
        let fatal_result = fatal_receiver.try_recv();
        assert!(
            matches!(
                fatal_result,
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected)
            ),
            "unexpected fatal error: {fatal_result:?}"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn response_stream_audits_empty_successful_responses() {
        let (audit, audit_events) = MemoryAuditSink::new();
        let max_response_bytes = response_body_limit(1_024);
        let (context, mut fatal_receiver) = response_audit_context(audit, max_response_bytes).await;
        let upstream_body = stream::empty::<Result<Bytes, UpstreamBodyError>>();
        let upstream_response =
            UpstreamResponse::new(StatusCode::OK, HeaderMap::new(), upstream_body.boxed());
        let mut response_body = response_stream(context, upstream_response, test_permit());

        assert!(
            response_body.next().await.is_none(),
            "empty stream should complete without chunks"
        );

        let events = audit_events
            .lock()
            .expect("memory audit sink should not be poisoned")
            .clone();
        assert_eq!(events.len(), 1);
        let event = events.first().expect("empty success should be audited");
        assert_eq!(event["decision"], "allowed");
        assert_eq!(event["response_body"], empty_body_value());
        let fatal_result = fatal_receiver.try_recv();
        assert!(
            matches!(
                fatal_result,
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected)
            ),
            "unexpected fatal error: {fatal_result:?}"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn response_stream_sends_terminal_error_when_empty_allowed_audit_fails() {
        let fail_on_first = NonZeroUsize::new(1).expect("literal should be non-zero");
        let (audit, audit_events) = MemoryAuditSink::failing_on(fail_on_first);
        let audit_observer = audit.clone();
        let max_response_bytes = response_body_limit(1_024);
        let (context, mut fatal_receiver) = response_audit_context(audit, max_response_bytes).await;
        let upstream_body = stream::empty::<Result<Bytes, UpstreamBodyError>>();
        let upstream_response =
            UpstreamResponse::new(StatusCode::OK, HeaderMap::new(), upstream_body.boxed());
        let mut response_body = response_stream(context, upstream_response, test_permit());

        let outcome = response_body
            .next()
            .await
            .expect("terminal error should be sent");
        let error = outcome.expect_err("empty completion should report audit failure");

        assert_eq!(error.to_string(), "audit_failed");
        assert!(
            response_body.next().await.is_none(),
            "stream should close after terminal error"
        );
        assert_eq!(audit_observer.event_count(), 1);
        assert!(
            audit_events
                .lock()
                .expect("memory audit sink should not be poisoned")
                .is_empty()
        );
        let fatal = fatal_receiver
            .recv()
            .await
            .expect("audit failure should be reported");
        assert_scripted_fatal_audit_write(&fatal);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn response_stream_withholds_final_chunk_when_allowed_audit_fails() {
        let fail_on_first = NonZeroUsize::new(1).expect("literal should be non-zero");
        let (audit, audit_events) = MemoryAuditSink::failing_on(fail_on_first);
        let audit_observer = audit.clone();
        let max_response_bytes = response_body_limit(1_024);
        let (context, mut fatal_receiver) = response_audit_context(audit, max_response_bytes).await;
        let upstream_body =
            stream::once(async { Ok::<Bytes, UpstreamBodyError>(Bytes::from_static(b"final")) });
        let upstream_response =
            UpstreamResponse::new(StatusCode::OK, HeaderMap::new(), upstream_body.boxed());
        let mut response_body = response_stream(context, upstream_response, test_permit());

        let terminal = response_body
            .next()
            .await
            .expect("audit failure should be sent instead of final chunk");
        let error = terminal.expect_err("terminal item should be an audit error");
        assert_eq!(error.to_string(), "audit_failed");
        assert!(
            response_body.next().await.is_none(),
            "stream should close after terminal error"
        );
        assert_eq!(audit_observer.event_count(), 1);
        let events = audit_events
            .lock()
            .expect("memory audit sink should not be poisoned")
            .clone();
        assert!(events.is_empty());
        let fatal = fatal_receiver
            .recv()
            .await
            .expect("audit failure should be reported");
        assert_scripted_fatal_audit_write(&fatal);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn response_stream_finishes_started_final_audit_after_downstream_close() {
        let (audit, observers) = BlockingFirstAuditSink::new();
        let audit_observer = audit.clone();
        let max_response_bytes = response_body_limit(1_024);
        let (context, mut fatal_receiver) = response_audit_context(audit, max_response_bytes).await;
        let upstream_body =
            stream::once(async { Ok::<Bytes, UpstreamBodyError>(Bytes::from_static(b"final")) });
        let upstream_response =
            UpstreamResponse::new(StatusCode::OK, HeaderMap::new(), upstream_body.boxed());
        let response_body = response_stream(context, upstream_response, test_permit());

        observers.first_append_started.notified().await;
        drop(response_body);
        observers.release_first_append.notify_one();
        let mut events = Vec::new();
        for _attempt in 0_u8..10 {
            events = observers
                .events
                .lock()
                .expect("blocking audit sink should not be poisoned")
                .clone();
            if events.len() == 1 {
                break;
            }
            yield_now().await;
        }

        assert_eq!(audit_observer.event_count(), 1);
        assert_eq!(events.len(), 1);
        let event = events.first().expect("completion should be audited");
        assert_eq!(event["decision"], "allowed");
        assert_eq!(event["error_class"], Value::Null);
        assert_eq!(event["response_body"], non_empty_body_value(b"final"));
        let fatal_result = fatal_receiver.try_recv();
        assert!(
            matches!(
                fatal_result,
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected)
            ),
            "unexpected fatal error: {fatal_result:?}"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn response_stream_attempts_audit_when_pending_chunk_send_fails() {
        let fail_on_first = NonZeroUsize::new(1).expect("literal should be non-zero");
        let (audit, audit_events) = MemoryAuditSink::failing_on(fail_on_first);
        let audit_observer = audit.clone();
        let max_response_bytes = response_body_limit(1_024);
        let (context, mut fatal_receiver) = response_audit_context(audit, max_response_bytes).await;
        let upstream_body = stream::unfold(Some(false), |state| async move {
            match state {
                Some(false) => Some((
                    Ok::<Bytes, UpstreamBodyError>(Bytes::from_static(b"first")),
                    Some(true),
                )),
                Some(true) => {
                    sleep(Duration::from_secs(1)).await;
                    Some((
                        Err(UpstreamBodyError::stream("scripted upstream stream failed")),
                        None,
                    ))
                }
                None => None,
            }
        });
        let upstream_response =
            UpstreamResponse::new(StatusCode::OK, HeaderMap::new(), upstream_body.boxed());
        let response_body = response_stream(context, upstream_response, test_permit());

        yield_now().await;
        drop(response_body);
        advance(Duration::from_secs(1)).await;
        yield_now().await;

        assert_eq!(audit_observer.event_count(), 1);
        let events = audit_events
            .lock()
            .expect("memory audit sink should not be poisoned")
            .clone();
        assert!(events.is_empty());
        let fatal = fatal_receiver
            .recv()
            .await
            .expect("audit failure should be reported");
        assert_scripted_fatal_audit_write(&fatal);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn response_stream_preserves_upstream_errors_when_pending_chunk_send_fails() {
        let (audit, audit_events) = MemoryAuditSink::new();
        let audit_observer = audit.clone();
        let max_response_bytes = response_body_limit(1_024);
        let (context, mut fatal_receiver) = response_audit_context(audit, max_response_bytes).await;
        let upstream_body = stream::unfold(Some(false), |state| async move {
            match state {
                Some(false) => Some((
                    Ok::<Bytes, UpstreamBodyError>(Bytes::from_static(b"first")),
                    Some(true),
                )),
                Some(true) => {
                    sleep(Duration::from_secs(1)).await;
                    Some((
                        Err(UpstreamBodyError::stream("scripted upstream stream failed")),
                        None,
                    ))
                }
                None => None,
            }
        });
        let upstream_response =
            UpstreamResponse::new(StatusCode::OK, HeaderMap::new(), upstream_body.boxed());
        let response_body = response_stream(context, upstream_response, test_permit());

        yield_now().await;
        drop(response_body);
        advance(Duration::from_secs(1)).await;
        yield_now().await;

        assert_eq!(audit_observer.event_count(), 1);
        let events = audit_events
            .lock()
            .expect("memory audit sink should not be poisoned")
            .clone();
        assert_eq!(events.len(), 1);
        let event = events.first().expect("upstream failure should be audited");
        assert_eq!(event["decision"], "response_error");
        assert_eq!(event["error_class"], "upstream_response_stream_failed");
        let fatal_result = fatal_receiver.try_recv();
        assert!(
            matches!(
                fatal_result,
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected)
            ),
            "unexpected fatal error: {fatal_result:?}"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn response_stream_attempts_audit_when_final_chunk_send_fails() {
        let fail_on_first = NonZeroUsize::new(1).expect("literal should be non-zero");
        let (audit, audit_events) = MemoryAuditSink::failing_on(fail_on_first);
        let audit_observer = audit.clone();
        let max_response_bytes = response_body_limit(1_024);
        let (context, mut fatal_receiver) = response_audit_context(audit, max_response_bytes).await;
        let upstream_body = stream::unfold(false, |sent| async move {
            if sent {
                sleep(Duration::from_secs(1)).await;
                None
            } else {
                Some((
                    Ok::<Bytes, UpstreamBodyError>(Bytes::from_static(b"final")),
                    true,
                ))
            }
        });
        let upstream_response =
            UpstreamResponse::new(StatusCode::OK, HeaderMap::new(), upstream_body.boxed());
        let response_body = response_stream(context, upstream_response, test_permit());

        yield_now().await;
        drop(response_body);
        advance(Duration::from_secs(1)).await;
        yield_now().await;

        assert_eq!(audit_observer.event_count(), 1);
        let events = audit_events
            .lock()
            .expect("memory audit sink should not be poisoned")
            .clone();
        assert!(events.is_empty());
        let fatal = fatal_receiver
            .recv()
            .await
            .expect("audit failure should be reported");
        assert_scripted_fatal_audit_write(&fatal);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn response_stream_audits_final_chunk_send_failures() {
        let (audit, audit_events) = MemoryAuditSink::new();
        let max_response_bytes = response_body_limit(1_024);
        let (context, mut fatal_receiver) = response_audit_context(audit, max_response_bytes).await;
        let upstream_body = stream::unfold(false, |sent| async move {
            if sent {
                sleep(Duration::from_secs(1)).await;
                None
            } else {
                Some((
                    Ok::<Bytes, UpstreamBodyError>(Bytes::from_static(b"final")),
                    true,
                ))
            }
        });
        let upstream_response =
            UpstreamResponse::new(StatusCode::OK, HeaderMap::new(), upstream_body.boxed());
        let response_body = response_stream(context, upstream_response, test_permit());

        yield_now().await;
        drop(response_body);
        advance(Duration::from_secs(1)).await;
        yield_now().await;

        let events = audit_events
            .lock()
            .expect("memory audit sink should not be poisoned")
            .clone();
        assert_eq!(events.len(), 1);
        let event = events.first().expect("disconnect should be audited");
        assert_eq!(event["decision"], "response_error");
        assert_eq!(event["error_class"], "downstream_closed");
        assert_eq!(event["response_body"], non_empty_body_value(b"final"));
        let fatal_result = fatal_receiver.try_recv();
        assert!(
            matches!(
                fatal_result,
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected)
            ),
            "unexpected fatal error: {fatal_result:?}"
        );
    }

    #[test]
    fn report_fatal_error_tolerates_a_closed_channel() {
        let (fatal_errors, receiver) = mpsc::unbounded_channel();
        drop(receiver);

        report_fatal_error(
            &fatal_errors,
            GatewayError::Audit(AuditError::EventTooLarge { bytes: 2, max: 1 }),
        );

        assert!(fatal_errors.is_closed(), "receiver should be gone");
    }

    #[tokio::test]
    async fn audit_after_response_started_reports_fatal_error() {
        let directory = tempdir().expect("temporary directory should be created");
        let config = GatewayConfig::for_test(
            directory.path().join("audit.ndjson"),
            NonZeroUsize::new(1).expect("limit should be non-zero"),
        );
        let target = allowed_target(&config, "/v1/models");
        let gateway = production_gateway(config, fixed_request_ids())
            .await
            .expect("gateway should initialize");
        let request_body = AccountedBody::read_request(Body::empty(), request_body_limit(1))
            .await
            .expect("request body should be accounted");
        let mut response_account = ResponseAccount::new(response_body_limit(1_024));
        response_account
            .add_chunk(b"hello")
            .expect("response chunk should be accounted");
        let (fatal_errors, mut fatal_receiver) = mpsc::unbounded_channel();
        let context = ResponseAuditContext {
            fatal_errors,
            gateway,
            request_body,
            request_id: RequestId::from_parts(
                &RunToken::for_test("0000000000007e57-000000000000c0de"),
                NonZeroU64::new(1).expect("sequence should be non-zero"),
            ),
            response_account,
            status: StatusCode::OK,
            target,
        };

        let result = context
            .audit_after_response_started(ResponseStreamOutcome::Allowed)
            .await;
        let fatal = fatal_receiver
            .recv()
            .await
            .expect("fatal error should be reported");

        assert!(result.is_err());
        assert_fatal_event_too_large(&fatal, 481, 1);
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

        let server_task = Box::pin(future::pending::<Result<(), io::Error>>());
        let result = run_until_server_stops(server_task, fatal_receiver).await;

        assert!(matches!(
            result,
            Err(ServeError::Gateway(GatewayError::Audit(
                AuditError::EventTooLarge { bytes: 2, max: 1 },
            ))),
        ));
    }
}
