//! Axum request and response wiring.

use crate::adapters::{
    ReqwestUpstreamClient, SequentialRequestIds, SystemClock, UpstreamClientBuildError,
};
use crate::allowlist::{AcceptedTarget, AllowedTarget, RejectionReason, allow_target};
use crate::audit::{
    AuditDenialReason, AuditResponseHeaderError, AuditTarget, AuditUpstreamError, AuditWriter,
    RequestId,
};
use crate::body::{AccountedBody, RequestBodyError, ResponseAccount};
use crate::config::GatewayConfig;
use crate::gateway::{Gateway, GatewayError, ResponseAuditInput, ResponseAuditOutcome};
use crate::headers::{
    ForwardedRequestHeaders, HeaderError, forward_request_headers, forward_response_headers,
};
use crate::ports::{
    UpstreamClient, UpstreamDeadline, UpstreamError, UpstreamErrorKind, UpstreamRequest,
    UpstreamResponse,
};
use ::http::{Method, Uri};
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{Request, Response, StatusCode};
use axum::response::IntoResponse as _;
use axum::{Router, routing::any};
use core::convert::Infallible;
use core::future::IntoFuture;
use futures_util::StreamExt as _;
use futures_util::future::{self, Either};
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
    #[error("{0}")]
    Client(UpstreamClientBuildError),

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
    client: Arc<dyn UpstreamClient>,
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

/// Terminal response stream outcome.
#[derive(Debug)]
enum ResponseStreamOutcome {
    /// Response completed successfully.
    Allowed,

    /// Downstream closed before the response completed.
    DownstreamClosed,

    /// Response body exceeded the configured byte limit.
    ResponseBodyTooLarge,

    /// Upstream response stream failed after upstream I/O started.
    UpstreamResponseStreamFailed,
}

impl ResponseAuditContext {
    /// Writes the terminal response audit event.
    async fn audit(self, stream_outcome: ResponseStreamOutcome) -> Result<(), GatewayError> {
        let Self {
            gateway,
            request_body,
            request_id,
            response_account,
            status,
            target,
            ..
        } = self;
        let audit_outcome = match stream_outcome {
            ResponseStreamOutcome::Allowed => {
                ResponseAuditOutcome::allowed(response_account, status)
            }
            ResponseStreamOutcome::DownstreamClosed => {
                ResponseAuditOutcome::downstream_closed(response_account, status)
            }
            ResponseStreamOutcome::ResponseBodyTooLarge => {
                ResponseAuditOutcome::response_body_too_large(response_account, status)
            }
            ResponseStreamOutcome::UpstreamResponseStreamFailed => {
                ResponseAuditOutcome::upstream_response_stream_failed(response_account, status)
            }
        };
        let input = ResponseAuditInput::new(target, audit_outcome, request_body, request_id);
        gateway.audit_response(input).await
    }

    /// Writes the terminal response audit event or reports a fatal error.
    async fn audit_after_response_started(
        self,
        outcome: ResponseStreamOutcome,
    ) -> Result<(), String> {
        let fatal_errors = self.fatal_errors.clone();
        match self.audit(outcome).await {
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
) -> Result<Result<AllowedTarget, Response<Body>>, GatewayError> {
    if method == Method::CONNECT {
        let target = synthetic_target(uri);
        gateway
            .audit_denial(
                request_id.clone(),
                method,
                target,
                None,
                AuditDenialReason::ConnectUnsupported,
            )
            .await?;
        return Ok(Err(status_response(
            AuditDenialReason::ConnectUnsupported.status(),
        )));
    }

    if uri.authority().is_some() {
        let target = synthetic_target(uri);
        gateway
            .audit_denial(
                request_id.clone(),
                method,
                target,
                None,
                AuditDenialReason::AbsoluteFormUnsupported,
            )
            .await?;
        return Ok(Err(status_response(
            AuditDenialReason::AbsoluteFormUnsupported.status(),
        )));
    }

    let target = match AcceptedTarget::new(uri.path(), uri.query()) {
        Ok(target) => target,
        Err(reason) => {
            let denial = denial_reason_from_rejection(reason);
            let target = synthetic_target(uri);
            gateway
                .audit_denial(request_id.clone(), method, target, None, denial)
                .await?;
            return Ok(Err(status_response(denial.status())));
        }
    };

    match allow_target(gateway.config(), method, target.clone()) {
        Ok(allowed_target) => Ok(Ok(allowed_target)),
        Err(reason) => {
            let denial = denial_reason_from_rejection(reason);
            gateway
                .audit_denial(request_id.clone(), method, target.into(), None, denial)
                .await?;
            Ok(Err(status_response(denial.status())))
        }
    }
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
                    AuditDenialReason::TooManyRequests,
                )
                .await
                .is_err()
            {
                return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
            return Ok(AuditDenialReason::TooManyRequests.status().into_response());
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
    client: Arc<dyn UpstreamClient>,
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
                let reason = denial_reason_from_request_header(error);
                gateway
                    .audit_denial(
                        request_id,
                        &method,
                        target.target().clone().into(),
                        None,
                        reason,
                    )
                    .await?;
                return Ok(status_response(reason.status()));
            }
        };

    let request_body =
        match AccountedBody::read_request(body, gateway.config().max_request_bytes()).await {
            Ok(request_body) => request_body,
            Err(error) => {
                let reason = denial_reason_from_request_body(&error);
                gateway
                    .audit_denial(
                        request_id,
                        &method,
                        target.target().clone().into(),
                        None,
                        reason,
                    )
                    .await?;
                return Ok(status_response(reason.status()));
            }
        };

    forward_request(
        fatal_errors,
        gateway,
        client,
        request_id,
        target,
        request_headers,
        request_body,
    )
    .await
}

/// Forwards an accepted request to the configured upstream.
async fn forward_request(
    fatal_errors: mpsc::UnboundedSender<GatewayError>,
    gateway: Gateway,
    client: Arc<dyn UpstreamClient>,
    request_id: RequestId,
    target: AllowedTarget,
    request_headers: ForwardedRequestHeaders,
    request_body: AccountedBody,
) -> Result<Response<Body>, GatewayError> {
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
            let input = ResponseAuditInput::new(target, outcome, request_body, request_id);
            gateway.audit_response(input).await?;
            return Ok(status_response(audit_error.status()));
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
            let input = ResponseAuditInput::new(target, outcome, request_body, request_id);
            gateway.audit_response(input).await?;
            return Ok(status_response(audit_error.status()));
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
    upstream_response: UpstreamResponse,
) -> ReceiverStream<Result<Bytes, io::Error>> {
    let (sender, receiver) = mpsc::channel(8);

    tokio::spawn(async move {
        let mut stream = upstream_response.into_body();
        let mut pending = None;
        while let Some(chunk_result) = stream.next().await {
            let chunk = match chunk_result {
                Ok(bytes) => bytes,
                Err(upstream_body_error) => {
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
                    send_stream_error(
                        &sender,
                        context
                            .audit_after_response_started(
                                ResponseStreamOutcome::UpstreamResponseStreamFailed,
                            )
                            .await,
                        upstream_body_error.to_string(),
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
                let error_class = "response_body_too_large".to_owned();
                send_stream_error(
                    &sender,
                    context
                        .audit_after_response_started(ResponseStreamOutcome::ResponseBodyTooLarge)
                        .await,
                    error_class,
                )
                .await;
                return;
            }

            pending = Some(chunk);
        }

        if let Some(final_chunk) = pending
            && sender.send(Ok(final_chunk)).await.is_err()
        {
            if let Err(audit_error) = context
                .audit_after_response_started(ResponseStreamOutcome::DownstreamClosed)
                .await
            {
                tracing::error!(%audit_error, "failed to audit downstream close");
            }
            return;
        }

        if let Err(error) = context
            .audit_after_response_started(ResponseStreamOutcome::Allowed)
            .await
        {
            send_stream_error(&sender, Err(error), "audit failed".to_owned()).await;
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
    let client = ReqwestUpstreamClient::new().map_err(ServeError::Client)?;
    let gateway = production_gateway(config)
        .await
        .map_err(ServeError::Gateway)?;
    let (fatal_errors, fatal_receiver) = mpsc::unbounded_channel();
    let state = AppState {
        client: Arc::new(client),
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

/// Builds a gateway from production adapters.
///
/// # Errors
///
/// Returns an error when the audit log cannot be opened.
async fn production_gateway(config: GatewayConfig) -> Result<Gateway, GatewayError> {
    let audit = AuditWriter::open(&config).await?;
    Ok(Gateway::from_ports(
        config,
        audit,
        SystemClock,
        SequentialRequestIds::production(),
    ))
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

/// Maps accepted-target rejection reasons to closed denial reasons.
const fn denial_reason_from_rejection(reason: RejectionReason) -> AuditDenialReason {
    match reason {
        RejectionReason::DotSegment => AuditDenialReason::DotSegment,
        RejectionReason::InvalidPercentEncoding => AuditDenialReason::InvalidPercentEncoding,
        RejectionReason::MethodDenied => AuditDenialReason::MethodDenied,
        RejectionReason::NonOriginForm => AuditDenialReason::NonOriginForm,
        RejectionReason::PathDenied => AuditDenialReason::PathDenied,
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
        use super::{ScenarioBody, ScenarioRun, run_scenario};
        use crate::sim::{
            Scenario, ScenarioAdmission, ScenarioAudit, ScenarioBounds, ScenarioClass,
            ScenarioDownstream, ScenarioRequest, ScenarioUpstream, scenario_any,
        };
        use axum::body::Bytes;
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
                    ScenarioAudit::FailFirst,
                    _,
                    _,
                    ScenarioUpstream::Respond | ScenarioUpstream::StreamError,
                ) => ScenarioBody::Error(
                    "failed to write audit event: scripted audit failure".to_owned(),
                ),
                (
                    ScenarioAdmission::Open,
                    ScenarioAudit::Record,
                    ScenarioBounds::TinyResponse,
                    _,
                    ScenarioUpstream::Respond | ScenarioUpstream::StreamError,
                ) => ScenarioBody::Error("response_body_too_large".to_owned()),
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
                    ScenarioBounds::Roomy,
                    ScenarioDownstream::DropBeforeFirstChunk,
                    ScenarioUpstream::Respond,
                ) => ScenarioBody::Dropped(Bytes::new()),
                (
                    ScenarioAdmission::Open,
                    ScenarioAudit::Record,
                    ScenarioBounds::Roomy,
                    ScenarioDownstream::DropBeforeFinalChunk,
                    ScenarioUpstream::Respond,
                ) => ScenarioBody::Dropped(Bytes::from_static(b"script")),
                (
                    ScenarioAdmission::Open,
                    ScenarioAudit::Record,
                    ScenarioBounds::Roomy,
                    _,
                    ScenarioUpstream::StreamError,
                ) => ScenarioBody::Error("scripted upstream stream failed".to_owned()),
            }
        }

        /// Returns true when the scenario should report a fatal post-start error.
        fn expected_fatal_error(scenario: &Scenario) -> bool {
            scenario.admission() == ScenarioAdmission::Open
                && scenario.audit() == ScenarioAudit::FailFirst
                && scenario.upstream() != ScenarioUpstream::Timeout
        }

        /// Returns the expected status for the harness response.
        fn expected_status(scenario: &Scenario) -> StatusCode {
            match (scenario.admission(), scenario.audit(), scenario.upstream()) {
                (ScenarioAdmission::Saturated, ScenarioAudit::FailFirst, _)
                | (ScenarioAdmission::Open, ScenarioAudit::FailFirst, ScenarioUpstream::Timeout) => {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
                (ScenarioAdmission::Saturated, ScenarioAudit::Record, _) => {
                    StatusCode::TOO_MANY_REQUESTS
                }
                (ScenarioAdmission::Open, _, ScenarioUpstream::Timeout) => {
                    StatusCode::GATEWAY_TIMEOUT
                }
                (
                    ScenarioAdmission::Open,
                    _,
                    ScenarioUpstream::Respond | ScenarioUpstream::StreamError,
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

        /// Returns the request query field from a generated target.
        fn query_value(target: &str) -> Value {
            target
                .split_once('?')
                .map_or(Value::Null, |(_path, query)| {
                    Value::String(query.to_owned())
                })
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

        /// Returns the request path from a generated target.
        fn request_path(target: &str) -> &str {
            target.split_once('?').map_or(target, |(path, _query)| path)
        }

        /// Asserts the audit event invariants for one generated scenario.
        fn prop_assert_audit_event(
            scenario: &Scenario,
            run: &ScenarioRun,
        ) -> Result<(), TestCaseError> {
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
            let path = request_path(scenario.request().target());
            let query = query_value(scenario.request().target());
            prop_assert_eq!(&object["decision"], &Value::String(decision.to_owned()));
            prop_assert_eq!(&object["error_class"], &error_class);
            prop_assert_eq!(
                &object["method"],
                &Value::String(scenario.request().method().as_str().to_owned())
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
                prop_assert_eq!(&object["upstream_path"], &Value::String(path.to_owned()));
                prop_assert_eq!(&object["upstream_query"], &query);
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
            prop_assert_eq!(run.fatal_error.is_some(), expected_fatal_error(scenario));
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
            prop_assert_eq!(request.method(), scenario.request().method());
            prop_assert_eq!(
                request.url(),
                format!("https://api.openai.com{}", scenario.request().target())
            );
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

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: 32,
                ..ProptestConfig::default()
            })]

            #[test]
            fn generated_scenarios_satisfy_gateway_invariants(scenario in scenario_any()) {
                let run = run_generated_scenario(scenario.clone());

                prop_assert_scenario(&scenario, &run)?;
            }
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
                        Method::GET,
                        "/v1/models?limit=1",
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
    }

    use super::{
        AppState, ResponseAuditContext, ResponseStreamOutcome, ServeError,
        audit_response_header_error, audit_upstream_error, denial_reason_from_request_body,
        denial_reason_from_request_header, production_gateway, proxy, report_fatal_error,
        response_stream, run_until_server_stops, send_stream_error, serve, synthetic_target,
    };
    use crate::adapters::{ReqwestUpstreamClient, SequentialRequestIds};
    use crate::allowlist::{AcceptedTarget, AllowedTarget, allow_target};
    use crate::audit::{
        AuditDenialReason, AuditError, AuditResponseHeaderError, AuditUpstreamError, RequestId,
    };
    use crate::body::{AccountedBody, RequestBodyError, ResponseAccount};
    use crate::config::{GatewayConfig, ServeArgs};
    use crate::gateway::{Gateway, GatewayError};
    use crate::headers::HeaderError;
    use crate::ports::{
        UpstreamBodyError, UpstreamDeadline, UpstreamError, UpstreamErrorKind, UpstreamResponse,
    };
    use crate::sim::{
        FixedClock, MemoryAuditSink, RecordedUpstreamRequest, Scenario, ScenarioAdmission,
        ScenarioBounds, ScenarioDownstream, ScenarioRequest, ScenarioUpstream,
        ScriptedUpstreamClient,
    };
    use ::http::{Method, Uri};
    use axum::body::{Body, Bytes, to_bytes};
    use axum::http::{HeaderMap, Request, StatusCode};
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
    use reqwest::Client;
    use serde_json::{Map, Value};
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::fs::read_to_string;
    use tokio::net::TcpListener;
    use tokio::sync::{Semaphore, mpsc};
    use tokio::task::yield_now;
    use tokio::time::{Instant, advance, sleep};
    use tower::ServiceExt as _;

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
        /// Captured audit events.
        audit_events: Vec<Value>,
        /// Upstream deadline used by the gateway.
        deadline: UpstreamDeadline,
        /// Fatal gateway error reported after response start.
        fatal_error: Option<String>,
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

    /// Builds an allowlist witness for response audit tests.
    fn allowed_target(config: &GatewayConfig, path: &str) -> AllowedTarget {
        let target = AcceptedTarget::new(path, None).expect("target should parse");
        allow_target(config, &Method::GET, target).expect("target should be allowed")
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
        Router::new().route("/v1/models", get(|| async { "hello" }))
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
                Value::String("req-test-0000000000000001".to_owned()),
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
                Value::String("req-test-0000000000000001".to_owned()),
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

    /// Builds the proxy router and fatal error channel around a configuration.
    async fn proxy_router(
        config: GatewayConfig,
        permits: usize,
    ) -> (Router, mpsc::UnboundedReceiver<GatewayError>) {
        let client = ReqwestUpstreamClient::new().expect("upstream client should build");
        let gateway = production_gateway(config)
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
        let (client, upstream_recorder) =
            ScriptedUpstreamClient::from_upstream(scenario.upstream());
        let mut config = GatewayConfig::for_runtime_test(
            PathBuf::from("unused-audit.ndjson"),
            "https://api.openai.com",
        );
        if scenario.bounds() == ScenarioBounds::TinyResponse {
            config = config
                .with_max_response_bytes(NonZeroU64::new(4).expect("literal should be non-zero"));
        }
        let deadline = UpstreamDeadline::from_timeout(config.request_timeout());
        let gateway =
            Gateway::from_ports(config, audit, FixedClock, SequentialRequestIds::new("test"));
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
            .method(request_shape.method().clone())
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
        let fatal_error = fatal_receiver
            .try_recv()
            .ok()
            .map(|error| error.to_string());

        ScenarioRun {
            audit_events: captured_audit_events,
            deadline,
            fatal_error,
            response_body,
            status,
            upstream_requests: captured_upstream_requests,
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
                Method::GET,
                "/v1/models?limit=1",
            ),
            ScenarioUpstream::Respond,
        );

        let run = run_scenario(scenario).await;

        assert_eq!(run.status, StatusCode::CREATED);
        assert_eq!(
            run.response_body,
            ScenarioBody::Complete(Bytes::from_static(b"scripted"))
        );
        assert_eq!(run.fatal_error, None);
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
    async fn proxy_uses_injected_ports_for_allowed_requests() {
        let (audit, audit_events) = MemoryAuditSink::new();
        let (client, upstream_requests) = ScriptedUpstreamClient::new();
        let config = GatewayConfig::for_runtime_test(
            PathBuf::from("unused-audit.ndjson"),
            "https://api.openai.com",
        );
        let deadline = UpstreamDeadline::from_timeout(config.request_timeout());
        let gateway =
            Gateway::from_ports(config, audit, FixedClock, SequentialRequestIds::new("test"));
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
        let gateway =
            Gateway::from_ports(config, audit, FixedClock, SequentialRequestIds::new("test"));
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
        let (_audit_log, audit_text) = audit_paths(directory.path());
        let config = config_from_args(&[
            "--upstream-origin",
            &upstream,
            "--allowed-operations",
            "GET:exact:/v1/models",
            "--audit-log",
            &audit_text,
            "--bind",
            "127.0.0.1:0",
            "--max-audit-event-bytes",
            "1",
        ]);
        let (router, mut fatal_receiver) = proxy_router(config, 1).await;

        let response = router
            .oneshot(build_request(Method::GET, "/v1/models"))
            .await
            .expect("proxy should respond");

        let error = to_bytes(response.into_body(), 1_024)
            .await
            .expect_err("completion audit failure should fail the response body");
        assert!(
            error.to_string().contains("audit event has"),
            "response body error should report the audit failure: {error}"
        );
        let fatal = fatal_receiver
            .recv()
            .await
            .expect("fatal error should be reported");
        assert!(
            matches!(fatal, GatewayError::Audit(AuditError::EventTooLarge { .. })),
            "completion audit failure should be fatal"
        );
    }

    #[tokio::test]
    async fn proxy_reports_a_fatal_error_when_the_disconnect_audit_fails() {
        let directory = tempdir().expect("temporary directory should be created");
        let upstream = spawn_upstream(slow_upstream_router()).await;
        let (_audit_log, audit_text) = audit_paths(directory.path());
        let config = config_from_args(&[
            "--upstream-origin",
            &upstream,
            "--allowed-operations",
            "GET:exact:/v1/models",
            "--audit-log",
            &audit_text,
            "--bind",
            "127.0.0.1:0",
            "--max-audit-event-bytes",
            "1",
        ]);
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
        assert!(
            matches!(fatal, GatewayError::Audit(AuditError::EventTooLarge { .. })),
            "disconnect audit failure should be fatal"
        );
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

        let result =
            run_until_server_stops(future::ready(Ok::<(), io::Error>(())), fatal_receiver).await;

        assert!(result.is_ok(), "a finished server should stop serving");
    }

    #[tokio::test]
    async fn run_until_server_stops_returns_server_error() {
        let (_fatal_errors, fatal_receiver) = mpsc::unbounded_channel::<GatewayError>();

        let result = run_until_server_stops(
            future::ready(Err::<(), io::Error>(io::Error::other("boom"))),
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

        let result =
            run_until_server_stops(future::pending::<Result<(), io::Error>>(), fatal_receiver)
                .await;

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
            Err("audit failed".to_owned()),
            "stream failed".to_owned(),
        )
        .await;

        let outcome = receiver
            .recv()
            .await
            .expect("terminal error should be sent");
        let error = outcome.expect_err("terminal item should be an error");
        assert_eq!(error.to_string(), "audit failed");
    }

    #[tokio::test]
    async fn send_stream_error_sends_the_stream_error_when_audit_succeeds() {
        let (sender, mut receiver) = mpsc::channel(1);

        send_stream_error(&sender, Ok(()), "stream failed".to_owned()).await;

        let outcome = receiver
            .recv()
            .await
            .expect("terminal error should be sent");
        let error = outcome.expect_err("terminal item should be an error");
        assert_eq!(error.to_string(), "stream failed");
    }

    #[tokio::test]
    async fn send_stream_error_tolerates_a_closed_receiver() {
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);

        send_stream_error(&sender, Ok(()), "stream failed".to_owned()).await;

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
        let gateway =
            Gateway::from_ports(config, audit, FixedClock, SequentialRequestIds::new("test"));
        let request_body = AccountedBody::read_request(
            Body::empty(),
            NonZeroUsize::new(1).expect("limit should be non-zero"),
        )
        .await
        .expect("request body should be accounted");
        let response_account =
            ResponseAccount::new(NonZeroU64::new(1_024).expect("limit should be non-zero"));
        let (fatal_errors, mut fatal_receiver) = mpsc::unbounded_channel();
        let context = ResponseAuditContext {
            fatal_errors,
            gateway,
            request_body,
            request_id: RequestId::from_parts("test", 1),
            response_account,
            status: StatusCode::OK,
            target,
        };
        let upstream_body = stream::unfold(0_u8, |step| async move {
            match step {
                0 => Some((
                    Ok::<Bytes, UpstreamBodyError>(Bytes::from_static(b"first")),
                    1,
                )),
                1 => Some((
                    Ok::<Bytes, UpstreamBodyError>(Bytes::from_static(b"second")),
                    2,
                )),
                2 => {
                    sleep(Duration::from_secs(1)).await;
                    None
                }
                _ => None,
            }
        });
        let upstream_response =
            UpstreamResponse::new(StatusCode::OK, HeaderMap::new(), upstream_body.boxed());
        let mut response_body = response_stream(context, upstream_response);

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
        let gateway = production_gateway(config)
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
            request_body,
            request_id: RequestId::from_parts("test", 1),
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
