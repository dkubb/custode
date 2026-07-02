//! Request handling state machine.

use crate::allowlist::AcceptedTarget;
use crate::audit::{
    AuditDecision, AuditError, AuditEvent, AuditEventInput, AuditTarget, AuditWriter, RequestId,
};
use crate::body::{AccountedBody, BodyError, ResponseAccount};
use crate::config::{ConfigError, GatewayConfig};
use crate::headers::HeaderError;
use ::http::{Error as HttpError, Method};
use core::sync::atomic::{AtomicU64, Ordering};
use reqwest::Client;
use std::io;
use std::process;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Shared gateway state.
#[derive(Clone, Debug)]
pub(crate) struct Gateway {
    /// Audit log writer.
    audit: AuditWriter,
    /// Upstream HTTP client.
    client: Client,
    /// Parsed gateway configuration.
    config: Arc<GatewayConfig>,
    /// Monotonic request sequence.
    request_sequence: Arc<AtomicU64>,
    /// Per-process run token embedded in request identities.
    run_token: Arc<str>,
}

/// Gateway runtime error.
#[derive(Debug, Error)]
pub(crate) enum GatewayError {
    /// Audit log failed.
    #[error("{0}")]
    Audit(#[from] AuditError),

    /// Body accounting failed.
    #[error("{0}")]
    Body(#[from] BodyError),

    /// Upstream client could not be built.
    #[error("failed to build upstream client: {0}")]
    Client(reqwest::Error),

    /// Upstream URL construction failed.
    #[error("{0}")]
    Config(#[from] ConfigError),

    /// Header filtering failed.
    #[error("{0}")]
    Header(#[from] HeaderError),

    /// Gateway response could not be built.
    #[error("failed to build response: {0}")]
    ResponseBuild(HttpError),

    /// Gateway server failed.
    #[error("gateway server failed: {0}")]
    Server(io::Error),

    /// Gateway listener could not bind.
    #[error("failed to bind gateway listener: {0}")]
    ServerBind(io::Error),
}

/// Input for response audit events.
#[derive(Debug)]
pub(crate) struct ResponseAuditInput {
    /// Audit decision.
    pub decision: AuditDecision,
    /// Error class.
    pub error_class: Option<String>,
    /// Method.
    pub method: String,
    /// Accounted request body.
    pub request_body: AccountedBody,
    /// Request identity.
    pub request_id: RequestId,
    /// Accounted response body.
    pub response_account: ResponseAccount,
    /// Response status.
    pub status: Option<u16>,
    /// Accepted target.
    pub target: AcceptedTarget,
    /// Upstream path.
    pub upstream_path: String,
    /// Upstream query.
    pub upstream_query: Option<String>,
}

impl Gateway {
    /// Writes an audit event for a denied request.
    ///
    /// # Errors
    ///
    /// Returns an error when writing the audit event fails.
    pub(crate) async fn audit_denial(
        &self,
        request_id: RequestId,
        method: &Method,
        target: AuditTarget,
        request_body: Option<&AccountedBody>,
        error_class: &'static str,
        status: u16,
    ) -> Result<(), GatewayError> {
        let event = AuditEvent::new(AuditEventInput {
            decision: AuditDecision::Denied,
            error_class: Some(error_class.to_owned()),
            method: method.to_string(),
            request_body_blake3: request_body.and_then(|body| body.digest().map(str::to_owned)),
            request_bytes: request_body.map_or(0, AccountedBody::byte_count),
            request_id,
            response_body_blake3: None,
            response_bytes: 0,
            status: Some(status),
            target,
            upstream_origin: self.config.upstream_origin().as_str().to_owned(),
            upstream_path: None,
            upstream_query: None,
        });
        self.audit.write_event(&event).await?;
        Ok(())
    }

    /// Writes an audit event for a completed upstream response.
    ///
    /// # Errors
    ///
    /// Returns an error when writing the audit event fails.
    pub(crate) async fn audit_response(
        &self,
        input: ResponseAuditInput,
    ) -> Result<(), GatewayError> {
        let event = AuditEvent::new(AuditEventInput {
            decision: input.decision,
            error_class: input.error_class,
            method: input.method,
            request_body_blake3: input.request_body.digest().map(str::to_owned),
            request_bytes: input.request_body.byte_count(),
            request_id: input.request_id,
            response_body_blake3: input.response_account.finalize_digest(),
            response_bytes: input.response_account.byte_count(),
            status: input.status,
            target: input.target.into(),
            upstream_origin: self.config.upstream_origin().as_str().to_owned(),
            upstream_path: Some(input.upstream_path),
            upstream_query: input.upstream_query,
        });
        self.audit.write_event(&event).await?;
        Ok(())
    }

    /// Returns the upstream HTTP client.
    #[must_use]
    pub(crate) const fn client(&self) -> &Client {
        &self.client
    }

    /// Returns the parsed configuration.
    #[must_use]
    pub(crate) fn config(&self) -> &GatewayConfig {
        &self.config
    }

    /// Builds a gateway from parsed configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when audit log or upstream client setup fails.
    pub(crate) async fn new(config: GatewayConfig) -> Result<Self, GatewayError> {
        let audit = AuditWriter::open(&config).await?;
        let client = Client::builder()
            .timeout(config.request_timeout())
            .build()
            .map_err(GatewayError::Client)?;
        let run_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should not be before the Unix epoch")
            .as_nanos();
        // The process id disambiguates runs whose wall clocks collide, such
        // as restored snapshots or stepped clocks.
        let run_token = format!("{:x}-{run_nanos:x}", process::id());
        Ok(Self {
            audit,
            client,
            config: Arc::new(config),
            request_sequence: Arc::new(AtomicU64::new(1)),
            run_token: Arc::from(run_token),
        })
    }

    /// Allocates a request identity unique within the audit log.
    ///
    /// The identity embeds a per-process run token so identities from
    /// different gateway runs appended to the same audit log do not collide.
    #[must_use]
    pub(crate) fn next_request_id(&self) -> RequestId {
        let sequence = self.request_sequence.fetch_add(1, Ordering::Relaxed);
        RequestId::from_parts(&self.run_token, sequence)
    }
}
