//! Request handling state machine.

use crate::allowlist::AcceptedTarget;
use crate::audit::{
    AuditDecision, AuditError, AuditEvent, AuditEventInput, AuditTarget, AuditWriter, RequestId,
};
use crate::body::{AccountedBody, BodyError, ResponseAccount};
use crate::config::{AuthorizationSource, ConfigError, GatewayConfig};
use crate::headers::{HeaderError, ProviderAuthorization};
use ::http::header::{AUTHORIZATION, InvalidHeaderValue};
use ::http::{Error as HttpError, HeaderName, HeaderValue, Method};
use core::sync::atomic::{AtomicU64, Ordering};
use reqwest::Client;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::fs;

/// Shared gateway state.
#[derive(Clone, Debug)]
pub(crate) struct Gateway {
    /// Audit log writer.
    audit: AuditWriter,
    /// Provider authorization header.
    authorization: Option<ProviderAuthorization>,
    /// Upstream HTTP client.
    client: Client,
    /// Parsed gateway configuration.
    config: Arc<GatewayConfig>,
    /// Monotonic request sequence.
    request_sequence: Arc<AtomicU64>,
}

/// Gateway runtime error.
#[derive(Debug, Error)]
pub(crate) enum GatewayError {
    /// Audit log failed.
    #[error("{0}")]
    Audit(#[from] AuditError),

    /// Provider authorization header could not be built.
    #[error("failed to build authorization header: {0}")]
    AuthorizationHeader(InvalidHeaderValue),

    /// Provider authorization token file could not be read.
    #[error("failed to read authorization file {path}: {source}")]
    AuthorizationRead {
        /// Token file path.
        path: PathBuf,
        /// Source error.
        source: io::Error,
    },

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

    /// Returns the configured upstream authorization header.
    #[must_use]
    pub(crate) const fn authorization(&self) -> Option<&ProviderAuthorization> {
        self.authorization.as_ref()
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
    /// Returns an error when audit log or authorization setup fails.
    pub(crate) async fn new(config: GatewayConfig) -> Result<Self, GatewayError> {
        let audit = AuditWriter::open(&config).await?;
        let authorization = read_authorization(config.authorization()).await?;
        let client = Client::builder()
            .timeout(config.request_timeout())
            .build()
            .map_err(GatewayError::Client)?;
        Ok(Self {
            audit,
            authorization,
            client,
            config: Arc::new(config),
            request_sequence: Arc::new(AtomicU64::new(1)),
        })
    }

    /// Allocates a request identity.
    #[must_use]
    pub(crate) fn next_request_id(&self) -> RequestId {
        let sequence = self.request_sequence.fetch_add(1, Ordering::Relaxed);
        RequestId::from_sequence(sequence)
    }
}

/// Reads the configured provider authorization header.
async fn read_authorization(
    authorization: &AuthorizationSource,
) -> Result<Option<ProviderAuthorization>, GatewayError> {
    if let Some(path) = authorization.bearer_file_path() {
        let token = read_authorization_token(path).await?;
        let value = format!("Bearer {}", token.trim());
        return HeaderValue::from_str(&value)
            .map(|header_value| Some(ProviderAuthorization::new(AUTHORIZATION, header_value)))
            .map_err(GatewayError::AuthorizationHeader);
    }

    if let Some(path) = authorization.x_api_key_file_path() {
        let token = read_authorization_token(path).await?;
        return HeaderValue::from_str(token.trim())
            .map(|header_value| {
                Some(ProviderAuthorization::new(
                    HeaderName::from_static("x-api-key"),
                    header_value,
                ))
            })
            .map_err(GatewayError::AuthorizationHeader);
    }

    Ok(None)
}

/// Reads a provider authorization token file.
async fn read_authorization_token(path: &Path) -> Result<String, GatewayError> {
    fs::read_to_string(path)
        .await
        .map_err(|read_error| GatewayError::AuthorizationRead {
            path: path.to_owned(),
            source: read_error,
        })
}
