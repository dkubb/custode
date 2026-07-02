//! Audit event schema and writer.

use crate::allowlist::AcceptedTarget;
use crate::config::GatewayConfig;
use serde::Serialize;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use thiserror::Error;
use tokio::fs::{File, OpenOptions, create_dir_all};
use tokio::io::AsyncWriteExt as _;
use tokio::sync::Mutex;

/// Audit decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuditDecision {
    /// Request was allowed and completed normally.
    Allowed,

    /// Request was denied before upstream I/O.
    Denied,

    /// Response streaming failed.
    ResponseError,

    /// Upstream request failed before a response completed.
    UpstreamError,
}

/// Audit log error.
#[derive(Debug, Error)]
pub(crate) enum AuditError {
    /// Audit event exceeded configured maximum.
    #[error("audit event has {bytes} bytes, maximum is {max}")]
    EventTooLarge {
        /// Serialized event bytes.
        bytes: usize,
        /// Maximum allowed bytes.
        max: usize,
    },

    /// Audit log could not be opened.
    #[error("failed to open audit path {path}: {source}")]
    Open {
        /// Path that failed.
        path: PathBuf,
        /// I/O source error.
        source: io::Error,
    },

    /// Audit event could not be serialized.
    #[error("failed to serialize audit event: {0}")]
    Serialize(serde_json::Error),

    /// Audit log write failed.
    #[error("failed to write audit event: {0}")]
    Write(io::Error),
}

/// Structured audit event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct AuditEvent {
    /// Final audit decision.
    decision: AuditDecision,
    /// Stable error class for failed decisions.
    error_class: Option<String>,
    /// Request method.
    method: String,
    /// Accepted or synthetic request path.
    path: String,
    /// Request query string without `?`.
    query: Option<String>,
    /// Request body digest.
    request_body_blake3: Option<String>,
    /// Request body bytes.
    request_bytes: u64,
    /// Request identity.
    request_id: RequestId,
    /// Response body digest.
    response_body_blake3: Option<String>,
    /// Response body bytes.
    response_bytes: u64,
    /// Response status returned to the harness, when one exists.
    status: Option<u16>,
    /// RFC 3339 UTC timestamp.
    timestamp: String,
    /// Configured upstream origin.
    upstream_origin: String,
    /// Upstream path, when an upstream request was attempted.
    upstream_path: Option<String>,
    /// Upstream query, when an upstream request was attempted.
    upstream_query: Option<String>,
    /// Audit schema version.
    version: u8,
}

/// Input used to construct an audit event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuditEventInput {
    /// Audit decision.
    pub decision: AuditDecision,
    /// Error class, when one exists.
    pub error_class: Option<String>,
    /// Request method.
    pub method: String,
    /// Request body digest.
    pub request_body_blake3: Option<String>,
    /// Request body byte count.
    pub request_bytes: u64,
    /// Request identity.
    pub request_id: RequestId,
    /// Response body digest.
    pub response_body_blake3: Option<String>,
    /// Response body byte count.
    pub response_bytes: u64,
    /// Response status returned to the harness, when one exists.
    pub status: Option<u16>,
    /// Accepted or raw audit target.
    pub target: AuditTarget,
    /// Configured upstream origin.
    pub upstream_origin: String,
    /// Upstream path, when an upstream request was attempted.
    pub upstream_path: Option<String>,
    /// Upstream query, when an upstream request was attempted.
    pub upstream_query: Option<String>,
}

/// Request target recorded in the audit log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuditTarget {
    /// Request path.
    path: String,
    /// Request query string without `?`.
    query: Option<String>,
}

/// Newline-delimited JSON audit writer.
#[derive(Clone, Debug)]
pub(crate) struct AuditWriter {
    /// Audit log file guarded for append writes.
    file: Arc<Mutex<File>>,
    /// Maximum serialized event bytes.
    max_event_bytes: usize,
}

/// Request identity used in audit events.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct RequestId(String);

impl AuditTarget {
    /// Creates an audit target from raw request URI parts.
    #[must_use]
    pub(crate) fn from_uri_parts(path: &str, query: Option<&str>) -> Self {
        Self {
            path: if path.is_empty() {
                "/".to_owned()
            } else {
                path.to_owned()
            },
            query: query.map(str::to_owned),
        }
    }

    /// Returns the audited path.
    #[must_use]
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    /// Returns the audited query string.
    #[must_use]
    pub(crate) fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }
}

impl From<AcceptedTarget> for AuditTarget {
    fn from(target: AcceptedTarget) -> Self {
        Self {
            path: target.path().to_owned(),
            query: target.query().map(str::to_owned),
        }
    }
}

impl AuditEvent {
    /// Creates an audit event for a request decision.
    #[must_use]
    pub(crate) fn new(input: AuditEventInput) -> Self {
        Self {
            decision: input.decision,
            error_class: input.error_class,
            method: input.method,
            path: input.target.path().to_owned(),
            query: input.target.query().map(str::to_owned),
            request_body_blake3: input.request_body_blake3,
            request_bytes: input.request_bytes,
            request_id: input.request_id,
            response_body_blake3: input.response_body_blake3,
            response_bytes: input.response_bytes,
            status: input.status,
            timestamp: rfc3339_timestamp(),
            upstream_origin: input.upstream_origin,
            upstream_path: input.upstream_path,
            upstream_query: input.upstream_query,
            version: 1,
        }
    }
}

impl AuditWriter {
    /// Opens an audit writer in append mode.
    ///
    /// # Errors
    ///
    /// Returns an error when the audit log cannot be opened.
    pub(crate) async fn open(config: &GatewayConfig) -> Result<Self, AuditError> {
        let path = config.audit_log();
        if let Some(parent) = path.parent() {
            create_dir_all(parent)
                .await
                .map_err(|source| AuditError::Open {
                    path: parent.to_owned(),
                    source,
                })?;
        }
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .await
            .map_err(|source| AuditError::Open {
                path: path.to_owned(),
                source,
            })?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
            max_event_bytes: config.max_audit_event_bytes().get(),
        })
    }

    /// Writes one required audit event.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization or writing fails.
    pub(crate) async fn write_event(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let mut serialized = serde_json::to_vec(event).map_err(AuditError::Serialize)?;
        if serialized.len() > self.max_event_bytes {
            return Err(AuditError::EventTooLarge {
                bytes: serialized.len(),
                max: self.max_event_bytes,
            });
        }
        serialized.push(b'\n');

        let mut file = self.file.lock().await;
        file.write_all(&serialized)
            .await
            .map_err(AuditError::Write)?;
        file.flush().await.map_err(AuditError::Write)?;
        drop(file);
        Ok(())
    }
}

impl RequestId {
    /// Creates a request identity from a monotonic sequence number.
    #[must_use]
    pub(crate) fn from_sequence(sequence: u64) -> Self {
        Self(format!("req-{sequence:016x}"))
    }
}

/// Returns the current RFC 3339 UTC timestamp for audit events.
fn rfc3339_timestamp() -> String {
    humantime::format_rfc3339_nanos(SystemTime::now()).to_string()
}

#[cfg(test)]
mod tests;
