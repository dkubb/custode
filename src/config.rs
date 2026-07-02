//! Gateway configuration parsing.

use crate::process::RunError;
use crate::{health, http};
use ::http::Method;
use clap::{Args, Parser, Subcommand};
use core::net::SocketAddr;
use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::path::PathBuf;
use thiserror::Error;
use url::Url;

/// A configured method-path operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AllowedOperation {
    /// Accepted HTTP method.
    method: Method,
    /// Accepted request path.
    path: AllowedPath,
}

/// A configured allowed path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AllowedPath {
    /// Match mode.
    kind: AllowedPathKind,
    /// Path value.
    value: String,
}

/// Allowed path match mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AllowedPathKind {
    /// Exact path match.
    Exact,

    /// Path-prefix match constrained to path segments.
    Prefix,
}

/// Custode command-line interface.
#[derive(Debug, Parser)]
#[command(name = "custode-proxy")]
#[command(about = "Run the Custode provider gateway")]
pub struct Cli {
    /// Selected command.
    #[command(subcommand)]
    command: Command,
}

/// Top-level CLI command.
#[derive(Debug, Subcommand)]
enum Command {
    /// Probe a running gateway health endpoint.
    Healthcheck(health::HealthcheckArgs),

    /// Run the HTTP gateway.
    Serve(ServeArgs),
}

/// Configuration parsing error.
#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    /// No operations were configured.
    #[error("at least one allowed operation is required")]
    EmptyOperations,

    /// Operation could not be parsed.
    #[error(
        "allowed operation {operation:?} must have form METHOD:exact:/path or METHOD:prefix:/path"
    )]
    InvalidAllowedOperation {
        /// Raw operation.
        operation: String,
    },

    /// Path did not begin with `/`.
    #[error("allowed path {path:?} must begin with /")]
    InvalidAllowedPath {
        /// Invalid path.
        path: String,
    },

    /// Method could not be parsed.
    #[error("invalid HTTP method {method:?}")]
    InvalidMethod {
        /// Raw method.
        method: String,
    },

    /// Operation kind is invalid.
    #[error("allowed operation kind {kind:?} must be exact or prefix")]
    InvalidOperationKind {
        /// Raw operation kind.
        kind: String,
    },

    /// Upstream origin could not be parsed.
    #[error("invalid upstream origin {raw:?}: {source}")]
    InvalidUpstreamOrigin {
        /// Raw upstream origin.
        raw: String,
        /// URL parser source error.
        source: url::ParseError,
    },

    /// Upstream origin had no host.
    #[error("upstream origin must include a host")]
    MissingUpstreamHost,

    /// Upstream origin used an unsupported scheme.
    #[error("unsupported upstream scheme {scheme:?}")]
    UnsupportedUpstreamScheme {
        /// Unsupported scheme.
        scheme: String,
    },

    /// Upstream origin included path, query, or fragment.
    #[error("upstream origin must not include path, query, or fragment")]
    UpstreamOriginHasComponents,

    /// Upstream origin included credentials.
    #[error("upstream origin must not include credentials")]
    UpstreamOriginHasCredentials,

    /// Upstream origin used a wildcard host.
    #[error("upstream origin must not use a wildcard host")]
    WildcardUpstreamHost,

    /// A numeric bound was zero.
    #[error("{name} must be greater than zero")]
    ZeroBound {
        /// Bound name.
        name: &'static str,
    },
}

/// Fully parsed gateway configuration.
#[derive(Clone, Debug)]
pub(crate) struct GatewayConfig {
    /// Allowed method-path operations.
    allowed_operations: Vec<AllowedOperation>,
    /// Newline-delimited audit log path.
    audit_log: PathBuf,
    /// Gateway bind address.
    bind: SocketAddr,
    /// Maximum serialized audit event bytes.
    max_audit_event_bytes: NonZeroUsize,
    /// Maximum concurrent gateway requests.
    max_concurrent_requests: NonZeroUsize,
    /// Maximum incoming request body bytes.
    max_request_bytes: NonZeroUsize,
    /// Maximum incoming request header bytes.
    max_request_header_bytes: NonZeroUsize,
    /// Maximum upstream response body bytes.
    max_response_bytes: NonZeroU64,
    /// Maximum upstream response header bytes.
    max_response_header_bytes: NonZeroUsize,
    /// Upstream request timeout.
    request_timeout: Duration,
    /// Configured upstream origin.
    upstream_origin: UpstreamOrigin,
}

/// Raw serve command arguments before fail-closed parsing.
#[derive(Debug, Args)]
struct ServeArgs {
    /// Comma-separated method-path operations accepted by the gateway.
    #[arg(
        long,
        env = "CUSTODE_ALLOWED_OPERATIONS",
        value_delimiter = ',',
        default_value = "GET:exact:/v1/models,POST:prefix:/v1/responses,POST:prefix:/v1/chat/completions"
    )]
    allowed_operations: Vec<String>,

    /// Newline-delimited JSON audit log path.
    #[arg(
        long,
        env = "CUSTODE_AUDIT_LOG",
        default_value = "/var/log/custode/proxy.ndjson"
    )]
    audit_log: PathBuf,

    /// Address the gateway listens on.
    #[arg(long, env = "CUSTODE_BIND", default_value = "0.0.0.0:8080")]
    bind: SocketAddr,

    /// Maximum serialized audit event bytes.
    #[arg(long, env = "CUSTODE_MAX_AUDIT_EVENT_BYTES", default_value_t = 16_384)]
    max_audit_event_bytes: usize,

    /// Maximum concurrent gateway requests.
    #[arg(long, env = "CUSTODE_MAX_CONCURRENT_REQUESTS", default_value_t = 8)]
    max_concurrent_requests: usize,

    /// Maximum incoming request body bytes.
    #[arg(long, env = "CUSTODE_MAX_REQUEST_BYTES", default_value_t = 10_485_760)]
    max_request_bytes: usize,

    /// Maximum incoming request header bytes.
    #[arg(
        long,
        env = "CUSTODE_MAX_REQUEST_HEADER_BYTES",
        default_value_t = 32_768
    )]
    max_request_header_bytes: usize,

    /// Maximum upstream response body bytes.
    #[arg(
        long,
        env = "CUSTODE_MAX_RESPONSE_BYTES",
        default_value_t = 104_857_600
    )]
    max_response_bytes: u64,

    /// Maximum upstream response header bytes.
    #[arg(
        long,
        env = "CUSTODE_MAX_RESPONSE_HEADER_BYTES",
        default_value_t = 65_536
    )]
    max_response_header_bytes: usize,

    /// Upstream request timeout in seconds.
    #[arg(long, env = "CUSTODE_REQUEST_TIMEOUT_SECS", default_value_t = 120)]
    request_timeout_secs: u64,

    /// Provider origin containing scheme, host, and optional port only.
    #[arg(long, env = "CUSTODE_UPSTREAM_ORIGIN")]
    upstream_origin: String,
}

/// Configured upstream origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UpstreamOrigin {
    /// Parsed upstream URL.
    url: Url,
}

impl AllowedOperation {
    /// Returns true if this operation has the supplied method.
    #[must_use]
    pub(crate) fn has_method(&self, method: &Method) -> bool {
        self.method == *method
    }

    /// Returns true if this operation accepts the method and path.
    #[must_use]
    pub(crate) fn matches(&self, method: &Method, path: &str) -> bool {
        self.method == *method && self.path.matches(path)
    }

    /// Parses a configured allowed operation.
    ///
    /// # Errors
    ///
    /// Returns an error when the method, match kind, or path is invalid.
    pub(crate) fn parse(raw: &str) -> Result<Self, ConfigError> {
        let mut parts = raw.splitn(3, ':');
        let method_text = parts.next().unwrap_or_default();
        let kind = parts.next().unwrap_or_default();
        let path_text = parts.next().unwrap_or_default();

        if method_text.is_empty() || kind.is_empty() || path_text.is_empty() {
            return Err(ConfigError::InvalidAllowedOperation {
                operation: raw.to_owned(),
            });
        }

        let method = Method::from_bytes(method_text.as_bytes()).map_err(|_error| {
            ConfigError::InvalidMethod {
                method: method_text.to_owned(),
            }
        })?;
        let path = match kind {
            "exact" => AllowedPath::exact(path_text)?,
            "prefix" => AllowedPath::prefix(path_text)?,
            _ => {
                return Err(ConfigError::InvalidOperationKind {
                    kind: kind.to_owned(),
                });
            }
        };

        Ok(Self { method, path })
    }
}

impl AllowedPath {
    /// Parses an exact allowed path.
    ///
    /// # Errors
    ///
    /// Returns an error when the path does not begin with `/`.
    pub(crate) fn exact(raw: &str) -> Result<Self, ConfigError> {
        Ok(Self {
            kind: AllowedPathKind::Exact,
            value: parse_allowed_path(raw)?,
        })
    }

    /// Returns true if this allowed path accepts the incoming path.
    #[must_use]
    pub(crate) fn matches(&self, path: &str) -> bool {
        match self.kind {
            AllowedPathKind::Exact => path == self.value.as_str(),
            AllowedPathKind::Prefix => {
                let prefix_text = self.value.as_str();
                path == prefix_text
                    || path
                        .strip_prefix(prefix_text)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            }
        }
    }

    /// Parses an allowed path prefix.
    ///
    /// # Errors
    ///
    /// Returns an error when the path does not begin with `/`.
    pub(crate) fn prefix(raw: &str) -> Result<Self, ConfigError> {
        Ok(Self {
            kind: AllowedPathKind::Prefix,
            value: parse_allowed_path(raw)?,
        })
    }
}

impl Cli {
    /// Runs the selected command.
    ///
    /// # Errors
    ///
    /// Returns an error when configuration parsing, serving, or healthchecking
    /// fails.
    #[inline]
    pub async fn run(self) -> Result<(), RunError> {
        match self.command {
            Command::Healthcheck(args) => health::check(args).await.map_err(RunError::from),
            Command::Serve(args) => http::serve(args.try_into()?).await.map_err(RunError::from),
        }
    }
}

impl GatewayConfig {
    /// Returns the allowed operations.
    #[must_use]
    pub(crate) fn allowed_operations(&self) -> &[AllowedOperation] {
        &self.allowed_operations
    }

    /// Returns the audit log path.
    #[must_use]
    pub(crate) const fn audit_log(&self) -> &PathBuf {
        &self.audit_log
    }

    /// Returns the gateway bind address.
    #[must_use]
    pub(crate) const fn bind(&self) -> SocketAddr {
        self.bind
    }

    /// Builds a minimal valid config for focused runtime tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn for_test(audit_log: PathBuf, max_audit_event_bytes: NonZeroUsize) -> Self {
        Self {
            allowed_operations: vec![
                AllowedOperation::parse("GET:exact:/v1/models").expect("operation should parse"),
            ],
            audit_log,
            bind: "127.0.0.1:0".parse().expect("bind address should parse"),
            max_audit_event_bytes,
            max_concurrent_requests: NonZeroUsize::new(1).expect("limit should be non-zero"),
            max_request_bytes: NonZeroUsize::new(1).expect("limit should be non-zero"),
            max_request_header_bytes: NonZeroUsize::new(1).expect("limit should be non-zero"),
            max_response_bytes: NonZeroU64::new(1_024).expect("limit should be non-zero"),
            max_response_header_bytes: NonZeroUsize::new(1).expect("limit should be non-zero"),
            request_timeout: Duration::from_secs(1),
            upstream_origin: UpstreamOrigin::parse("https://api.openai.com")
                .expect("origin should parse"),
        }
    }

    /// Returns the maximum serialized audit event bytes.
    #[must_use]
    pub(crate) const fn max_audit_event_bytes(&self) -> NonZeroUsize {
        self.max_audit_event_bytes
    }

    /// Returns the maximum concurrent requests.
    #[must_use]
    pub(crate) const fn max_concurrent_requests(&self) -> NonZeroUsize {
        self.max_concurrent_requests
    }

    /// Returns the maximum incoming request body bytes.
    #[must_use]
    pub(crate) const fn max_request_bytes(&self) -> NonZeroUsize {
        self.max_request_bytes
    }

    /// Returns the maximum incoming request header bytes.
    #[must_use]
    pub(crate) const fn max_request_header_bytes(&self) -> NonZeroUsize {
        self.max_request_header_bytes
    }

    /// Returns the maximum upstream response body bytes.
    #[must_use]
    pub(crate) const fn max_response_bytes(&self) -> NonZeroU64 {
        self.max_response_bytes
    }

    /// Returns the maximum upstream response header bytes.
    #[must_use]
    pub(crate) const fn max_response_header_bytes(&self) -> NonZeroUsize {
        self.max_response_header_bytes
    }

    /// Returns the upstream request timeout.
    #[must_use]
    pub(crate) const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Returns the configured upstream origin.
    #[must_use]
    pub(crate) const fn upstream_origin(&self) -> &UpstreamOrigin {
        &self.upstream_origin
    }
}

impl TryFrom<ServeArgs> for GatewayConfig {
    type Error = ConfigError;

    fn try_from(args: ServeArgs) -> Result<Self, Self::Error> {
        let allowed_operations = parse_allowed_operations(args.allowed_operations)?;
        let request_timeout = Duration::from_secs(
            non_zero_u64("CUSTODE_REQUEST_TIMEOUT_SECS", args.request_timeout_secs)?.get(),
        );

        Ok(Self {
            allowed_operations,
            audit_log: args.audit_log,
            bind: args.bind,
            max_audit_event_bytes: non_zero_usize(
                "CUSTODE_MAX_AUDIT_EVENT_BYTES",
                args.max_audit_event_bytes,
            )?,
            max_concurrent_requests: non_zero_usize(
                "CUSTODE_MAX_CONCURRENT_REQUESTS",
                args.max_concurrent_requests,
            )?,
            max_request_bytes: non_zero_usize("CUSTODE_MAX_REQUEST_BYTES", args.max_request_bytes)?,
            max_request_header_bytes: non_zero_usize(
                "CUSTODE_MAX_REQUEST_HEADER_BYTES",
                args.max_request_header_bytes,
            )?,
            max_response_bytes: non_zero_u64(
                "CUSTODE_MAX_RESPONSE_BYTES",
                args.max_response_bytes,
            )?,
            max_response_header_bytes: non_zero_usize(
                "CUSTODE_MAX_RESPONSE_HEADER_BYTES",
                args.max_response_header_bytes,
            )?,
            request_timeout,
            upstream_origin: UpstreamOrigin::parse(&args.upstream_origin)?,
        })
    }
}

impl UpstreamOrigin {
    /// Returns the origin as a string.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        self.url.as_str().trim_end_matches('/')
    }

    /// Joins an accepted origin-form path and query onto this origin.
    #[must_use]
    pub(crate) fn join_path_query(&self, path: &str, query: Option<&str>) -> Url {
        let mut url = self.url.clone();
        url.set_path(path);
        url.set_query(query);
        url
    }

    /// Parses an upstream origin from a raw string.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the origin is not HTTP(S), lacks a
    /// host, uses a wildcard host, or contains path, query, fragment,
    /// username, or password.
    pub(crate) fn parse(raw: &str) -> Result<Self, ConfigError> {
        let url = Url::parse(raw).map_err(|source| ConfigError::InvalidUpstreamOrigin {
            raw: raw.to_owned(),
            source,
        })?;

        if !matches!(url.scheme(), "http" | "https") {
            return Err(ConfigError::UnsupportedUpstreamScheme {
                scheme: url.scheme().to_owned(),
            });
        }
        let Some(host) = url.host_str() else {
            return Err(ConfigError::MissingUpstreamHost);
        };
        if host.contains('*') {
            return Err(ConfigError::WildcardUpstreamHost);
        }
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(ConfigError::UpstreamOriginHasComponents);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ConfigError::UpstreamOriginHasCredentials);
        }

        Ok(Self { url })
    }
}

/// Returns a non-zero `u64` or the matching configuration error.
fn non_zero_u64(name: &'static str, value: u64) -> Result<NonZeroU64, ConfigError> {
    NonZeroU64::new(value).ok_or(ConfigError::ZeroBound { name })
}

/// Returns a non-zero `usize` or the matching configuration error.
fn non_zero_usize(name: &'static str, value: usize) -> Result<NonZeroUsize, ConfigError> {
    NonZeroUsize::new(value).ok_or(ConfigError::ZeroBound { name })
}

/// Parses allowed operation strings and rejects an empty operation set.
fn parse_allowed_operations(operations: Vec<String>) -> Result<Vec<AllowedOperation>, ConfigError> {
    let parsed = operations
        .into_iter()
        .filter(|operation| !operation.is_empty())
        .map(|operation| AllowedOperation::parse(&operation))
        .collect::<Result<Vec<_>, _>>()?;

    if parsed.is_empty() {
        return Err(ConfigError::EmptyOperations);
    }

    Ok(parsed)
}

/// Parses an allowed path string.
fn parse_allowed_path(path: &str) -> Result<String, ConfigError> {
    if path.starts_with('/') {
        Ok(path.to_owned())
    } else {
        Err(ConfigError::InvalidAllowedPath {
            path: path.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests;
