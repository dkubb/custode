//! Gateway configuration parsing.

use crate::target::{MAX_ORIGIN_FORM_PATH_BYTES, OriginFormPath, OriginFormQuery};
use ::http::Method;
use clap::Args;
use core::net::SocketAddr;
use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;
use std::path::PathBuf;
use thiserror::Error;
use tokio::sync::Semaphore;
use url::Url;

/// Maximum serialized audit event bytes, including the NDJSON newline.
const MAX_AUDIT_EVENT_BYTES: usize = 0x0010_0000;
/// Minimum serialized audit event bytes required for every admitted target.
pub(crate) const MIN_AUDIT_EVENT_BYTES: usize = 0x0001_0000;
/// Maximum accepted HTTP method bytes for allowlisted and audited methods.
pub(crate) const MAX_ALLOWED_METHOD_BYTES: usize = 64;
/// Maximum configured allowed operation bytes.
const MAX_ALLOWED_OPERATION_BYTES: usize = MAX_ORIGIN_FORM_PATH_BYTES + MAX_ALLOWED_METHOD_BYTES;
/// Maximum configured allowed operations.
const MAX_ALLOWED_OPERATIONS: usize = 256;
/// Maximum concurrent gateway requests accepted by Tokio's semaphore.
const MAX_CONCURRENT_REQUESTS: usize = Semaphore::MAX_PERMITS;
/// Maximum incoming request body bytes.
const MAX_REQUEST_BYTES: usize = 0x4000_0000;
/// Maximum incoming request header name/value bytes.
const MAX_REQUEST_HEADER_BYTES: usize = 0x0010_0000;
/// Maximum upstream response body bytes.
const MAX_RESPONSE_BYTES: u64 = 0x4000_0000;
/// Maximum upstream response header name/value bytes.
const MAX_RESPONSE_HEADER_BYTES: usize = 0x0010_0000;
/// Maximum request timeout in seconds.
const MAX_REQUEST_TIMEOUT_SECS: u64 = 3_600;
/// Maximum upstream origin bytes.
const MAX_UPSTREAM_ORIGIN_BYTES: usize = 255;

/// A configured method-path operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AllowedOperation {
    /// Accepted HTTP method.
    method: AllowedMethod,
    /// Accepted request path.
    path: AllowedPath,
}

/// A configured HTTP method accepted by the gateway protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AllowedMethod {
    /// Parsed HTTP method.
    method: Method,
}

/// Parsed maximum serialized audit event bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuditEventBytes(NonZeroUsize);

/// Parsed maximum concurrent gateway requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConcurrentRequests(NonZeroUsize);

/// Parsed maximum incoming request body bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RequestBodyBytes(NonZeroUsize);

/// Parsed maximum incoming request header bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RequestHeaderBytes(NonZeroUsize);

/// Parsed maximum upstream response body bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResponseBodyBytes(NonZeroU64);

/// Parsed maximum upstream response header bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResponseHeaderBytes(NonZeroUsize);

/// A configured allowed path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AllowedPath {
    /// Match mode.
    kind: AllowedPathKind,
    /// Path value.
    value: OriginFormPath,
}

/// Allowed path match mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AllowedPathKind {
    /// Exact path match.
    Exact,

    /// Path-prefix match constrained to path segments.
    Prefix,
}

/// Configuration parsing error.
#[derive(Debug, Error)]
pub(crate) enum ConfigError {
    /// Operation text exceeded the supported byte limit.
    #[error("allowed operation must be at most {max} bytes, got {value}")]
    AllowedOperationTooLong {
        /// Maximum accepted bytes.
        max: u128,
        /// Supplied bytes.
        value: u128,
    },

    /// A numeric bound was above the supported maximum.
    #[error("{name} must be at most {max}, got {value}")]
    BoundTooLarge {
        /// Bound name.
        name: &'static str,
        /// Maximum accepted value.
        max: u128,
        /// Supplied value.
        value: u128,
    },

    /// A numeric bound was below the supported minimum.
    #[error("{name} must be at least {min}, got {value}")]
    BoundTooSmall {
        /// Bound name.
        name: &'static str,
        /// Minimum accepted value.
        min: u128,
        /// Supplied value.
        value: u128,
    },

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

    /// Path was not a supported origin-form path.
    #[error(
        "allowed path {path:?} must be origin-form without query delimiters, fragments, literal backslashes, dot segments, encoded separators, or invalid percent-encoding"
    )]
    InvalidAllowedPath {
        /// Invalid path.
        path: String,
    },

    /// Prefix path was not a supported segment-bounded prefix.
    #[error("allowed prefix {path:?} must be non-root and must not end with `/`")]
    InvalidAllowedPrefix {
        /// Invalid prefix.
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

    /// Method exceeded the supported byte limit.
    #[error("HTTP method must be at most {max} bytes, got {value}")]
    MethodTooLong {
        /// Maximum accepted bytes.
        max: u128,
        /// Supplied bytes.
        value: u128,
    },

    /// Too many operations were configured.
    #[error("at most {max} allowed operations are supported, got {value}")]
    TooManyAllowedOperations {
        /// Maximum accepted operation count.
        max: u128,
        /// Supplied operation count.
        value: u128,
    },

    /// Method is outside the gateway protocol.
    #[error("unsupported HTTP method {method:?}")]
    UnsupportedMethod {
        /// Raw method.
        method: String,
    },

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

    /// Upstream origin used port zero.
    #[error("upstream origin port must be greater than zero")]
    UpstreamOriginHasZeroPort,

    /// Upstream origin text exceeded the supported byte limit.
    #[error("upstream origin must be at most {max} bytes, got {value}")]
    UpstreamOriginTooLong {
        /// Maximum accepted bytes.
        max: u128,
        /// Supplied bytes.
        value: u128,
    },

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
    /// Maximum serialized audit event bytes, including the NDJSON newline.
    max_audit_event_bytes: AuditEventBytes,
    /// Maximum concurrent gateway requests.
    max_concurrent_requests: ConcurrentRequests,
    /// Maximum incoming request body bytes.
    max_request_bytes: RequestBodyBytes,
    /// Maximum incoming request header bytes.
    max_request_header_bytes: RequestHeaderBytes,
    /// Maximum upstream response body bytes.
    max_response_bytes: ResponseBodyBytes,
    /// Maximum upstream response header bytes.
    max_response_header_bytes: ResponseHeaderBytes,
    /// Upstream request timeout.
    request_timeout: RequestTimeout,
    /// Configured upstream origin.
    upstream_origin: UpstreamOrigin,
}

/// Raw serve command arguments before fail-closed parsing.
#[derive(Debug, Args)]
pub(crate) struct ServeArgs {
    /// Comma-separated method-path operations accepted by the gateway.
    ///
    /// There is intentionally no default: a missing or empty allowlist is a
    /// configuration error so the gateway fails closed.
    #[arg(long, env = "CUSTODE_ALLOWED_OPERATIONS", value_delimiter = ',')]
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

    /// Maximum serialized audit event bytes, including the NDJSON newline.
    #[arg(
        long,
        env = "CUSTODE_MAX_AUDIT_EVENT_BYTES",
        default_value_t = MIN_AUDIT_EVENT_BYTES
    )]
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

/// Non-zero upstream request timeout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RequestTimeout {
    /// Timeout duration.
    duration: Duration,
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
        self.method.matches(method)
    }

    /// Returns true if this operation accepts the method and path.
    #[must_use]
    pub(crate) fn matches(&self, method: &Method, path: &OriginFormPath) -> bool {
        self.method.matches(method) && self.path.matches(path)
    }

    /// Returns the configured allowed method.
    #[must_use]
    pub(crate) const fn method(&self) -> &AllowedMethod {
        &self.method
    }

    /// Parses a configured allowed operation.
    ///
    /// # Errors
    ///
    /// Returns an error when the method, match kind, or path is invalid.
    pub(crate) fn parse(raw: &str) -> Result<Self, ConfigError> {
        if raw.len() > MAX_ALLOWED_OPERATION_BYTES {
            return Err(ConfigError::AllowedOperationTooLong {
                max: usize_to_u128(MAX_ALLOWED_OPERATION_BYTES),
                value: usize_to_u128(raw.len()),
            });
        }

        let mut parts = raw.splitn(3, ':');
        let method_text = parts.next().unwrap_or_default();
        let kind = parts.next().unwrap_or_default();
        let path_text = parts.next().unwrap_or_default();

        if method_text.is_empty() || kind.is_empty() || path_text.is_empty() {
            return Err(ConfigError::InvalidAllowedOperation {
                operation: raw.to_owned(),
            });
        }

        let method = AllowedMethod::parse(method_text)?;
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

impl AllowedMethod {
    /// Returns the parsed HTTP method.
    #[must_use]
    pub(crate) const fn as_method(&self) -> &Method {
        &self.method
    }

    /// Returns true if this configured method equals the supplied method.
    #[must_use]
    fn matches(&self, method: &Method) -> bool {
        self.method == *method
    }

    /// Parses a configured HTTP method.
    ///
    /// # Errors
    ///
    /// Returns an error when the method is syntactically invalid, unsupported
    /// by the gateway, or wider than the audited method domain.
    pub(crate) fn parse(raw: &str) -> Result<Self, ConfigError> {
        if raw.len() > MAX_ALLOWED_METHOD_BYTES {
            return Err(ConfigError::MethodTooLong {
                max: usize_to_u128(MAX_ALLOWED_METHOD_BYTES),
                value: usize_to_u128(raw.len()),
            });
        }

        let method =
            Method::from_bytes(raw.as_bytes()).map_err(|_error| ConfigError::InvalidMethod {
                method: raw.to_owned(),
            })?;
        if method == Method::CONNECT {
            return Err(ConfigError::UnsupportedMethod {
                method: raw.to_owned(),
            });
        }
        Ok(Self { method })
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
    pub(crate) fn matches(&self, path: &OriginFormPath) -> bool {
        let path_text = path.as_str();
        match self.kind {
            AllowedPathKind::Exact => path_text == self.value.as_str(),
            AllowedPathKind::Prefix => {
                let prefix_text = self.value.as_str();
                path_text == prefix_text
                    || path_text
                        .strip_prefix(prefix_text)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            }
        }
    }

    /// Parses an allowed path prefix.
    ///
    /// # Errors
    ///
    /// Returns an error when the prefix is not a supported segment-bounded
    /// prefix.
    pub(crate) fn prefix(raw: &str) -> Result<Self, ConfigError> {
        Ok(Self {
            kind: AllowedPathKind::Prefix,
            value: parse_allowed_prefix(raw)?,
        })
    }
}

impl AuditEventBytes {
    /// Builds a test-only limit for audit serialization failure paths.
    #[cfg(test)]
    pub(crate) const fn for_test(value: NonZeroUsize) -> Self {
        Self(value)
    }

    /// Returns the parsed non-zero byte limit.
    pub(crate) const fn get(self) -> usize {
        self.0.get()
    }

    /// Parses and bounds audit event bytes.
    fn parse(name: &'static str, raw_value: usize) -> Result<Self, ConfigError> {
        let value = bounded_non_zero_usize(name, raw_value, MAX_AUDIT_EVENT_BYTES)?;
        if value.get() < MIN_AUDIT_EVENT_BYTES {
            return Err(ConfigError::BoundTooSmall {
                name,
                min: usize_to_u128(MIN_AUDIT_EVENT_BYTES),
                value: usize_to_u128(raw_value),
            });
        }
        Ok(Self(value))
    }
}

impl ConcurrentRequests {
    /// Parses a test limit through the production bounds.
    #[cfg(test)]
    pub(crate) fn for_test(value: NonZeroUsize) -> Self {
        Self::parse("CUSTODE_MAX_CONCURRENT_REQUESTS", value.get())
            .expect("test concurrent request limit should be valid")
    }

    /// Returns the parsed non-zero request limit.
    pub(crate) const fn get(self) -> usize {
        self.0.get()
    }

    /// Parses and bounds concurrent requests.
    fn parse(name: &'static str, raw_value: usize) -> Result<Self, ConfigError> {
        bounded_non_zero_usize(name, raw_value, MAX_CONCURRENT_REQUESTS).map(Self)
    }
}

impl RequestBodyBytes {
    /// Parses a test limit through the production bounds.
    #[cfg(test)]
    pub(crate) fn for_test(value: NonZeroUsize) -> Self {
        Self::parse("CUSTODE_MAX_REQUEST_BYTES", value.get())
            .expect("test request body byte limit should be valid")
    }

    /// Returns the parsed non-zero byte limit.
    pub(crate) const fn get(self) -> usize {
        self.0.get()
    }

    /// Parses and bounds request body bytes.
    fn parse(name: &'static str, raw_value: usize) -> Result<Self, ConfigError> {
        bounded_non_zero_usize(name, raw_value, MAX_REQUEST_BYTES).map(Self)
    }
}

impl RequestHeaderBytes {
    /// Parses a test limit through the production bounds.
    #[cfg(test)]
    pub(crate) fn for_test(value: NonZeroUsize) -> Self {
        Self::parse("CUSTODE_MAX_REQUEST_HEADER_BYTES", value.get())
            .expect("test request header byte limit should be valid")
    }

    /// Returns the parsed non-zero byte limit.
    pub(crate) const fn get(self) -> usize {
        self.0.get()
    }

    /// Parses and bounds request header bytes.
    fn parse(name: &'static str, raw_value: usize) -> Result<Self, ConfigError> {
        bounded_non_zero_usize(name, raw_value, MAX_REQUEST_HEADER_BYTES).map(Self)
    }
}

impl ResponseBodyBytes {
    /// Parses a test limit through the production bounds.
    #[cfg(test)]
    pub(crate) fn for_test(value: NonZeroU64) -> Self {
        Self::parse("CUSTODE_MAX_RESPONSE_BYTES", value.get())
            .expect("test response body byte limit should be valid")
    }

    /// Returns the parsed non-zero byte limit.
    pub(crate) const fn get(self) -> u64 {
        self.0.get()
    }

    /// Parses and bounds response body bytes.
    fn parse(name: &'static str, raw_value: u64) -> Result<Self, ConfigError> {
        bounded_non_zero_u64(name, raw_value, MAX_RESPONSE_BYTES).map(Self)
    }
}

impl ResponseHeaderBytes {
    /// Parses a test limit through the production bounds.
    #[cfg(test)]
    pub(crate) fn for_test(value: NonZeroUsize) -> Self {
        Self::parse("CUSTODE_MAX_RESPONSE_HEADER_BYTES", value.get())
            .expect("test response header byte limit should be valid")
    }

    /// Returns the parsed non-zero byte limit.
    pub(crate) const fn get(self) -> usize {
        self.0.get()
    }

    /// Parses and bounds response header bytes.
    fn parse(name: &'static str, raw_value: usize) -> Result<Self, ConfigError> {
        bounded_non_zero_usize(name, raw_value, MAX_RESPONSE_HEADER_BYTES).map(Self)
    }
}

impl RequestTimeout {
    /// Returns the timeout as a duration.
    #[must_use]
    pub(crate) const fn as_duration(&self) -> Duration {
        self.duration
    }

    /// Creates a timeout from a non-zero duration for tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn from_duration(duration: Duration) -> Self {
        assert!(
            !duration.is_zero(),
            "request timeout duration should be non-zero"
        );
        Self { duration }
    }

    /// Parses timeout seconds from a raw numeric configuration value.
    fn parse_seconds(name: &'static str, raw_seconds: u64) -> Result<Self, ConfigError> {
        let seconds = bounded_non_zero_u64(name, raw_seconds, MAX_REQUEST_TIMEOUT_SECS)?;
        Ok(Self {
            duration: Duration::from_secs(seconds.get()),
        })
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

    /// Builds a valid config with roomy bounds for runtime tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn for_runtime_test(audit_log: PathBuf, upstream_origin: &str) -> Self {
        Self {
            allowed_operations: vec![
                AllowedOperation::parse("GET:exact:/v1/models").expect("operation should parse"),
                AllowedOperation::parse("POST:prefix:/v1/responses")
                    .expect("operation should parse"),
            ],
            audit_log,
            bind: "127.0.0.1:0".parse().expect("bind address should parse"),
            max_audit_event_bytes: AuditEventBytes::for_test(
                NonZeroUsize::new(MIN_AUDIT_EVENT_BYTES).expect("limit should be non-zero"),
            ),
            max_concurrent_requests: ConcurrentRequests::for_test(
                NonZeroUsize::new(8).expect("limit should be non-zero"),
            ),
            max_request_bytes: RequestBodyBytes::for_test(
                NonZeroUsize::new(0x0010_0000).expect("limit should be non-zero"),
            ),
            max_request_header_bytes: RequestHeaderBytes::for_test(
                NonZeroUsize::new(0x8000).expect("limit should be non-zero"),
            ),
            max_response_bytes: ResponseBodyBytes::for_test(
                NonZeroU64::new(0x0010_0000).expect("limit should be non-zero"),
            ),
            max_response_header_bytes: ResponseHeaderBytes::for_test(
                NonZeroUsize::new(0x8000).expect("limit should be non-zero"),
            ),
            request_timeout: RequestTimeout::from_duration(Duration::from_secs(5)),
            upstream_origin: UpstreamOrigin::parse(upstream_origin).expect("origin should parse"),
        }
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
            max_audit_event_bytes: AuditEventBytes::for_test(max_audit_event_bytes),
            max_concurrent_requests: ConcurrentRequests::for_test(
                NonZeroUsize::new(1).expect("limit should be non-zero"),
            ),
            max_request_bytes: RequestBodyBytes::for_test(
                NonZeroUsize::new(1).expect("limit should be non-zero"),
            ),
            max_request_header_bytes: RequestHeaderBytes::for_test(
                NonZeroUsize::new(1).expect("limit should be non-zero"),
            ),
            max_response_bytes: ResponseBodyBytes::for_test(
                NonZeroU64::new(1_024).expect("limit should be non-zero"),
            ),
            max_response_header_bytes: ResponseHeaderBytes::for_test(
                NonZeroUsize::new(1).expect("limit should be non-zero"),
            ),
            request_timeout: RequestTimeout::from_duration(Duration::from_secs(1)),
            upstream_origin: UpstreamOrigin::parse("https://api.openai.com")
                .expect("origin should parse"),
        }
    }

    /// Returns the maximum serialized audit event bytes, including the NDJSON
    /// newline.
    #[must_use]
    pub(crate) const fn max_audit_event_bytes(&self) -> AuditEventBytes {
        self.max_audit_event_bytes
    }

    /// Returns the maximum concurrent requests.
    #[must_use]
    pub(crate) const fn max_concurrent_requests(&self) -> ConcurrentRequests {
        self.max_concurrent_requests
    }

    /// Returns the maximum incoming request body bytes.
    #[must_use]
    pub(crate) const fn max_request_bytes(&self) -> RequestBodyBytes {
        self.max_request_bytes
    }

    /// Returns the maximum incoming request header bytes.
    #[must_use]
    pub(crate) const fn max_request_header_bytes(&self) -> RequestHeaderBytes {
        self.max_request_header_bytes
    }

    /// Returns the maximum upstream response body bytes.
    #[must_use]
    pub(crate) const fn max_response_bytes(&self) -> ResponseBodyBytes {
        self.max_response_bytes
    }

    /// Returns the maximum upstream response header bytes.
    #[must_use]
    pub(crate) const fn max_response_header_bytes(&self) -> ResponseHeaderBytes {
        self.max_response_header_bytes
    }

    /// Returns the upstream request timeout.
    #[must_use]
    pub(crate) const fn request_timeout(&self) -> RequestTimeout {
        self.request_timeout
    }

    /// Returns the configured upstream origin.
    #[must_use]
    pub(crate) const fn upstream_origin(&self) -> &UpstreamOrigin {
        &self.upstream_origin
    }

    /// Returns this config with a replacement allowlist.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_allowed_operations(
        mut self,
        allowed_operations: Vec<AllowedOperation>,
    ) -> Self {
        self.allowed_operations = allowed_operations;
        self
    }

    /// Returns this config with a replacement audit event byte limit.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn with_max_audit_event_bytes(
        mut self,
        max_audit_event_bytes: NonZeroUsize,
    ) -> Self {
        self.max_audit_event_bytes = AuditEventBytes::for_test(max_audit_event_bytes);
        self
    }

    /// Returns this config with a replacement response body byte limit.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_max_response_bytes(mut self, max_response_bytes: NonZeroU64) -> Self {
        self.max_response_bytes = ResponseBodyBytes::for_test(max_response_bytes);
        self
    }

    /// Returns this config with a replacement response header byte limit.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_max_response_header_bytes(
        mut self,
        max_response_header_bytes: NonZeroUsize,
    ) -> Self {
        self.max_response_header_bytes = ResponseHeaderBytes::for_test(max_response_header_bytes);
        self
    }
}

impl TryFrom<ServeArgs> for GatewayConfig {
    type Error = ConfigError;

    fn try_from(args: ServeArgs) -> Result<Self, Self::Error> {
        let allowed_operations = parse_allowed_operations(args.allowed_operations)?;
        let request_timeout = RequestTimeout::parse_seconds(
            "CUSTODE_REQUEST_TIMEOUT_SECS",
            args.request_timeout_secs,
        )?;

        Ok(Self {
            allowed_operations,
            audit_log: args.audit_log,
            bind: args.bind,
            max_audit_event_bytes: AuditEventBytes::parse(
                "CUSTODE_MAX_AUDIT_EVENT_BYTES",
                args.max_audit_event_bytes,
            )?,
            max_concurrent_requests: ConcurrentRequests::parse(
                "CUSTODE_MAX_CONCURRENT_REQUESTS",
                args.max_concurrent_requests,
            )?,
            max_request_bytes: RequestBodyBytes::parse(
                "CUSTODE_MAX_REQUEST_BYTES",
                args.max_request_bytes,
            )?,
            max_request_header_bytes: RequestHeaderBytes::parse(
                "CUSTODE_MAX_REQUEST_HEADER_BYTES",
                args.max_request_header_bytes,
            )?,
            max_response_bytes: ResponseBodyBytes::parse(
                "CUSTODE_MAX_RESPONSE_BYTES",
                args.max_response_bytes,
            )?,
            max_response_header_bytes: ResponseHeaderBytes::parse(
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
    pub(crate) fn join_path_query(
        &self,
        path: &OriginFormPath,
        query: Option<&OriginFormQuery>,
    ) -> Url {
        let mut url = self.url.clone();
        url.set_path(path.as_str());
        url.set_query(query.map(OriginFormQuery::as_str));
        url
    }

    /// Parses an upstream origin from a raw string.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when the origin is not HTTP(S), uses a
    /// wildcard host, or contains path, query, fragment, username, or password.
    pub(crate) fn parse(raw: &str) -> Result<Self, ConfigError> {
        if raw.len() > MAX_UPSTREAM_ORIGIN_BYTES {
            return Err(ConfigError::UpstreamOriginTooLong {
                max: usize_to_u128(MAX_UPSTREAM_ORIGIN_BYTES),
                value: usize_to_u128(raw.len()),
            });
        }

        let url = Url::parse(raw).map_err(|source| ConfigError::InvalidUpstreamOrigin {
            raw: raw.to_owned(),
            source,
        })?;

        if !matches!(url.scheme(), "http" | "https") {
            return Err(ConfigError::UnsupportedUpstreamScheme {
                scheme: url.scheme().to_owned(),
            });
        }
        if url.host_str().is_some_and(|host| host.contains('*')) {
            return Err(ConfigError::WildcardUpstreamHost);
        }
        if url.port() == Some(0) {
            return Err(ConfigError::UpstreamOriginHasZeroPort);
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

/// Returns a bounded non-zero `u64` or the matching configuration error.
fn bounded_non_zero_u64(
    name: &'static str,
    raw_value: u64,
    max: u64,
) -> Result<NonZeroU64, ConfigError> {
    let value = non_zero_u64(name, raw_value)?;
    if raw_value > max {
        return Err(ConfigError::BoundTooLarge {
            name,
            max: u128::from(max),
            value: u128::from(raw_value),
        });
    }
    Ok(value)
}

/// Returns a non-zero `usize` or the matching configuration error.
fn non_zero_usize(name: &'static str, value: usize) -> Result<NonZeroUsize, ConfigError> {
    NonZeroUsize::new(value).ok_or(ConfigError::ZeroBound { name })
}

/// Returns a bounded non-zero `usize` or the matching configuration error.
fn bounded_non_zero_usize(
    name: &'static str,
    raw_value: usize,
    max: usize,
) -> Result<NonZeroUsize, ConfigError> {
    let value = non_zero_usize(name, raw_value)?;
    if raw_value > max {
        return Err(ConfigError::BoundTooLarge {
            name,
            max: usize_to_u128(max),
            value: usize_to_u128(raw_value),
        });
    }
    Ok(value)
}

/// Converts `usize` to `u128` without loss.
fn usize_to_u128(value: usize) -> u128 {
    u128::try_from(value).expect("usize should fit into u128")
}

/// Parses allowed operation strings and rejects an empty operation set.
fn parse_allowed_operations(operations: Vec<String>) -> Result<Vec<AllowedOperation>, ConfigError> {
    // An entirely empty list (no entries, or the single empty entry an unset
    // environment variable produces) is a missing allowlist. An empty entry
    // mixed with real entries is an invalid operation, not something to skip
    // silently.
    if operations.iter().all(String::is_empty) {
        return Err(ConfigError::EmptyOperations);
    }
    if operations.len() > MAX_ALLOWED_OPERATIONS {
        return Err(ConfigError::TooManyAllowedOperations {
            max: usize_to_u128(MAX_ALLOWED_OPERATIONS),
            value: usize_to_u128(operations.len()),
        });
    }

    operations
        .into_iter()
        .map(|operation| AllowedOperation::parse(&operation))
        .collect()
}

/// Parses an allowed path string.
fn parse_allowed_path(path: &str) -> Result<OriginFormPath, ConfigError> {
    if has_forbidden_allowed_path_character(path) {
        return Err(ConfigError::InvalidAllowedPath {
            path: path.to_owned(),
        });
    }

    OriginFormPath::parse(path).map_err(|_error| ConfigError::InvalidAllowedPath {
        path: path.to_owned(),
    })
}

/// Parses an allowed path prefix string.
fn parse_allowed_prefix(prefix: &str) -> Result<OriginFormPath, ConfigError> {
    let path = parse_allowed_path(prefix)?;
    if path.as_str() == "/" || path.as_str().ends_with('/') {
        return Err(ConfigError::InvalidAllowedPrefix {
            path: prefix.to_owned(),
        });
    }
    Ok(path)
}

/// Returns true when configured path text includes non-path syntax.
fn has_forbidden_allowed_path_character(path: &str) -> bool {
    path.as_bytes()
        .iter()
        .copied()
        .any(|byte| matches!(byte, b'#' | b'?' | b'\\'))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[expect(
    clippy::inline_modules,
    reason = "inline tests keep file-local coverage ownership explicit"
)]
mod tests {
    use super::{
        AllowedOperation, AllowedPath, ConfigError, GatewayConfig, MAX_ALLOWED_METHOD_BYTES,
        MAX_ALLOWED_OPERATION_BYTES, MAX_ALLOWED_OPERATIONS, MAX_AUDIT_EVENT_BYTES,
        MAX_CONCURRENT_REQUESTS, MAX_REQUEST_BYTES, MAX_REQUEST_HEADER_BYTES,
        MAX_REQUEST_TIMEOUT_SECS, MAX_RESPONSE_BYTES, MAX_RESPONSE_HEADER_BYTES,
        MAX_UPSTREAM_ORIGIN_BYTES, MIN_AUDIT_EVENT_BYTES, ServeArgs, UpstreamOrigin,
        non_zero_usize, parse_allowed_operations, usize_to_u128,
    };
    use crate::target::{MAX_ORIGIN_FORM_PATH_BYTES, OriginFormPath, OriginFormQuery};
    use core::net::SocketAddr;
    use core::num::NonZeroU64;
    use core::time::Duration;
    use pretty_assertions::assert_eq;
    use std::path::PathBuf;

    /// A mutation that changes one serve argument bound.
    type MutateBound = fn(&mut ServeArgs);

    /// Builds valid serve args mirroring the documented defaults.
    pub(super) fn serve_args() -> ServeArgs {
        ServeArgs {
            allowed_operations: vec!["GET:exact:/v1/models".to_owned()],
            audit_log: PathBuf::from("/var/log/custode/proxy.ndjson"),
            bind: "127.0.0.1:8080".parse().expect("bind address should parse"),
            max_audit_event_bytes: MIN_AUDIT_EVENT_BYTES,
            max_concurrent_requests: 8,
            max_request_bytes: 10_485_760,
            max_request_header_bytes: 0x8000,
            max_response_bytes: 104_857_600,
            max_response_header_bytes: 0x0001_0000,
            request_timeout_secs: 120,
            upstream_origin: "https://api.openai.com".to_owned(),
        }
    }

    /// Parses a test origin-form path.
    fn origin_form_path(path: &str) -> OriginFormPath {
        OriginFormPath::parse(path).expect("test path should parse")
    }

    /// Parses a test origin-form query.
    fn origin_form_query(query: &str) -> OriginFormQuery {
        OriginFormQuery::parse(query).expect("test query should parse")
    }

    /// Converts a test `usize` into the expected `u128` value.
    fn expected_usize_u128(value: usize) -> u128 {
        u128::try_from(value).expect("usize should fit into u128")
    }

    /// Builds the longest valid origin accepted by the input byte cap.
    fn maximum_supported_origin() -> String {
        let labels = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(55),
        ];
        let origin = format!("https://{}", labels.join("."));
        assert_eq!(origin.len(), MAX_UPSTREAM_ORIGIN_BYTES);
        origin
    }

    #[test]
    fn configuration_limits_match_documented_values() {
        assert_eq!(MAX_ALLOWED_METHOD_BYTES, 64);
        assert_eq!(MAX_ALLOWED_OPERATION_BYTES, 4_160);
        assert_eq!(MAX_ALLOWED_OPERATIONS, 256);
        assert_eq!(MAX_AUDIT_EVENT_BYTES, 0x0010_0000);
        assert_eq!(MIN_AUDIT_EVENT_BYTES, 0x0001_0000);
        assert_eq!(MAX_REQUEST_BYTES, 0x4000_0000);
        assert_eq!(MAX_REQUEST_HEADER_BYTES, 0x0010_0000);
        assert_eq!(MAX_RESPONSE_BYTES, 0x4000_0000);
        assert_eq!(MAX_RESPONSE_HEADER_BYTES, 0x0010_0000);
        assert_eq!(MAX_REQUEST_TIMEOUT_SECS, 3_600);
        assert_eq!(MAX_UPSTREAM_ORIGIN_BYTES, 255);
    }

    #[test]
    fn allowed_path_requires_leading_slash() {
        assert!(matches!(
            AllowedPath::exact("v1/models"),
            Err(ConfigError::InvalidAllowedPath { .. }),
        ));
    }

    #[test]
    fn allowed_path_rejects_dot_segments_encoded_separators_and_invalid_percent_encoding() {
        for path in ["/v1/../models", "/v1/%2fmodels", "/v1/%zz"] {
            assert!(
                matches!(
                    AllowedPath::exact(path),
                    Err(ConfigError::InvalidAllowedPath { .. }),
                ),
                "path {path:?} should fail closed",
            );
        }
    }

    #[test]
    fn allowed_path_rejects_query_fragments_and_backslashes() {
        for path in ["/v1/models?limit=1", "/v1/models#fragment", "/v1\\models"] {
            assert!(
                matches!(
                    AllowedPath::exact(path),
                    Err(ConfigError::InvalidAllowedPath { .. }),
                ),
                "path {path:?} should fail closed",
            );
        }
    }

    #[test]
    fn allowed_prefix_rejects_root_and_trailing_slash() {
        for prefix in ["/", "/v1/"] {
            assert!(
                matches!(
                    AllowedPath::prefix(prefix),
                    Err(ConfigError::InvalidAllowedPrefix { path }) if path == prefix,
                ),
                "prefix {prefix:?} should fail closed",
            );
        }
    }

    #[test]
    fn allowed_prefix_rejects_invalid_path_before_prefix_shape() {
        assert!(matches!(
            AllowedPath::prefix("v1/models"),
            Err(ConfigError::InvalidAllowedPath { path }) if path == "v1/models",
        ));
    }

    #[test]
    fn exact_path_accepts_root_and_trailing_slash() {
        for path in ["/", "/v1/"] {
            let allowed = AllowedPath::exact(path).expect("exact path should parse");
            let incoming = origin_form_path(path);

            assert!(allowed.matches(&incoming));
        }
    }

    #[test]
    fn allowed_path_rejects_paths_over_the_supported_maximum() {
        let path = format!("/{}", "a".repeat(MAX_ORIGIN_FORM_PATH_BYTES));

        assert!(matches!(
            AllowedPath::exact(&path),
            Err(ConfigError::InvalidAllowedPath { .. }),
        ));
    }

    #[test]
    fn operation_accepts_text_at_the_supported_maximum() {
        let path = format!("/{}", "a".repeat(MAX_ORIGIN_FORM_PATH_BYTES - 1));
        let method_len = MAX_ALLOWED_OPERATION_BYTES
            .checked_sub(":exact:".len())
            .and_then(|budget| budget.checked_sub(path.len()))
            .expect("operation limit should include the fixed prefix");
        let method = "A".repeat(method_len);
        let raw = format!("{method}:exact:{path}");

        let operation = AllowedOperation::parse(&raw).expect("maximum operation should parse");
        let parsed_method =
            http::Method::from_bytes(method.as_bytes()).expect("test method should parse");
        let parsed_path = origin_form_path(&path);

        assert_eq!(raw.len(), MAX_ALLOWED_OPERATION_BYTES);
        assert!(operation.matches(&parsed_method, &parsed_path));
    }

    #[test]
    fn operation_rejects_text_over_the_supported_maximum() {
        let raw = format!("GET:exact:/{}", "a".repeat(MAX_ALLOWED_OPERATION_BYTES));

        assert!(matches!(
            AllowedOperation::parse(&raw),
            Err(ConfigError::AllowedOperationTooLong { max, value })
                if max == expected_usize_u128(MAX_ALLOWED_OPERATION_BYTES)
                    && value == expected_usize_u128(raw.len()),
        ));
    }

    #[test]
    fn operation_binds_method_to_path() {
        let operation =
            AllowedOperation::parse("GET:exact:/v1/models").expect("operation should parse");

        let path = origin_form_path("/v1/models");

        assert!(operation.matches(&http::Method::GET, &path));
        assert!(!operation.matches(&http::Method::POST, &path));
    }

    #[test]
    fn operation_accepts_exact_and_prefix_kinds() {
        let exact =
            AllowedOperation::parse("GET:exact:/v1/models").expect("exact operation should parse");
        let prefix = AllowedOperation::parse("POST:prefix:/v1/responses")
            .expect("prefix operation should parse");

        assert!(exact.matches(&http::Method::GET, &origin_form_path("/v1/models")));
        assert!(!exact.matches(&http::Method::GET, &origin_form_path("/v1/models/extra")));
        assert!(prefix.matches(&http::Method::POST, &origin_form_path("/v1/responses/1")));
    }

    #[test]
    fn operation_reports_exact_and_prefix_path_errors() {
        assert!(matches!(
            AllowedOperation::parse("GET:exact:v1/models"),
            Err(ConfigError::InvalidAllowedPath { path }) if path == "v1/models",
        ));
        assert!(matches!(
            AllowedOperation::parse("POST:prefix:/"),
            Err(ConfigError::InvalidAllowedPrefix { path }) if path == "/",
        ));
    }

    #[test]
    fn upstream_origin_rejects_path() {
        assert!(matches!(
            UpstreamOrigin::parse("https://api.openai.com/v1"),
            Err(ConfigError::UpstreamOriginHasComponents),
        ));
    }

    #[test]
    fn upstream_origin_accepts_the_maximum_supported_length() {
        let origin = maximum_supported_origin();

        let parsed = UpstreamOrigin::parse(&origin).expect("maximum origin should parse");

        assert_eq!(parsed.as_str(), origin);
    }

    #[test]
    fn upstream_origin_rejects_lengths_over_the_supported_maximum() {
        let origin = format!("{}a", maximum_supported_origin());

        assert!(matches!(
            UpstreamOrigin::parse(&origin),
            Err(ConfigError::UpstreamOriginTooLong { max, value })
                if max == expected_usize_u128(MAX_UPSTREAM_ORIGIN_BYTES)
                    && value == expected_usize_u128(origin.len()),
        ));
    }

    #[test]
    fn upstream_origin_rejects_wildcard_hosts() {
        for origin in ["https://*", "https://*.openai.com"] {
            assert!(
                matches!(
                    UpstreamOrigin::parse(origin),
                    Err(ConfigError::WildcardUpstreamHost),
                ),
                "origin {origin} should be rejected"
            );
        }
    }

    #[test]
    fn upstream_origin_rejects_zero_ports() {
        for origin in ["http://api.openai.com:0", "https://api.openai.com:0"] {
            assert!(
                matches!(
                    UpstreamOrigin::parse(origin),
                    Err(ConfigError::UpstreamOriginHasZeroPort),
                ),
                "origin {origin} should be rejected"
            );
        }
    }

    #[test]
    fn upstream_origin_rejects_credentials() {
        for origin in [
            "https://user:secret@api.openai.com",
            "https://user@api.openai.com",
            "https://:secret@api.openai.com",
        ] {
            assert!(
                matches!(
                    UpstreamOrigin::parse(origin),
                    Err(ConfigError::UpstreamOriginHasCredentials),
                ),
                "origin {origin} should be rejected"
            );
        }
    }

    #[test]
    fn upstream_origin_joins_path_and_query() {
        let origin =
            UpstreamOrigin::parse("https://api.example.com:8443").expect("origin should parse");

        let path = origin_form_path("/v1/models");
        let query = origin_form_query("limit=1");
        let encoded_query = origin_form_query("q='");
        let with_query = origin.join_path_query(&path, Some(&query));
        let with_encoded_query = origin.join_path_query(&path, Some(&encoded_query));
        let without_query = origin.join_path_query(&path, None);

        assert_eq!(
            with_query.as_str(),
            "https://api.example.com:8443/v1/models?limit=1"
        );
        assert_eq!(
            with_encoded_query.as_str(),
            "https://api.example.com:8443/v1/models?q=%27"
        );
        assert_eq!(
            without_query.as_str(),
            "https://api.example.com:8443/v1/models"
        );
    }

    #[test]
    fn response_body_bound_override_preserves_non_zero_value() {
        let config = GatewayConfig::for_runtime_test(
            PathBuf::from("/var/log/custode/proxy.ndjson"),
            "https://api.openai.com",
        )
        .with_max_response_bytes(NonZeroU64::new(4).expect("literal should be non-zero"));

        assert_eq!(config.max_response_bytes().get(), 4);
    }

    #[test]
    fn upstream_origin_as_str_has_no_trailing_slash() {
        let origin = UpstreamOrigin::parse("https://api.openai.com").expect("origin should parse");

        assert_eq!(origin.as_str(), "https://api.openai.com");
    }

    #[test]
    fn empty_operations_fail_closed() {
        for operations in [Vec::new(), vec![String::new()]] {
            assert!(matches!(
                parse_allowed_operations(operations),
                Err(ConfigError::EmptyOperations),
            ));
        }
    }

    #[test]
    fn operations_with_a_stray_empty_entry_fail_closed() {
        let operations = vec!["GET:exact:/v1/models".to_owned(), String::new()];

        assert!(matches!(
            parse_allowed_operations(operations),
            Err(ConfigError::InvalidAllowedOperation { .. }),
        ));
    }

    #[test]
    fn operation_sets_accept_the_maximum_supported_count() {
        let operations = vec!["GET:exact:/v1/models".to_owned(); MAX_ALLOWED_OPERATIONS];

        let parsed =
            parse_allowed_operations(operations).expect("maximum operation count should parse");

        assert_eq!(parsed.len(), MAX_ALLOWED_OPERATIONS);
    }

    #[test]
    fn operation_sets_reject_counts_over_the_supported_maximum() {
        let operations = vec![
            "GET:exact:/v1/models".to_owned();
            MAX_ALLOWED_OPERATIONS
                .checked_add(1)
                .expect("test count should fit usize")
        ];

        assert!(matches!(
            parse_allowed_operations(operations),
            Err(ConfigError::TooManyAllowedOperations { max, value })
                if max == expected_usize_u128(MAX_ALLOWED_OPERATIONS)
                    && value == expected_usize_u128(MAX_ALLOWED_OPERATIONS + 1),
        ));
    }

    #[test]
    fn operation_sets_still_report_empty_allowlists_before_count_bounds() {
        let operations = vec![
            String::new();
            MAX_ALLOWED_OPERATIONS
                .checked_add(1)
                .expect("test count should fit usize")
        ];

        assert!(matches!(
            parse_allowed_operations(operations),
            Err(ConfigError::EmptyOperations),
        ));
    }

    #[test]
    fn operation_rejects_unknown_kind() {
        assert!(matches!(
            AllowedOperation::parse("GET:glob:/v1/models"),
            Err(ConfigError::InvalidOperationKind { .. }),
        ));
    }

    #[test]
    fn operation_rejects_invalid_method() {
        assert!(matches!(
            AllowedOperation::parse("B@D:exact:/v1/models"),
            Err(ConfigError::InvalidMethod { .. }),
        ));
    }

    #[test]
    fn operation_rejects_connect_method() {
        assert!(matches!(
            AllowedOperation::parse("CONNECT:exact:/v1/models"),
            Err(ConfigError::UnsupportedMethod { method }) if method == "CONNECT",
        ));
    }

    #[test]
    fn operation_rejects_methods_over_the_supported_maximum() {
        let method = "A".repeat(MAX_ALLOWED_METHOD_BYTES + 1);
        let raw = format!("{method}:exact:/");

        assert!(matches!(
            AllowedOperation::parse(&raw),
            Err(ConfigError::MethodTooLong { max, value })
                if max == expected_usize_u128(MAX_ALLOWED_METHOD_BYTES)
                    && value == expected_usize_u128(method.len()),
        ));
    }

    #[test]
    fn zero_bounds_fail_closed() {
        assert!(matches!(
            non_zero_usize("CUSTODE_MAX_REQUEST_BYTES", 0),
            Err(ConfigError::ZeroBound {
                name: "CUSTODE_MAX_REQUEST_BYTES",
            }),
        ));
    }

    #[test]
    fn usize_to_u128_preserves_representative_values() {
        assert_eq!(usize_to_u128(0), 0);
        assert_eq!(usize_to_u128(1), 1);
        assert_eq!(usize_to_u128(usize::MAX), expected_usize_u128(usize::MAX));
    }

    #[test]
    fn too_large_serve_args_fail_closed_with_the_env_name() {
        let cases: [(&str, u128, u128, MutateBound); 7] = [
            (
                "CUSTODE_MAX_AUDIT_EVENT_BYTES",
                expected_usize_u128(MAX_AUDIT_EVENT_BYTES),
                expected_usize_u128(MAX_AUDIT_EVENT_BYTES + 1),
                |args| {
                    args.max_audit_event_bytes = MAX_AUDIT_EVENT_BYTES
                        .checked_add(1)
                        .expect("test max should fit usize");
                },
            ),
            (
                "CUSTODE_MAX_CONCURRENT_REQUESTS",
                expected_usize_u128(MAX_CONCURRENT_REQUESTS),
                expected_usize_u128(
                    MAX_CONCURRENT_REQUESTS
                        .checked_add(1)
                        .expect("test max should fit usize"),
                ),
                |args| {
                    args.max_concurrent_requests = MAX_CONCURRENT_REQUESTS
                        .checked_add(1)
                        .expect("test max should fit usize");
                },
            ),
            (
                "CUSTODE_MAX_REQUEST_BYTES",
                expected_usize_u128(MAX_REQUEST_BYTES),
                expected_usize_u128(MAX_REQUEST_BYTES + 1),
                |args| {
                    args.max_request_bytes = MAX_REQUEST_BYTES
                        .checked_add(1)
                        .expect("test max should fit usize");
                },
            ),
            (
                "CUSTODE_MAX_REQUEST_HEADER_BYTES",
                expected_usize_u128(MAX_REQUEST_HEADER_BYTES),
                expected_usize_u128(MAX_REQUEST_HEADER_BYTES + 1),
                |args| {
                    args.max_request_header_bytes = MAX_REQUEST_HEADER_BYTES
                        .checked_add(1)
                        .expect("test max should fit usize");
                },
            ),
            (
                "CUSTODE_MAX_RESPONSE_BYTES",
                u128::from(MAX_RESPONSE_BYTES),
                u128::from(MAX_RESPONSE_BYTES + 1),
                |args| {
                    args.max_response_bytes = MAX_RESPONSE_BYTES
                        .checked_add(1)
                        .expect("test max should fit u64");
                },
            ),
            (
                "CUSTODE_MAX_RESPONSE_HEADER_BYTES",
                expected_usize_u128(MAX_RESPONSE_HEADER_BYTES),
                expected_usize_u128(MAX_RESPONSE_HEADER_BYTES + 1),
                |args| {
                    args.max_response_header_bytes = MAX_RESPONSE_HEADER_BYTES
                        .checked_add(1)
                        .expect("test max should fit usize");
                },
            ),
            (
                "CUSTODE_REQUEST_TIMEOUT_SECS",
                u128::from(MAX_REQUEST_TIMEOUT_SECS),
                u128::from(MAX_REQUEST_TIMEOUT_SECS + 1),
                |args| {
                    args.request_timeout_secs = MAX_REQUEST_TIMEOUT_SECS
                        .checked_add(1)
                        .expect("test max should fit u64");
                },
            ),
        ];

        for (name, expected_max, expected_value, too_large_bound) in cases {
            let mut args = serve_args();
            too_large_bound(&mut args);

            let error = GatewayConfig::try_from(args).expect_err("large bound should fail");

            assert!(
                matches!(
                    error,
                    ConfigError::BoundTooLarge {
                        name: actual,
                        max,
                        value,
                    } if actual == name && max == expected_max && value == expected_value
                ),
                "bound {name} should fail closed"
            );
        }
    }

    #[test]
    fn too_small_audit_event_bound_fails_closed_with_the_env_name() {
        let mut args = serve_args();
        let too_small = MIN_AUDIT_EVENT_BYTES
            .checked_sub(1)
            .expect("minimum should be above zero");
        args.max_audit_event_bytes = too_small;

        let error = GatewayConfig::try_from(args).expect_err("small bound should fail");

        assert!(matches!(
            error,
            ConfigError::BoundTooSmall { name, min, value }
                if name == "CUSTODE_MAX_AUDIT_EVENT_BYTES"
                    && min == expected_usize_u128(MIN_AUDIT_EVENT_BYTES)
                    && value == expected_usize_u128(too_small),
        ));
    }

    #[test]
    fn serve_args_accept_the_supported_maximum_bounds() {
        let mut args = serve_args();
        args.max_audit_event_bytes = MAX_AUDIT_EVENT_BYTES;
        args.max_concurrent_requests = MAX_CONCURRENT_REQUESTS;
        args.max_request_bytes = MAX_REQUEST_BYTES;
        args.max_request_header_bytes = MAX_REQUEST_HEADER_BYTES;
        args.max_response_bytes = MAX_RESPONSE_BYTES;
        args.max_response_header_bytes = MAX_RESPONSE_HEADER_BYTES;
        args.request_timeout_secs = MAX_REQUEST_TIMEOUT_SECS;

        let config = GatewayConfig::try_from(args).expect("maximum bounds should parse");

        assert_eq!(config.max_audit_event_bytes().get(), MAX_AUDIT_EVENT_BYTES);
        assert_eq!(
            config.max_concurrent_requests().get(),
            MAX_CONCURRENT_REQUESTS
        );
        assert_eq!(config.max_request_bytes().get(), MAX_REQUEST_BYTES);
        assert_eq!(
            config.max_request_header_bytes().get(),
            MAX_REQUEST_HEADER_BYTES
        );
        assert_eq!(config.max_response_bytes().get(), MAX_RESPONSE_BYTES);
        assert_eq!(
            config.max_response_header_bytes().get(),
            MAX_RESPONSE_HEADER_BYTES
        );
        assert_eq!(
            config.request_timeout().as_duration(),
            Duration::from_secs(MAX_REQUEST_TIMEOUT_SECS)
        );
    }

    #[test]
    fn serve_args_convert_into_a_full_config() {
        let config = GatewayConfig::try_from(serve_args()).expect("valid args should convert");

        let operation = config
            .allowed_operations()
            .first()
            .expect("one operation should be configured");
        assert_eq!(config.allowed_operations().len(), 1);
        let path = origin_form_path("/v1/models");

        assert!(operation.matches(&http::Method::GET, &path));
        assert_eq!(
            config.audit_log(),
            &PathBuf::from("/var/log/custode/proxy.ndjson")
        );
        assert_eq!(
            config.bind(),
            "127.0.0.1:8080"
                .parse::<SocketAddr>()
                .expect("bind address should parse")
        );
        assert_eq!(config.max_audit_event_bytes().get(), MIN_AUDIT_EVENT_BYTES);
        assert_eq!(config.max_concurrent_requests().get(), 8);
        assert_eq!(config.max_request_bytes().get(), 10_485_760);
        assert_eq!(config.max_request_header_bytes().get(), 0x8000);
        assert_eq!(config.max_response_bytes().get(), 104_857_600);
        assert_eq!(config.max_response_header_bytes().get(), 0x0001_0000);
        assert_eq!(
            config.request_timeout().as_duration(),
            Duration::from_secs(120)
        );
        assert_eq!(config.upstream_origin().as_str(), "https://api.openai.com");
    }

    #[test]
    fn serve_args_reject_invalid_upstream_origins() {
        let mut args = serve_args();
        args.upstream_origin = "ftp://api.openai.com".to_owned();

        let error = GatewayConfig::try_from(args).expect_err("invalid origin should fail");

        assert!(matches!(
            error,
            ConfigError::UnsupportedUpstreamScheme { scheme } if scheme == "ftp",
        ));
    }

    #[test]
    fn zero_serve_args_fail_closed_with_the_env_name() {
        let cases: [(&str, MutateBound); 7] = [
            ("CUSTODE_MAX_AUDIT_EVENT_BYTES", |args| {
                args.max_audit_event_bytes = 0;
            }),
            ("CUSTODE_MAX_CONCURRENT_REQUESTS", |args| {
                args.max_concurrent_requests = 0;
            }),
            ("CUSTODE_MAX_REQUEST_BYTES", |args| {
                args.max_request_bytes = 0;
            }),
            ("CUSTODE_MAX_REQUEST_HEADER_BYTES", |args| {
                args.max_request_header_bytes = 0;
            }),
            ("CUSTODE_MAX_RESPONSE_BYTES", |args| {
                args.max_response_bytes = 0;
            }),
            ("CUSTODE_MAX_RESPONSE_HEADER_BYTES", |args| {
                args.max_response_header_bytes = 0;
            }),
            ("CUSTODE_REQUEST_TIMEOUT_SECS", |args| {
                args.request_timeout_secs = 0;
            }),
        ];

        for (name, zero_one_bound) in cases {
            let mut args = serve_args();
            zero_one_bound(&mut args);

            let error = GatewayConfig::try_from(args).expect_err("zero bound should fail");

            assert!(
                matches!(error, ConfigError::ZeroBound { name: actual } if actual == name),
                "bound {name} should fail closed"
            );
        }
    }

    #[test]
    fn operation_has_method_ignores_path() {
        let operation =
            AllowedOperation::parse("GET:exact:/v1/models").expect("operation should parse");

        assert!(operation.has_method(&http::Method::GET));
        assert!(!operation.has_method(&http::Method::POST));
    }

    #[test]
    fn operation_requires_method_kind_and_path() {
        for raw in ["", "GET", "GET:exact", "GET::/v1", ":exact:/v1"] {
            assert!(
                matches!(
                    AllowedOperation::parse(raw),
                    Err(ConfigError::InvalidAllowedOperation { .. }),
                ),
                "operation {raw:?} should be rejected"
            );
        }
    }

    #[test]
    fn upstream_origin_rejects_unparsable_urls() {
        assert!(matches!(
            UpstreamOrigin::parse("http://"),
            Err(ConfigError::InvalidUpstreamOrigin { .. }),
        ));
    }

    #[test]
    fn upstream_origin_rejects_unsupported_schemes() {
        assert!(matches!(
            UpstreamOrigin::parse("ftp://example.com"),
            Err(ConfigError::UnsupportedUpstreamScheme { scheme }) if scheme == "ftp",
        ));
    }

    #[test]
    fn upstream_origin_rejects_query_and_fragment() {
        for origin in [
            "https://api.openai.com?limit=1",
            "https://api.openai.com#section",
        ] {
            assert!(
                matches!(
                    UpstreamOrigin::parse(origin),
                    Err(ConfigError::UpstreamOriginHasComponents),
                ),
                "origin {origin} should be rejected"
            );
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[expect(
    clippy::inline_modules,
    reason = "inline proptests keep file-local coverage ownership explicit"
)]
mod proptests {
    use super::{
        AllowedOperation, AllowedPath, ConfigError, GatewayConfig, MAX_ALLOWED_METHOD_BYTES,
        MAX_ALLOWED_OPERATION_BYTES, MAX_ALLOWED_OPERATIONS, MAX_AUDIT_EVENT_BYTES,
        MAX_CONCURRENT_REQUESTS, MAX_REQUEST_BYTES, MAX_REQUEST_HEADER_BYTES,
        MAX_REQUEST_TIMEOUT_SECS, MAX_RESPONSE_BYTES, MAX_RESPONSE_HEADER_BYTES,
        MIN_AUDIT_EVENT_BYTES, ServeArgs, UpstreamOrigin, parse_allowed_operations,
        tests::serve_args, usize_to_u128,
    };
    use crate::target::{
        MAX_ORIGIN_FORM_PATH_BYTES, OriginFormPath, OriginFormQuery,
        testing::{origin_form_path_valid, url_preserved_origin_form_query_valid},
    };
    use ::http::Method;
    use core::iter;
    use core::net::SocketAddr;
    use core::num::NonZeroUsize;
    use core::time::Duration;
    use proptest::prelude::*;
    use proptest::{collection, option};
    use std::path::PathBuf;

    /// HTTP token methods drawn from common and custom token spellings,
    /// including methods that collide with the kind tokens.
    fn method_valid() -> impl Strategy<Value = String> {
        prop_oneof![
            4 => prop_oneof![
                Just("GET".to_owned()),
                Just("POST".to_owned()),
                Just("PUT".to_owned()),
                Just("DELETE".to_owned()),
                Just("PATCH".to_owned()),
            ],
            1 => "[A-Z]{3,10}",
            1 => prop_oneof![
                Just("exact".to_owned()),
                Just("prefix".to_owned()),
                Just("EXACT".to_owned()),
            ],
        ]
    }

    /// Valid HTTP token methods outside the gateway protocol.
    fn method_unsupported() -> impl Strategy<Value = String> {
        Just("CONNECT".to_owned())
    }

    /// Methods containing a representative non-token byte.
    fn method_invalid() -> impl Strategy<Value = String> {
        (
            "[A-Z]{0,4}",
            prop_oneof![Just('@'), Just('('), Just(' ')],
            "[A-Z]{0,4}",
        )
            .prop_map(|(head, invalid, tail)| format!("{head}{invalid}{tail}"))
    }

    /// Token methods exceeding the audited method domain.
    fn method_too_long() -> impl Strategy<Value = String> {
        (MAX_ALLOWED_METHOD_BYTES + 1..=MAX_ALLOWED_METHOD_BYTES + 16)
            .prop_map(|length| "A".repeat(length))
    }

    /// Operation match kinds accepted by the grammar.
    fn kind_valid() -> impl Strategy<Value = String> {
        prop_oneof![Just("exact".to_owned()), Just("prefix".to_owned())]
    }

    /// Allowed path segments that are not dot segments.
    fn allowed_path_segment_valid() -> impl Strategy<Value = String> {
        prop_oneof![
            4 => "[A-Za-z0-9_-]{1,8}",
            1 => prop_oneof![
                Just("...".to_owned()),
                Just("a.".to_owned()),
                Just(".a".to_owned()),
                Just("a.b".to_owned()),
            ],
        ]
    }

    /// Allowed paths built from valid path segments.
    fn allowed_path_plain() -> impl Strategy<Value = String> {
        collection::vec(allowed_path_segment_valid(), 1..4)
            .prop_map(|segments| format!("/{}", segments.join("/")))
    }

    /// Allowed paths, biased toward a colon suffix because everything after
    /// the second delimiter belongs to the path.
    fn allowed_path_valid() -> impl Strategy<Value = String> {
        prop_oneof![
            4 => allowed_path_plain(),
            1 => allowed_path_plain().prop_map(|path| format!("{path}:v1")),
        ]
    }

    /// Supported non-zero `u64` bounds biased toward the low boundary.
    fn bound_u64(max: u64) -> impl Strategy<Value = u64> {
        prop_oneof![1 => Just(1_u64), 4 => 1_u64..=max]
    }

    /// Supported non-zero `usize` bounds biased toward the low boundary.
    fn bound_usize(max: usize) -> impl Strategy<Value = usize> {
        prop_oneof![1 => Just(1_usize), 4 => 1_usize..=max]
    }

    /// Supported audit event byte bounds biased toward both accepted edges.
    fn audit_event_bound() -> impl Strategy<Value = usize> {
        prop_oneof![
            1 => Just(MIN_AUDIT_EVENT_BYTES),
            1 => Just(MAX_AUDIT_EVENT_BYTES),
            4 => MIN_AUDIT_EVENT_BYTES..=MAX_AUDIT_EVENT_BYTES,
        ]
    }

    /// Paths outside the configured allowed path grammar.
    fn allowed_path_invalid() -> impl Strategy<Value = String> {
        prop_oneof![
            "[A-Za-z0-9_.-][A-Za-z0-9/_.-]{0,12}",
            allowed_path_valid().prop_map(|path| format!("{path}/..")),
            allowed_path_valid().prop_map(|path| format!("{path}%2fchild")),
            allowed_path_valid().prop_map(|path| format!("{path}%zz")),
            allowed_path_valid().prop_map(|path| format!("{path}?limit=1")),
            allowed_path_valid().prop_map(|path| format!("{path}#fragment")),
            allowed_path_valid().prop_map(|path| format!("{path}\\child")),
            (MAX_ORIGIN_FORM_PATH_BYTES..=MAX_ORIGIN_FORM_PATH_BYTES + 64)
                .prop_map(|tail_len| format!("/{}", "a".repeat(tail_len))),
        ]
    }

    /// Paths outside the configured prefix grammar but valid as exact paths.
    fn allowed_prefix_invalid() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("/".to_owned()),
            allowed_path_valid().prop_map(|path| format!("{path}/")),
        ]
    }

    /// Allowed operation strings longer than the supported byte limit.
    fn operation_too_long() -> impl Strategy<Value = String> {
        (MAX_ALLOWED_OPERATION_BYTES..=MAX_ALLOWED_OPERATION_BYTES + 64)
            .prop_map(|tail_len| format!("GET:exact:/{}", "a".repeat(tail_len)))
    }

    /// Registrable-looking hostnames without wildcards.
    fn host_valid() -> impl Strategy<Value = String> {
        // Avoid the `xn--` IDNA prefix: those labels are interpreted as
        // Punycode and not every ASCII spelling is a valid IDNA label.
        let label = prop_oneof![
            "[a-wy-z][a-z0-9-]{0,8}[a-z0-9]",
            "x[a-mo-z0-9][a-z0-9-]{0,8}[a-z0-9]",
            "xn[a-z0-9][a-z0-9-]{0,7}[a-z0-9]",
            "xn-[a-z0-9]",
            "xn-[a-z0-9][a-z0-9-]{0,6}[a-z0-9]",
        ];
        collection::vec(label, 1..4).prop_map(|labels| labels.join("."))
    }

    /// Ports biased toward the boundary values.
    fn port_any() -> impl Strategy<Value = u16> {
        prop_oneof![
            1 => Just(1_u16),
            1 => Just(u16::MAX),
            3 => 1_u16..,
        ]
    }

    /// Valid origins: scheme, host, and optional port only.
    fn origin_valid() -> impl Strategy<Value = String> {
        (
            prop_oneof![Just("http"), Just("https")],
            host_valid(),
            option::of(port_any()),
        )
            .prop_map(|(scheme, host, port)| {
                port.map_or_else(
                    || format!("{scheme}://{host}"),
                    |port_number| format!("{scheme}://{host}:{port_number}"),
                )
            })
    }

    /// Invalid origins sampling representative rejection classes: wildcard
    /// hosts, zero ports, extra components, credentials, unsupported schemes, and
    /// unparsable spellings (hostless and scheme-relative).
    fn origin_invalid() -> impl Strategy<Value = String> {
        prop_oneof![
            host_valid().prop_map(|host| format!("https://*.{host}")),
            Just("https://*".to_owned()),
            host_valid().prop_map(|host| format!("https://{host}:0")),
            (host_valid(), "[a-z]{1,8}").prop_map(|(host, path)| format!("https://{host}/{path}")),
            (host_valid(), "[a-z]{1,8}")
                .prop_map(|(host, query)| { format!("https://{host}?{query}") }),
            (host_valid(), "[a-z]{1,8}")
                .prop_map(|(host, fragment)| { format!("https://{host}#{fragment}") }),
            (host_valid(), "[a-z]{1,8}").prop_map(|(user, host)| format!("https://{user}@{host}")),
            host_valid().prop_map(|host| format!("ftp://{host}")),
            Just("http://".to_owned()),
            host_valid(),
        ]
    }

    proptest! {
        #[test]
        fn parse_accepts_every_valid_operation(
            method in method_valid(),
            kind in kind_valid(),
            path in allowed_path_valid(),
        ) {
            let raw = format!("{method}:{kind}:{path}");

            prop_assert!(AllowedOperation::parse(&raw).is_ok());
        }

        #[test]
        fn parse_rejects_pathless_operations(
            method in method_valid(),
            kind in kind_valid(),
            path in allowed_path_invalid(),
        ) {
            let raw = format!("{method}:{kind}:{path}");

            prop_assert!(AllowedOperation::parse(&raw).is_err());
        }

        #[test]
        fn parse_rejects_invalid_prefix_operations(
            method in method_valid(),
            path in allowed_prefix_invalid(),
        ) {
            let raw = format!("{method}:prefix:{path}");

            prop_assert!(AllowedOperation::parse(&raw).is_err());
        }

        #[test]
        fn parse_rejects_unknown_kinds(
            method in method_valid(),
            kind in "[a-z]{1,8}",
            path in allowed_path_valid(),
        ) {
            prop_assume!(kind != "exact" && kind != "prefix");
            let raw = format!("{method}:{kind}:{path}");

            prop_assert!(AllowedOperation::parse(&raw).is_err());
        }

        #[test]
        fn parse_rejects_invalid_methods(
            method in method_invalid(),
            kind in kind_valid(),
            path in allowed_path_valid(),
        ) {
            let raw = format!("{method}:{kind}:{path}");

            let is_invalid_method = matches!(
                AllowedOperation::parse(&raw),
                Err(ConfigError::InvalidMethod { .. }),
            );
            prop_assert!(is_invalid_method);
        }

        #[test]
        fn parse_rejects_too_long_methods(
            method in method_too_long(),
            kind in kind_valid(),
            path in allowed_path_valid(),
        ) {
            let raw = format!("{method}:{kind}:{path}");
            let is_too_long_method = matches!(
                AllowedOperation::parse(&raw),
                Err(ConfigError::MethodTooLong { .. }),
            );
            prop_assert!(is_too_long_method);
        }

        #[test]
        fn parse_rejects_unsupported_methods(
            method in method_unsupported(),
            kind in kind_valid(),
            path in allowed_path_valid(),
        ) {
            let raw = format!("{method}:{kind}:{path}");

            let is_unsupported_method = matches!(
                AllowedOperation::parse(&raw),
                Err(ConfigError::UnsupportedMethod { .. }),
            );
            prop_assert!(is_unsupported_method);
        }

        #[test]
        fn parse_rejects_too_long_operations(raw in operation_too_long()) {
            let is_too_long = matches!(
                AllowedOperation::parse(&raw),
                Err(ConfigError::AllowedOperationTooLong { .. }),
            );
            prop_assert!(is_too_long);
        }

        #[test]
        fn parse_rejects_operations_with_missing_parts(
            method in method_valid(),
            kind in kind_valid(),
            path in allowed_path_valid(),
            missing in 0_u8..4,
        ) {
            let raw = match missing {
                0 => format!(":{kind}:{path}"),
                1 => format!("{method}::{path}"),
                2 => format!("{method}:{kind}:"),
                _ => format!("{method}:{kind}"),
            };

            let is_invalid_operation = matches!(
                AllowedOperation::parse(&raw),
                Err(ConfigError::InvalidAllowedOperation { .. }),
            );
            prop_assert!(is_invalid_operation);
        }

        #[test]
        fn parsed_operations_bind_the_method_to_the_path(
            method in method_valid(),
            kind in kind_valid(),
            path in allowed_path_valid(),
        ) {
            let raw = format!("{method}:{kind}:{path}");
            let operation = AllowedOperation::parse(&raw)
                .expect("generated operations should parse");
            let parsed_method = Method::from_bytes(method.as_bytes())
                .expect("generated methods are valid tokens");
            let other_method = Method::from_bytes(b"ZZ")
                .expect("two-letter tokens are valid methods");
            let parsed_path = OriginFormPath::parse(&path)
                .expect("generated paths should parse");

            prop_assert!(operation.has_method(&parsed_method));
            prop_assert!(!operation.has_method(&other_method));
            prop_assert!(operation.matches(&parsed_method, &parsed_path));
            prop_assert!(!operation.matches(&other_method, &parsed_path));
        }

        #[test]
        fn exact_paths_match_only_themselves(
            path in allowed_path_valid(),
            suffix in allowed_path_segment_valid(),
        ) {
            let allowed = AllowedPath::exact(&path).expect("generated path should parse");
            let child = format!("{path}/{suffix}");
            let extended = format!("{path}{suffix}");
            let parsed_path = OriginFormPath::parse(&path)
                .expect("generated paths should parse");
            let parsed_child = OriginFormPath::parse(&child)
                .expect("child path should parse");
            let parsed_extended = OriginFormPath::parse(&extended)
                .expect("extended path should parse");

            prop_assert!(allowed.matches(&parsed_path));
            prop_assert!(!allowed.matches(&parsed_child));
            prop_assert!(!allowed.matches(&parsed_extended));
        }

        #[test]
        fn parse_allowed_operations_rejects_empty_entries_and_absent_lists(
            operations in collection::vec(
                (method_valid(), kind_valid(), allowed_path_valid()),
                0..4,
            ),
            empty_entries in 0_usize..3,
        ) {
            let expected_count = operations.len();
            let mut raw: Vec<String> = operations
                .into_iter()
                .map(|(method, kind, path)| format!("{method}:{kind}:{path}"))
                .collect();
            raw.extend(iter::repeat_n(String::new(), empty_entries));

            let result = parse_allowed_operations(raw);

            if expected_count == 0 {
                let is_empty_error = matches!(result, Err(ConfigError::EmptyOperations));
                prop_assert!(is_empty_error);
            } else if empty_entries > 0 {
                let is_invalid_operation =
                    matches!(result, Err(ConfigError::InvalidAllowedOperation { .. }));
                prop_assert!(is_invalid_operation);
            } else {
                let parsed = result.expect("valid operations should parse");
                prop_assert_eq!(parsed.len(), expected_count);
            }
        }

        #[test]
        fn parse_allowed_operations_rejects_too_many_entries(extra in 1_usize..=16) {
            let count = MAX_ALLOWED_OPERATIONS
                .checked_add(extra)
                .expect("test operation count should fit usize");
            let raw = vec!["GET:exact:/v1/models".to_owned(); count];

            let is_too_many = matches!(
                parse_allowed_operations(raw),
                Err(ConfigError::TooManyAllowedOperations { .. }),
            );
            prop_assert!(is_too_many);
        }

        #[test]
        fn serve_args_with_non_zero_bounds_convert(
            port in port_any(),
            max_audit_event_bytes in audit_event_bound(),
            max_concurrent_requests in bound_usize(MAX_CONCURRENT_REQUESTS),
            max_request_bytes in bound_usize(MAX_REQUEST_BYTES),
            max_request_header_bytes in bound_usize(MAX_REQUEST_HEADER_BYTES),
            max_response_bytes in bound_u64(MAX_RESPONSE_BYTES),
            max_response_header_bytes in bound_usize(MAX_RESPONSE_HEADER_BYTES),
            request_timeout_secs in bound_u64(MAX_REQUEST_TIMEOUT_SECS),
            origin in origin_valid(),
        ) {
            let args = ServeArgs {
                allowed_operations: vec!["GET:exact:/v1/models".to_owned()],
                audit_log: PathBuf::from("/var/log/custode/proxy.ndjson"),
                bind: SocketAddr::from(([127, 0, 0, 1], port)),
                max_audit_event_bytes,
                max_concurrent_requests,
                max_request_bytes,
                max_request_header_bytes,
                max_response_bytes,
                max_response_header_bytes,
                request_timeout_secs,
                upstream_origin: origin.clone(),
            };

            let config = GatewayConfig::try_from(args)
                .expect("non-zero bounds should convert");

            prop_assert_eq!(config.allowed_operations().len(), 1);
            prop_assert_eq!(
                config.audit_log(),
                &PathBuf::from("/var/log/custode/proxy.ndjson")
            );
            prop_assert_eq!(config.bind().port(), port);
            prop_assert_eq!(config.max_audit_event_bytes().get(), max_audit_event_bytes);
            prop_assert_eq!(
                config.max_concurrent_requests().get(),
                max_concurrent_requests
            );
            prop_assert_eq!(config.max_request_bytes().get(), max_request_bytes);
            prop_assert_eq!(
                config.max_request_header_bytes().get(),
                max_request_header_bytes
            );
            prop_assert_eq!(config.max_response_bytes().get(), max_response_bytes);
            prop_assert_eq!(
                config.max_response_header_bytes().get(),
                max_response_header_bytes
            );
            prop_assert_eq!(
                config.request_timeout().as_duration(),
                Duration::from_secs(request_timeout_secs)
            );
            let expected_origin = UpstreamOrigin::parse(&origin)
                .expect("generated origins should parse");
            prop_assert_eq!(config.upstream_origin(), &expected_origin);
        }

        #[test]
        fn serve_args_with_a_zero_bound_fail_closed(zeroed in 0_u8..7) {
            let mut args = serve_args();
            let expected_name = match zeroed {
                0 => {
                    args.max_audit_event_bytes = 0;
                    "CUSTODE_MAX_AUDIT_EVENT_BYTES"
                }
                1 => {
                    args.max_concurrent_requests = 0;
                    "CUSTODE_MAX_CONCURRENT_REQUESTS"
                }
                2 => {
                    args.max_request_bytes = 0;
                    "CUSTODE_MAX_REQUEST_BYTES"
                }
                3 => {
                    args.max_request_header_bytes = 0;
                    "CUSTODE_MAX_REQUEST_HEADER_BYTES"
                }
                4 => {
                    args.max_response_bytes = 0;
                    "CUSTODE_MAX_RESPONSE_BYTES"
                }
                5 => {
                    args.max_response_header_bytes = 0;
                    "CUSTODE_MAX_RESPONSE_HEADER_BYTES"
                }
                _ => {
                    args.request_timeout_secs = 0;
                    "CUSTODE_REQUEST_TIMEOUT_SECS"
                }
            };

            let error = GatewayConfig::try_from(args)
                .expect_err("zero bounds should fail closed");

            let is_zero_bound =
                matches!(error, ConfigError::ZeroBound { name } if name == expected_name);
            prop_assert!(is_zero_bound);
        }

        #[test]
        fn serve_args_with_too_small_audit_event_bounds_fail_closed(
            max_audit_event_bytes in 1_usize..MIN_AUDIT_EVENT_BYTES,
        ) {
            let mut args = serve_args();
            args.max_audit_event_bytes = max_audit_event_bytes;

            let error = GatewayConfig::try_from(args)
                .expect_err("too-small audit event bound should fail");

            let is_too_small = matches!(
                error,
                ConfigError::BoundTooSmall { name, min, value }
                    if name == "CUSTODE_MAX_AUDIT_EVENT_BYTES"
                        && min == usize_to_u128(MIN_AUDIT_EVENT_BYTES)
                        && value == usize_to_u128(max_audit_event_bytes)
            );
            prop_assert!(is_too_small);
        }

        #[test]
        fn bound_overrides_preserve_non_zero_values(
            max_audit_event_bytes in bound_usize(MAX_AUDIT_EVENT_BYTES),
            max_response_header_bytes in bound_usize(MAX_RESPONSE_HEADER_BYTES),
            origin in origin_valid(),
        ) {
            let config = GatewayConfig::for_runtime_test(
                PathBuf::from("/var/log/custode/proxy.ndjson"),
                &origin,
            )
            .with_max_audit_event_bytes(
                NonZeroUsize::new(max_audit_event_bytes)
                    .expect("generated value should be non-zero"),
            )
            .with_max_response_header_bytes(
                NonZeroUsize::new(max_response_header_bytes)
                    .expect("generated value should be non-zero"),
            );

            prop_assert_eq!(config.max_audit_event_bytes().get(), max_audit_event_bytes);
            prop_assert_eq!(
                config.max_response_header_bytes().get(),
                max_response_header_bytes,
            );
        }

        #[test]
        fn prefix_matching_is_segment_bounded(
            prefix in allowed_path_valid(),
            suffix in allowed_path_segment_valid(),
        ) {
            let allowed = AllowedPath::prefix(&prefix).expect("generated prefix should parse");
            let child = format!("{prefix}/{suffix}");
            let sibling = format!("{prefix}{suffix}");
            let parsed_prefix = OriginFormPath::parse(&prefix)
                .expect("generated prefix should parse");
            let parsed_child = OriginFormPath::parse(&child)
                .expect("child path should parse");
            let parsed_sibling = OriginFormPath::parse(&sibling)
                .expect("sibling path should parse");

            prop_assert!(allowed.matches(&parsed_prefix));
            prop_assert!(allowed.matches(&parsed_child));
            prop_assert!(!allowed.matches(&parsed_sibling));
        }

        #[test]
        fn origin_parse_accepts_every_valid_origin(origin in origin_valid()) {
            prop_assert!(UpstreamOrigin::parse(&origin).is_ok());
        }

        #[test]
        fn origin_parse_rejects_every_invalid_origin(origin in origin_invalid()) {
            prop_assert!(UpstreamOrigin::parse(&origin).is_err());
        }

        #[test]
        fn join_path_query_preserves_origin_path_and_query(
            origin in origin_valid(),
            path in origin_form_path_valid(),
            query in option::of(url_preserved_origin_form_query_valid()),
        ) {
            let parsed = UpstreamOrigin::parse(&origin).expect("generated origin should parse");
            let parsed_path = OriginFormPath::parse(&path)
                .expect("generated path should parse");
            let parsed_query = query
                .as_deref()
                .map(OriginFormQuery::parse)
                .transpose()
                .expect("generated query should parse");

            let joined = parsed.join_path_query(&parsed_path, parsed_query.as_ref());

            let expected = query.as_deref().map_or_else(
                || format!("{}{path}", parsed.as_str()),
                |query_text| format!("{}{path}?{query_text}", parsed.as_str()),
            );
            prop_assert_eq!(joined.as_str(), expected.as_str());
        }
    }
}
