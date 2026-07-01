//! Header filtering and redaction.

use ::http::header::{AUTHORIZATION, CONNECTION, COOKIE, HOST, PROXY_AUTHORIZATION};
use ::http::{HeaderMap, HeaderName, HeaderValue};
use core::num::NonZeroUsize;
use thiserror::Error;

/// Gateway-owned provider authorization header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderAuthorization {
    /// Header name.
    name: HeaderName,
    /// Header value.
    value: HeaderValue,
}

/// Header handling error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum HeaderError {
    /// Connection header contained an invalid dynamic header name.
    #[error("connection header contained an invalid header name")]
    InvalidConnectionHeader,

    /// Headers exceeded the configured maximum.
    #[error("headers exceeded configured maximum")]
    TooLarge,
}

impl ProviderAuthorization {
    /// Returns the provider authorization header name.
    #[must_use]
    pub(crate) const fn name(&self) -> &HeaderName {
        &self.name
    }

    /// Creates gateway-owned provider authorization.
    #[must_use]
    pub(crate) const fn new(name: HeaderName, value: HeaderValue) -> Self {
        Self { name, value }
    }

    /// Returns the provider authorization header value.
    #[must_use]
    pub(crate) const fn value(&self) -> &HeaderValue {
        &self.value
    }
}

/// Returns the dynamic header names listed by `Connection`.
fn connection_header_names(headers: &HeaderMap) -> Result<Vec<HeaderName>, HeaderError> {
    let mut names = Vec::new();
    for raw_value in headers.get_all(CONNECTION) {
        let value_text = raw_value
            .to_str()
            .map_err(|_error| HeaderError::InvalidConnectionHeader)?;
        for raw_token in value_text.split(',') {
            let token_text = raw_token.trim();
            if token_text.is_empty() {
                return Err(HeaderError::InvalidConnectionHeader);
            }
            let name = HeaderName::from_bytes(token_text.as_bytes())
                .map_err(|_error| HeaderError::InvalidConnectionHeader)?;
            names.push(name);
        }
    }
    Ok(names)
}

/// Enforces the configured aggregate header byte limit.
fn enforce_header_limit(
    headers: &HeaderMap,
    max_header_bytes: NonZeroUsize,
) -> Result<(), HeaderError> {
    let mut bytes = 0_usize;
    for (name, value) in headers {
        bytes = bytes
            .checked_add(name.as_str().len())
            .and_then(|value_so_far| value_so_far.checked_add(value.as_bytes().len()))
            .ok_or(HeaderError::TooLarge)?;
        if bytes > max_header_bytes.get() {
            return Err(HeaderError::TooLarge);
        }
    }
    Ok(())
}

/// Applies request header filtering before upstream forwarding.
///
/// # Errors
///
/// Returns an error when the header set exceeds the configured byte bound or a
/// `Connection` header contains an invalid token.
pub(crate) fn forward_request_headers(
    incoming: &HeaderMap,
    max_header_bytes: NonZeroUsize,
    authorization: Option<&ProviderAuthorization>,
) -> Result<HeaderMap, HeaderError> {
    enforce_header_limit(incoming, max_header_bytes)?;
    let connection_headers = connection_header_names(incoming)?;

    let mut outgoing = HeaderMap::new();
    for (name, value) in incoming {
        if request_header_is_forwarded(name, &connection_headers) {
            outgoing.append(name, value.clone());
        }
    }

    if let Some(value) = authorization {
        outgoing.insert(value.name().clone(), value.value().clone());
    }

    Ok(outgoing)
}

/// Applies response header filtering before returning to the harness.
///
/// # Errors
///
/// Returns an error when the header set exceeds the configured byte bound or a
/// `Connection` header contains an invalid token.
pub(crate) fn forward_response_headers(
    incoming: &HeaderMap,
    max_header_bytes: NonZeroUsize,
) -> Result<HeaderMap, HeaderError> {
    enforce_header_limit(incoming, max_header_bytes)?;
    let connection_headers = connection_header_names(incoming)?;

    let mut outgoing = HeaderMap::new();
    for (name, value) in incoming {
        if !is_hop_by_hop(name, &connection_headers) {
            outgoing.append(name, value.clone());
        }
    }
    Ok(outgoing)
}

/// Returns true when the header is hop-by-hop or named by `Connection`.
fn is_hop_by_hop(name: &HeaderName, connection_headers: &[HeaderName]) -> bool {
    is_standard_hop_by_hop(name) || connection_headers.iter().any(|dynamic| dynamic == name)
}

/// Returns true when the header is an HTTP standard hop-by-hop header.
fn is_standard_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Returns true when a request header is safe to forward upstream.
fn request_header_is_forwarded(name: &HeaderName, connection_headers: &[HeaderName]) -> bool {
    !is_hop_by_hop(name, connection_headers)
        && *name != AUTHORIZATION
        && *name != COOKIE
        && *name != PROXY_AUTHORIZATION
        && *name != HOST
        && name.as_str() != "x-api-key"
}

#[cfg(test)]
mod tests;
