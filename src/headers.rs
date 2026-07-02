//! Header filtering and redaction.

use ::http::header::{CONNECTION, HOST};
use ::http::{HeaderMap, HeaderName};
use core::num::NonZeroUsize;
use thiserror::Error;

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
) -> Result<HeaderMap, HeaderError> {
    enforce_header_limit(incoming, max_header_bytes)?;
    let connection_headers = connection_header_names(incoming)?;

    let mut outgoing = HeaderMap::new();
    for (name, value) in incoming {
        if request_header_is_forwarded(name, &connection_headers) {
            outgoing.append(name, value.clone());
        }
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
    !is_hop_by_hop(name, connection_headers) && *name != HOST
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{HeaderError, forward_request_headers, forward_response_headers};
    use ::http::header::{AUTHORIZATION, CONNECTION, COOKIE, HOST, PROXY_AUTHORIZATION};
    use ::http::{HeaderMap, HeaderValue};
    use core::num::NonZeroUsize;
    use pretty_assertions::assert_eq;

    #[test]
    fn request_headers_strip_connection_named_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("X-Trace"));
        headers.insert("x-trace", HeaderValue::from_static("secret"));

        let forwarded = forward_request_headers(
            &headers,
            NonZeroUsize::new(1024).expect("literal should be non-zero"),
        )
        .expect("headers should fit");

        assert_eq!(forwarded.get("x-trace"), None);
    }

    #[test]
    fn request_headers_forward_provider_authorization() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer harness"));
        headers.insert("x-api-key", HeaderValue::from_static("harness-key"));
        headers.insert(COOKIE, HeaderValue::from_static("session=bad"));

        let forwarded = forward_request_headers(
            &headers,
            NonZeroUsize::new(1024).expect("literal should be non-zero"),
        )
        .expect("headers should fit");

        assert_eq!(
            forwarded.get(AUTHORIZATION),
            Some(&HeaderValue::from_static("Bearer harness")),
        );
        assert_eq!(
            forwarded.get("x-api-key"),
            Some(&HeaderValue::from_static("harness-key")),
        );
        assert_eq!(
            forwarded.get(COOKIE),
            Some(&HeaderValue::from_static("session=bad")),
        );
    }

    #[test]
    fn request_headers_strip_routing_and_proxy_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("proxy:8080"));
        headers.insert(PROXY_AUTHORIZATION, HeaderValue::from_static("Basic bad"));
        headers.insert("x-visible", HeaderValue::from_static("ok"));

        let forwarded = forward_request_headers(
            &headers,
            NonZeroUsize::new(1024).expect("literal should be non-zero"),
        )
        .expect("headers should fit");

        assert_eq!(
            forwarded.get("x-visible"),
            Some(&HeaderValue::from_static("ok")),
        );
        assert_eq!(forwarded.get(HOST), None);
        assert_eq!(forwarded.get(PROXY_AUTHORIZATION), None);
    }

    #[test]
    fn request_headers_reject_empty_connection_tokens() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("a,,b"));

        let result = forward_request_headers(
            &headers,
            NonZeroUsize::new(1024).expect("literal should be non-zero"),
        );
        let expected = Err(HeaderError::InvalidConnectionHeader);

        assert_eq!(result, expected);
    }

    #[test]
    fn request_headers_accept_sets_exactly_at_the_byte_limit() {
        let mut headers = HeaderMap::new();
        headers.insert("x-wide", HeaderValue::from_static("0123456789"));

        // The only header contributes 6 name bytes and 10 value bytes.
        let forwarded = forward_request_headers(
            &headers,
            NonZeroUsize::new(16).expect("literal should be non-zero"),
        )
        .expect("headers at the exact limit should fit");

        assert_eq!(
            forwarded.get("x-wide"),
            Some(&HeaderValue::from_static("0123456789")),
        );
    }

    #[test]
    fn request_headers_reject_sets_over_the_byte_limit() {
        let mut headers = HeaderMap::new();
        headers.insert("x-wide", HeaderValue::from_static("0123456789"));

        let result = forward_request_headers(
            &headers,
            NonZeroUsize::new(1).expect("literal should be non-zero"),
        );
        let expected = Err(HeaderError::TooLarge);

        assert_eq!(result, expected);
    }

    #[test]
    fn response_headers_reject_invalid_connection_tokens() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("x trace"));

        let result = forward_response_headers(
            &headers,
            NonZeroUsize::new(1024).expect("literal should be non-zero"),
        );
        let expected = Err(HeaderError::InvalidConnectionHeader);

        assert_eq!(result, expected);
    }

    #[test]
    fn response_headers_strip_connection_named_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, HeaderValue::from_static("X-Trace"));
        headers.insert("x-trace", HeaderValue::from_static("secret"));
        headers.insert("x-visible", HeaderValue::from_static("ok"));

        let forwarded = forward_response_headers(
            &headers,
            NonZeroUsize::new(1024).expect("literal should be non-zero"),
        )
        .expect("headers should fit");
        let expected = Some(&HeaderValue::from_static("ok"));

        assert_eq!(forwarded.get("x-trace"), None);
        assert_eq!(forwarded.get("x-visible"), expected);
    }
}
