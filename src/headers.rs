//! Header filtering and redaction.

use ::http::header::{CONNECTION, CONTENT_LENGTH, HOST};
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

/// Request headers proven safe for upstream forwarding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ForwardedRequestHeaders {
    /// Filtered request headers.
    headers: HeaderMap,
}

impl ForwardedRequestHeaders {
    /// Returns the filtered request headers for tests and composition.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn as_header_map(&self) -> &HeaderMap {
        &self.headers
    }

    /// Consumes the witness and returns the filtered header map.
    #[must_use]
    pub(crate) fn into_header_map(self) -> HeaderMap {
        self.headers
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
    let max = max_header_bytes.get();
    let mut bytes = 0_usize;
    for (name, value) in headers {
        bytes = add_header_bytes(bytes, name.as_str().len(), max)?;
        bytes = add_header_bytes(bytes, value.as_bytes().len(), max)?;
    }
    Ok(())
}

/// Adds bytes after proving the configured aggregate bound still has room.
const fn add_header_bytes(bytes: usize, amount: usize, max: usize) -> Result<usize, HeaderError> {
    if amount > remaining_header_bytes(bytes, max) {
        return Err(HeaderError::TooLarge);
    }
    Ok(checked_header_bytes(bytes, amount))
}

/// Adds two header byte counts after the caller proves the sum fits.
const fn checked_header_bytes(bytes: usize, amount: usize) -> usize {
    bytes
        .checked_add(amount)
        .expect("bounded header byte count should not overflow")
}

/// Returns the remaining byte budget for a valid running header total.
const fn remaining_header_bytes(bytes: usize, max: usize) -> usize {
    max.checked_sub(bytes)
        .expect("running header byte count should stay within the limit")
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
) -> Result<ForwardedRequestHeaders, HeaderError> {
    enforce_header_limit(incoming, max_header_bytes)?;
    let connection_headers = connection_header_names(incoming)?;

    let mut outgoing = HeaderMap::new();
    for (name, value) in incoming {
        if request_header_is_forwarded(name, &connection_headers) {
            outgoing.append(name, value.clone());
        }
    }

    Ok(ForwardedRequestHeaders { headers: outgoing })
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
        if response_header_is_forwarded(name, &connection_headers) {
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

/// Returns true when a response header is safe to forward downstream.
fn response_header_is_forwarded(name: &HeaderName, connection_headers: &[HeaderName]) -> bool {
    !is_hop_by_hop(name, connection_headers) && *name != CONTENT_LENGTH
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[expect(
    clippy::inline_modules,
    reason = "inline tests keep file-local coverage ownership explicit"
)]
mod tests {
    use super::{HeaderError, forward_request_headers, forward_response_headers};
    use ::http::header::{
        AUTHORIZATION, CONNECTION, CONTENT_LENGTH, COOKIE, HOST, PROXY_AUTHORIZATION,
    };
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

        assert_eq!(forwarded.as_header_map().get("x-trace"), None);
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
            forwarded.as_header_map().get(AUTHORIZATION),
            Some(&HeaderValue::from_static("Bearer harness")),
        );
        assert_eq!(
            forwarded.as_header_map().get("x-api-key"),
            Some(&HeaderValue::from_static("harness-key")),
        );
        assert_eq!(
            forwarded.as_header_map().get(COOKIE),
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
            forwarded.as_header_map().get("x-visible"),
            Some(&HeaderValue::from_static("ok")),
        );
        assert_eq!(forwarded.as_header_map().get(HOST), None);
        assert_eq!(forwarded.as_header_map().get(PROXY_AUTHORIZATION), None);
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
    fn request_headers_reject_non_utf8_connection_values() {
        let mut headers = HeaderMap::new();
        let value = HeaderValue::from_bytes(b"\xff").expect("opaque header value should build");
        headers.insert(CONNECTION, value);

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
            forwarded.as_header_map().get("x-wide"),
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
    fn request_headers_reject_sets_whose_value_exceeds_the_remaining_limit() {
        let mut headers = HeaderMap::new();
        headers.insert("x-wide", HeaderValue::from_static("0123456789"));

        let result = forward_request_headers(
            &headers,
            NonZeroUsize::new(6).expect("literal should be non-zero"),
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

    #[test]
    fn response_headers_strip_content_length() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("5"));
        headers.insert("x-visible", HeaderValue::from_static("ok"));

        let forwarded = forward_response_headers(
            &headers,
            NonZeroUsize::new(1024).expect("literal should be non-zero"),
        )
        .expect("headers should fit");

        assert_eq!(forwarded.get(CONTENT_LENGTH), None);
        assert_eq!(
            forwarded.get("x-visible"),
            Some(&HeaderValue::from_static("ok"))
        );
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[expect(
    clippy::inline_modules,
    reason = "inline proptests keep file-local coverage ownership explicit"
)]
mod proptests {
    use super::{HeaderError, forward_request_headers, forward_response_headers};
    use ::http::header::{CONNECTION, CONTENT_LENGTH, HOST};
    use ::http::{HeaderMap, HeaderName, HeaderValue};
    use core::num::NonZeroUsize;
    use proptest::prelude::*;
    use proptest::{collection, option};

    /// Connection values with a representative invalid token: empty or
    /// containing a space.
    fn connection_value_invalid() -> impl Strategy<Value = String> {
        prop_oneof![
            "[a-z]{1,4},,[a-z]{1,4}",
            ",[a-z]{1,4}",
            "[a-z]{1,4},",
            "[a-z]{1,4} [a-z]{1,4}",
        ]
    }

    /// End-to-end header names that never collide with the hop-by-hop set,
    /// `Connection`, or `Host`.
    fn name_end_to_end() -> impl Strategy<Value = String> {
        "x-[a-z][a-z0-9-]{0,10}"
    }

    /// Every standard hop-by-hop header name other than `Connection`.
    fn name_hop_by_hop() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("keep-alive".to_owned()),
            Just("proxy-authenticate".to_owned()),
            Just("proxy-authorization".to_owned()),
            Just("te".to_owned()),
            Just("trailer".to_owned()),
            Just("transfer-encoding".to_owned()),
            Just("upgrade".to_owned()),
        ]
    }

    /// Visible ASCII header values.
    fn value_any() -> impl Strategy<Value = String> {
        "[!-~]{0,12}"
    }

    /// Builds a header map from end-to-end, hop-by-hop, `Connection`, and
    /// `Host` parts.
    fn header_map(
        end_to_end: &[(String, String)],
        hop_by_hop: &[(String, String)],
        connection_named: &[String],
        host: Option<&str>,
    ) -> HeaderMap {
        let mut incoming = HeaderMap::new();
        for (name, value) in end_to_end
            .iter()
            .chain(hop_by_hop)
            .map(|entry| (entry.0.as_str(), entry.1.as_str()))
        {
            incoming.append(
                HeaderName::from_bytes(name.as_bytes()).expect("generated names are valid"),
                HeaderValue::from_str(value).expect("generated values are valid"),
            );
        }
        if let Some(host_value) = host {
            incoming.insert(
                HOST,
                HeaderValue::from_str(host_value).expect("generated hosts are valid"),
            );
        }
        if !connection_named.is_empty() {
            incoming.insert(
                CONNECTION,
                HeaderValue::from_str(&connection_named.join(", "))
                    .expect("generated tokens are valid"),
            );
        }
        incoming
    }

    /// A roomy header byte limit for filters that should not hit the bound.
    fn roomy_limit() -> NonZeroUsize {
        NonZeroUsize::new(0x8000).expect("limit should be non-zero")
    }

    proptest! {
        #[test]
        fn request_filtering_strips_exactly_the_hop_by_hop_and_routing_headers(
            end_to_end in collection::vec((name_end_to_end(), value_any()), 0..4),
            hop_by_hop in collection::vec((name_hop_by_hop(), value_any()), 0..3),
            connection_named in collection::vec(name_end_to_end(), 0..3),
            host in option::of("[a-z]{1,8}"),
        ) {
            let incoming = header_map(
                &end_to_end,
                &hop_by_hop,
                &connection_named,
                host.as_deref(),
            );

            let forwarded = forward_request_headers(&incoming, roomy_limit())
                .expect("generated headers should fit");

            prop_assert!(forwarded.as_header_map().get(HOST).is_none());
            prop_assert!(forwarded.as_header_map().get(CONNECTION).is_none());
            for name in hop_by_hop.iter().map(|entry| entry.0.as_str()) {
                let message = format!("hop-by-hop {name} should be stripped");
                prop_assert!(!forwarded.as_header_map().contains_key(name), "{}", message);
            }
            for name in end_to_end.iter().map(|entry| entry.0.as_str()) {
                let stripped = connection_named.iter().any(|token| token == name);
                let expected: Vec<&HeaderValue> = if stripped {
                    Vec::new()
                } else {
                    incoming.get_all(name).iter().collect()
                };
                let actual: Vec<&HeaderValue> =
                    forwarded.as_header_map().get_all(name).iter().collect();
                prop_assert_eq!(actual, expected);
            }
        }

        #[test]
        fn response_filtering_preserves_host_and_strips_hop_by_hop(
            end_to_end in collection::vec((name_end_to_end(), value_any()), 0..4),
            hop_by_hop in collection::vec((name_hop_by_hop(), value_any()), 0..3),
            connection_named in collection::vec(name_end_to_end(), 0..3),
            host in option::of("[a-z]{1,8}"),
        ) {
            let incoming = header_map(
                &end_to_end,
                &hop_by_hop,
                &connection_named,
                host.as_deref(),
            );

            let forwarded = forward_response_headers(&incoming, roomy_limit())
                .expect("generated headers should fit");

            prop_assert_eq!(forwarded.get(HOST), incoming.get(HOST));
            prop_assert!(forwarded.get(CONNECTION).is_none());
            prop_assert!(forwarded.get(CONTENT_LENGTH).is_none());
            for name in hop_by_hop.iter().map(|entry| entry.0.as_str()) {
                let message = format!("hop-by-hop {name} should be stripped");
                prop_assert!(!forwarded.contains_key(name), "{}", message);
            }
            for name in end_to_end.iter().map(|entry| entry.0.as_str()) {
                let stripped =
                    connection_named.iter().any(|token| token == name) || name == "content-length";
                let expected: Vec<&HeaderValue> = if stripped {
                    Vec::new()
                } else {
                    incoming.get_all(name).iter().collect()
                };
                let actual: Vec<&HeaderValue> = forwarded.get_all(name).iter().collect();
                prop_assert_eq!(actual, expected);
            }
        }

        #[test]
        fn filtering_rejects_header_sets_over_the_byte_limit(
            name in "x-[a-z]{1,10}",
            value in "[a-z]{0,12}",
        ) {
            let mut incoming = HeaderMap::new();
            incoming.insert(
                HeaderName::from_bytes(name.as_bytes()).expect("generated names are valid"),
                HeaderValue::from_str(&value).expect("generated values are valid"),
            );
            let total = name
                .len()
                .checked_add(value.len())
                .expect("generated header sizes fit in usize");
            let limit = NonZeroUsize::new(
                total
                    .checked_sub(1)
                    .expect("generated names have at least three bytes"),
            )
            .expect("generated names have at least three bytes");

            let result = forward_request_headers(&incoming, limit);

            prop_assert_eq!(result, Err(HeaderError::TooLarge));
        }

        #[test]
        fn filtering_rejects_invalid_connection_values(
            connection_value in connection_value_invalid(),
        ) {
            let mut incoming = HeaderMap::new();
            incoming.insert(
                CONNECTION,
                HeaderValue::from_str(&connection_value).expect("generated values are valid"),
            );

            let result = forward_request_headers(&incoming, roomy_limit());

            prop_assert_eq!(result, Err(HeaderError::InvalidConnectionHeader));
        }
    }
}
