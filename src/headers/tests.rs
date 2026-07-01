use super::{
    HeaderError, ProviderAuthorization, forward_request_headers, forward_response_headers,
};
use ::http::header::{AUTHORIZATION, CONNECTION, COOKIE};
use ::http::{HeaderMap, HeaderName, HeaderValue};
use core::num::NonZeroUsize;

#[test]
fn request_headers_strip_connection_named_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("X-Trace"));
    headers.insert("x-trace", HeaderValue::from_static("secret"));

    let forwarded = forward_request_headers(
        &headers,
        NonZeroUsize::new(1024).expect("literal should be non-zero"),
        None,
    )
    .expect("headers should fit");

    assert_eq!(forwarded.get("x-trace"), None);
}

#[test]
fn request_headers_strip_harness_credentials() {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer harness"));
    headers.insert("x-api-key", HeaderValue::from_static("harness-key"));
    headers.insert(COOKIE, HeaderValue::from_static("session=bad"));
    let authorization =
        ProviderAuthorization::new(AUTHORIZATION, HeaderValue::from_static("Bearer gateway"));

    let forwarded = forward_request_headers(
        &headers,
        NonZeroUsize::new(1024).expect("literal should be non-zero"),
        Some(&authorization),
    )
    .expect("headers should fit");

    assert_eq!(
        forwarded.get(AUTHORIZATION),
        Some(&HeaderValue::from_static("Bearer gateway")),
    );
    assert_eq!(forwarded.get("x-api-key"), None);
    assert_eq!(forwarded.get(COOKIE), None);
}

#[test]
fn request_headers_inject_gateway_x_api_key() {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer harness"));
    headers.insert("x-api-key", HeaderValue::from_static("harness-key"));
    let authorization = ProviderAuthorization::new(
        HeaderName::from_static("x-api-key"),
        HeaderValue::from_static("gateway-key"),
    );

    let forwarded = forward_request_headers(
        &headers,
        NonZeroUsize::new(1024).expect("literal should be non-zero"),
        Some(&authorization),
    )
    .expect("headers should fit");

    assert_eq!(forwarded.get(AUTHORIZATION), None);
    assert_eq!(
        forwarded.get("x-api-key"),
        Some(&HeaderValue::from_static("gateway-key")),
    );
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
