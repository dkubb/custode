//! Runtime port values.

use crate::allowlist::AcceptedTarget;
use crate::body::AccountedBody;
use crate::config::UpstreamOrigin;
use http::{HeaderMap, Method};
use url::Url;

/// Request passed to the upstream client port.
#[derive(Debug)]
pub(crate) struct UpstreamRequest {
    /// Upstream request body bytes.
    body: Vec<u8>,
    /// Upstream request headers.
    headers: HeaderMap,
    /// Upstream request method.
    method: Method,
    /// Fully joined upstream URL.
    url: Url,
}

impl UpstreamRequest {
    /// Returns the upstream request body.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    /// Creates an upstream request from the configured origin and accepted target.
    #[must_use]
    pub(crate) fn from_target(
        method: Method,
        origin: &UpstreamOrigin,
        target: &AcceptedTarget,
        headers: HeaderMap,
        body: &AccountedBody,
    ) -> Self {
        Self {
            body: body.bytes().to_vec(),
            headers,
            method,
            url: origin.join_path_query(target.path(), target.query()),
        }
    }

    /// Consumes the request into upstream adapter parts.
    #[must_use]
    pub(crate) fn into_parts(self) -> (Method, Url, HeaderMap, Vec<u8>) {
        (self.method, self.url, self.headers, self.body)
    }

    /// Returns the upstream request method.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the upstream request URL.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn url(&self) -> &Url {
        &self.url
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod proptests {
    use super::UpstreamRequest;
    use crate::allowlist::AcceptedTarget;
    use crate::body::AccountedBody;
    use crate::config::UpstreamOrigin;
    use ::http::{HeaderMap, Method};
    use axum::body::Body;
    use core::num::NonZeroUsize;
    use proptest::prelude::*;
    use tokio::runtime::Runtime;

    proptest! {
        #[test]
        fn from_target_preserves_accepted_target(query in prop::option::of("[a-z0-9=&]{0,16}")) {
            let runtime = Runtime::new()
                .expect("runtime should build");
            let body = runtime.block_on(AccountedBody::read_request(
                Body::from("payload"),
                NonZeroUsize::new(16).expect("limit should be non-zero"),
            ))
                .expect("request body should be accounted");
            let origin = UpstreamOrigin::parse("https://api.openai.com")
                .expect("origin should parse");
            let target = AcceptedTarget::new("/v1/models", query.as_deref())
                .expect("target should parse");

            let request = UpstreamRequest::from_target(
                Method::POST,
                &origin,
                &target,
                HeaderMap::new(),
                &body,
            );

            prop_assert_eq!(request.method(), &Method::POST);
            prop_assert_eq!(request.url().path(), target.path());
            prop_assert_eq!(request.url().query(), target.query());
            prop_assert_eq!(request.body(), b"payload");
        }
    }
}
