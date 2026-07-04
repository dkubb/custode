//! Bounded body accounting helpers.

use crate::config::{RequestBodyBytes, ResponseBodyBytes};
use axum::body::{Body, to_bytes};
use blake3::{Hash, Hasher};
use core::error::Error as CoreError;
use http_body_util::LengthLimitError;
use serde::{Serialize, Serializer};
use thiserror::Error;

/// Accounted request body bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AccountedBody {
    /// Raw body bytes.
    bytes: Vec<u8>,
}

/// BLAKE3 digest for observed non-empty body bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BodyDigest(Hash);

impl AccountedBody {
    /// Returns the byte count.
    #[must_use]
    pub(crate) fn byte_count(&self) -> u64 {
        u64::try_from(self.bytes.len()).expect("bounded body byte count should fit in u64")
    }

    /// Returns the body bytes.
    #[must_use]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the BLAKE3 digest when the body is non-empty.
    #[must_use]
    pub(crate) fn digest(&self) -> Option<BodyDigest> {
        if self.bytes.is_empty() {
            None
        } else {
            Some(BodyDigest::from_bytes(&self.bytes))
        }
    }

    /// Creates body accounting from bytes.
    #[must_use]
    const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Reads and accounts for a request body.
    ///
    /// # Errors
    ///
    /// Returns an error when the body exceeds the configured bound or cannot be
    /// read.
    pub(crate) async fn read_request(
        body: Body,
        limit: RequestBodyBytes,
    ) -> Result<Self, RequestBodyError> {
        let bytes = to_bytes(body, limit.get()).await.map_err(|source| {
            if source
                .source()
                .is_some_and(<dyn CoreError + 'static>::is::<LengthLimitError>)
            {
                RequestBodyError::TooLarge
            } else {
                RequestBodyError::Read { source }
            }
        })?;
        Ok(Self::from_bytes(bytes.to_vec()))
    }
}

impl BodyDigest {
    /// Creates a body digest from complete body bytes.
    #[must_use]
    pub(crate) fn from_bytes(bytes: &[u8]) -> Self {
        Self(blake3::hash(bytes))
    }

    /// Creates a body digest from a streaming hasher.
    #[must_use]
    fn from_hasher(hasher: &Hasher) -> Self {
        Self(hasher.finalize())
    }

    /// Returns the digest as lowercase BLAKE3 hex.
    #[must_use]
    pub(crate) fn to_hex_string(self) -> String {
        self.0.to_hex().to_string()
    }
}

impl Serialize for BodyDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex_string())
    }
}

/// Streaming response body account.
#[derive(Debug)]
pub(crate) struct ResponseAccount {
    /// Accounted response bytes.
    bytes: u64,
    /// Streaming BLAKE3 hasher.
    hasher: Hasher,
    /// Maximum allowed response bytes.
    max_bytes: ResponseBodyBytes,
}

impl ResponseAccount {
    /// Adds a response chunk to the account.
    ///
    /// # Errors
    ///
    /// Returns an error when the response body exceeds the configured bound.
    pub(crate) fn add_chunk(&mut self, chunk: &[u8]) -> Result<(), BodyError> {
        let chunk_len = chunk_len_u64(chunk);
        let remaining = self
            .max_bytes
            .get()
            .checked_sub(self.bytes)
            .expect("response byte count should not exceed limit");
        if chunk_len > remaining {
            return Err(BodyError::ResponseTooLarge);
        }
        self.bytes = self
            .bytes
            .checked_add(chunk_len)
            .expect("bounded response byte total should not overflow");
        self.hasher.update(chunk);
        Ok(())
    }

    /// Consumes the account into its response byte count and digest.
    #[must_use]
    pub(crate) fn into_digest_parts(self) -> (u64, Option<BodyDigest>) {
        let digest = if self.bytes == 0 {
            None
        } else {
            Some(BodyDigest::from_hasher(&self.hasher))
        };
        (self.bytes, digest)
    }

    /// Creates a response account.
    #[must_use]
    pub(crate) fn new(max_bytes: ResponseBodyBytes) -> Self {
        Self {
            bytes: 0,
            hasher: Hasher::new(),
            max_bytes,
        }
    }
}

/// Request body handling error.
#[derive(Debug, Error)]
pub(crate) enum RequestBodyError {
    /// Body could not be read.
    #[error("request body read failed: {source}")]
    Read {
        /// Axum body source error.
        source: axum::Error,
    },

    /// Request body exceeded its configured maximum.
    #[error("request body exceeded configured maximum")]
    TooLarge,
}

/// Body handling error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum BodyError {
    /// Response exceeded its configured maximum.
    #[error("response body exceeded configured maximum")]
    ResponseTooLarge,
}

/// Returns a chunk length representable in the response byte counter.
fn chunk_len_u64(chunk: &[u8]) -> u64 {
    u64::try_from(chunk.len()).expect("slice length should fit in u64")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[expect(
    clippy::inline_modules,
    reason = "inline tests keep file-local coverage ownership explicit"
)]
mod tests {
    use super::{AccountedBody, BodyDigest, BodyError, RequestBodyError, ResponseAccount};
    use crate::config::{RequestBodyBytes, ResponseBodyBytes};
    use axum::body::Body;
    use core::num::{NonZeroU64, NonZeroUsize};
    use futures_util::stream;
    use pretty_assertions::assert_eq;
    use std::io;

    /// BLAKE3 digest of `hello`, computed independently with `b3sum`.
    const HELLO_DIGEST: &str = "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f";

    /// Returns digest hex for assertion output.
    fn digest_hex(digest: Option<BodyDigest>) -> Option<String> {
        digest.map(BodyDigest::to_hex_string)
    }

    /// A roomy body limit for tests that should not hit the bound.
    fn request_limit(value: usize) -> RequestBodyBytes {
        RequestBodyBytes::for_test(NonZeroUsize::new(value).expect("limit should be non-zero"))
    }

    /// A response body limit for tests.
    fn response_limit(value: u64) -> ResponseBodyBytes {
        ResponseBodyBytes::for_test(NonZeroU64::new(value).expect("limit should be non-zero"))
    }

    /// A roomy request body limit for tests that should not hit the bound.
    fn roomy_limit() -> RequestBodyBytes {
        request_limit(1_024)
    }

    #[tokio::test]
    async fn read_request_accounts_bytes_count_and_digest() {
        let accounted = AccountedBody::read_request(Body::from("hello"), roomy_limit())
            .await
            .expect("body should fit within the limit");

        assert_eq!(accounted.bytes(), b"hello");
        assert_eq!(accounted.byte_count(), 5);
        assert_eq!(
            digest_hex(accounted.digest()).as_deref(),
            Some(HELLO_DIGEST)
        );
    }

    #[tokio::test]
    async fn read_request_gives_empty_bodies_no_digest() {
        let accounted = AccountedBody::read_request(Body::empty(), roomy_limit())
            .await
            .expect("empty body should fit within the limit");

        assert_eq!(accounted.bytes(), b"");
        assert_eq!(accounted.byte_count(), 0);
        assert_eq!(accounted.digest(), None);
    }

    #[tokio::test]
    async fn read_request_rejects_bodies_over_the_limit() {
        let result = AccountedBody::read_request(Body::from("ab"), request_limit(1)).await;

        assert!(matches!(result, Err(RequestBodyError::TooLarge)));
    }

    #[tokio::test]
    async fn read_request_reports_stream_read_failures() {
        let body = Body::from_stream(stream::iter([Err::<Vec<u8>, io::Error>(io::Error::other(
            "connection reset",
        ))]));

        let result = AccountedBody::read_request(body, roomy_limit()).await;

        assert!(matches!(result, Err(RequestBodyError::Read { .. })));
    }

    #[test]
    fn add_chunk_accepts_chunks_up_to_the_limit() {
        let mut account = ResponseAccount::new(response_limit(5));

        let result = account.add_chunk(b"hello");

        assert_eq!(result, Ok(()));
        let (byte_count, digest) = account.into_digest_parts();
        assert_eq!(byte_count, 5);
        assert!(digest.is_some());
    }

    #[test]
    fn add_chunk_rejects_totals_over_the_limit() {
        let mut account = ResponseAccount::new(response_limit(4));

        let result = account.add_chunk(b"hello");

        assert_eq!(result, Err(BodyError::ResponseTooLarge));
        assert_eq!(account.into_digest_parts(), (0, None));
    }

    #[test]
    fn add_chunk_rejects_accumulated_totals_over_the_limit() {
        let mut account = ResponseAccount::new(response_limit(5));
        account
            .add_chunk(b"hell")
            .expect("first chunk should fit within the limit");

        let result = account.add_chunk(b"oo");

        assert_eq!(result, Err(BodyError::ResponseTooLarge));
        let (byte_count, digest) = account.into_digest_parts();
        assert_eq!(byte_count, 4);
        assert!(digest.is_some());
    }

    #[test]
    fn finalize_digest_is_none_for_empty_responses() {
        let account = ResponseAccount::new(response_limit(5));

        assert_eq!(account.into_digest_parts(), (0, None));
    }

    #[test]
    fn finalize_digest_hashes_accumulated_chunks() {
        let mut account = ResponseAccount::new(response_limit(5));
        account
            .add_chunk(b"hel")
            .expect("first chunk should fit within the limit");
        account
            .add_chunk(b"lo")
            .expect("second chunk should fit within the limit");

        let (_byte_count, digest) = account.into_digest_parts();
        assert_eq!(digest_hex(digest).as_deref(), Some(HELLO_DIGEST));
    }
}
