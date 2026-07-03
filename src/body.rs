//! Bounded body accounting helpers.

use axum::body::{Body, to_bytes};
use blake3::{Hash, Hasher};
use core::error::Error as CoreError;
use core::num::{NonZeroU64, NonZeroUsize};
use http_body_util::LengthLimitError;
use serde::{Serialize, Serializer};
use thiserror::Error;

/// Body bytes plus accounting metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AccountedBody {
    /// Raw body bytes.
    bytes: Vec<u8>,
    /// BLAKE3 digest for non-empty bodies.
    digest: Option<BodyDigest>,
}

/// BLAKE3 digest for observed non-empty body bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BodyDigest(Hash);

impl AccountedBody {
    /// Returns the byte count.
    #[must_use]
    pub(crate) fn byte_count(&self) -> u64 {
        u64::try_from(self.bytes.len()).unwrap_or(u64::MAX)
    }

    /// Returns the body bytes.
    #[must_use]
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the BLAKE3 digest when the body is non-empty.
    #[must_use]
    pub(crate) const fn digest(&self) -> Option<BodyDigest> {
        self.digest
    }

    /// Creates body accounting from bytes.
    #[must_use]
    fn from_bytes(bytes: Vec<u8>) -> Self {
        let digest = if bytes.is_empty() {
            None
        } else {
            Some(BodyDigest::from_bytes(&bytes))
        };
        Self { bytes, digest }
    }

    /// Reads and accounts for a request body.
    ///
    /// # Errors
    ///
    /// Returns an error when the body exceeds the configured bound or cannot be
    /// read.
    pub(crate) async fn read_request(
        body: Body,
        limit: NonZeroUsize,
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
    max_bytes: NonZeroU64,
}

impl ResponseAccount {
    /// Adds a response chunk to the account.
    ///
    /// # Errors
    ///
    /// Returns an error when the response body exceeds the configured bound.
    pub(crate) fn add_chunk(&mut self, chunk: &[u8]) -> Result<(), BodyError> {
        let chunk_len = chunk_len_u64(chunk);
        let next = self
            .bytes
            .checked_add(chunk_len)
            .ok_or(BodyError::ResponseTooLarge)?;
        if next > self.max_bytes.get() {
            return Err(BodyError::ResponseTooLarge);
        }
        self.bytes = next;
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
    pub(crate) fn new(max_bytes: NonZeroU64) -> Self {
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
    fn roomy_limit() -> NonZeroUsize {
        NonZeroUsize::new(1_024).expect("limit should be non-zero")
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
        let result = AccountedBody::read_request(
            Body::from("ab"),
            NonZeroUsize::new(1).expect("limit should be non-zero"),
        )
        .await;

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
        let mut account = ResponseAccount::new(NonZeroU64::new(5).expect("limit is non-zero"));

        let result = account.add_chunk(b"hello");

        assert_eq!(result, Ok(()));
        let (byte_count, digest) = account.into_digest_parts();
        assert_eq!(byte_count, 5);
        assert!(digest.is_some());
    }

    #[test]
    fn add_chunk_rejects_totals_over_the_limit() {
        let mut account = ResponseAccount::new(NonZeroU64::new(4).expect("limit is non-zero"));

        let result = account.add_chunk(b"hello");

        assert_eq!(result, Err(BodyError::ResponseTooLarge));
        assert_eq!(account.into_digest_parts(), (0, None));
    }

    #[test]
    fn add_chunk_rejects_accumulated_totals_over_the_limit() {
        let mut account = ResponseAccount::new(NonZeroU64::new(5).expect("limit is non-zero"));
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
    fn add_chunk_rejects_counter_overflow() {
        let mut account =
            ResponseAccount::new(NonZeroU64::new(u64::MAX).expect("limit is non-zero"));
        account.bytes = u64::MAX;

        let result = account.add_chunk(b"x");

        assert_eq!(result, Err(BodyError::ResponseTooLarge));
        let (byte_count, _digest) = account.into_digest_parts();
        assert_eq!(byte_count, u64::MAX);
    }

    #[test]
    fn finalize_digest_is_none_for_empty_responses() {
        let account = ResponseAccount::new(NonZeroU64::new(5).expect("limit is non-zero"));

        assert_eq!(account.into_digest_parts(), (0, None));
    }

    #[test]
    fn finalize_digest_hashes_accumulated_chunks() {
        let mut account = ResponseAccount::new(NonZeroU64::new(5).expect("limit is non-zero"));
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
