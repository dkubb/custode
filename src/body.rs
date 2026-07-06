//! Bounded body accounting helpers.

use crate::config::{RequestBodyBytes, ResponseBodyBytes};
use axum::body::{Body, to_bytes};
use blake3::{Hash, Hasher};
use core::error::Error as CoreError;
use core::num::NonZeroU64;
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

/// Observed non-empty body accounting state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NonEmptyBodyObservation {
    /// Body digest.
    blake3: BodyDigest,
    /// Body byte count.
    bytes: NonZeroU64,
}

/// Observed response body bytes that exceeded the configured bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OversizedResponseBody {
    /// Observed response body summary at the overflow point.
    observation: NonEmptyBodyObservation,
}

/// Observed body accounting state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BodyObservation {
    /// Body was observed and empty.
    Empty,

    /// Body was observed and non-empty.
    NonEmpty(NonEmptyBodyObservation),
}

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

    /// Creates body accounting from bytes.
    #[must_use]
    const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the observed body accounting state.
    #[must_use]
    pub(crate) fn observation(&self) -> BodyObservation {
        NonZeroU64::new(self.byte_count()).map_or(BodyObservation::Empty, |bytes| {
            BodyObservation::NonEmpty(NonEmptyBodyObservation::from_bytes(&self.bytes, bytes))
        })
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
    /// Creates a body digest from complete non-empty test bytes.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn for_test(bytes: &[u8]) -> Self {
        NonEmptyBodyObservation::for_test(bytes).blake3()
    }

    /// Creates a body digest from complete non-empty body bytes.
    #[must_use]
    fn from_non_empty_bytes(bytes: &[u8]) -> Self {
        Self(blake3::hash(bytes))
    }

    /// Creates a body digest from a streaming hasher with non-empty bytes.
    #[must_use]
    fn from_non_empty_hasher(hasher: &Hasher) -> Self {
        Self(hasher.finalize())
    }

    /// Returns the digest as lowercase BLAKE3 hex.
    #[must_use]
    pub(crate) fn to_hex_string(self) -> String {
        self.0.to_hex().to_string()
    }
}

impl NonEmptyBodyObservation {
    /// Returns the observed BLAKE3 digest.
    #[must_use]
    pub(crate) const fn blake3(self) -> BodyDigest {
        self.blake3
    }

    /// Returns the observed byte count.
    #[must_use]
    pub(crate) const fn bytes(self) -> NonZeroU64 {
        self.bytes
    }

    /// Creates a non-empty observation from complete non-empty test bytes.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn for_test(bytes: &[u8]) -> Self {
        let byte_count = NonZeroU64::new(
            u64::try_from(bytes.len()).expect("test body length should fit in u64"),
        )
        .expect("test body should be non-empty");
        Self::from_bytes(bytes, byte_count)
    }

    /// Creates a non-empty observation from complete body bytes.
    #[must_use]
    fn from_bytes(bytes: &[u8], byte_count: NonZeroU64) -> Self {
        debug_assert_eq!(
            u64::try_from(bytes.len()).expect("slice length should fit in u64"),
            byte_count.get(),
            "body observation byte count should match body length",
        );
        Self {
            blake3: BodyDigest::from_non_empty_bytes(bytes),
            bytes: byte_count,
        }
    }

    /// Creates a non-empty observation from a streaming body hasher.
    #[must_use]
    fn from_hasher(hasher: &Hasher, byte_count: NonZeroU64) -> Self {
        Self {
            blake3: BodyDigest::from_non_empty_hasher(hasher),
            bytes: byte_count,
        }
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
    pub(crate) fn add_chunk(&mut self, chunk: &[u8]) -> Result<(), OversizedResponseBody> {
        let chunk_len = chunk_len_u64(chunk);
        let remaining = self
            .max_bytes
            .get()
            .checked_sub(self.bytes)
            .expect("response byte count should not exceed limit");
        if chunk_len > remaining {
            return Err(self.oversized_body(chunk, chunk_len));
        }
        self.bytes = self
            .bytes
            .checked_add(chunk_len)
            .expect("bounded response byte total should not overflow");
        self.hasher.update(chunk);
        Ok(())
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

    /// Returns the observed response body accounting state.
    #[must_use]
    pub(crate) fn observation(&self) -> BodyObservation {
        NonZeroU64::new(self.bytes).map_or(BodyObservation::Empty, |bytes| {
            BodyObservation::NonEmpty(NonEmptyBodyObservation::from_hasher(&self.hasher, bytes))
        })
    }

    /// Builds the observed oversized-body summary without mutating accepted state.
    #[must_use]
    fn oversized_body(&self, chunk: &[u8], chunk_len: u64) -> OversizedResponseBody {
        let bytes = self
            .bytes
            .checked_add(chunk_len)
            .expect("response byte total should not overflow");
        let non_empty_bytes =
            NonZeroU64::new(bytes).expect("oversized response body should include observed bytes");
        let mut hasher = self.hasher.clone();
        hasher.update(chunk);
        OversizedResponseBody::from_hasher(&hasher, non_empty_bytes)
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

impl OversizedResponseBody {
    /// Creates an oversized-body summary from a streaming body hasher.
    #[must_use]
    fn from_hasher(hasher: &Hasher, byte_count: NonZeroU64) -> Self {
        Self {
            observation: NonEmptyBodyObservation::from_hasher(hasher, byte_count),
        }
    }

    /// Returns the observed response body summary.
    #[must_use]
    pub(crate) const fn observation(self) -> NonEmptyBodyObservation {
        self.observation
    }
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
    use super::{
        AccountedBody, BodyDigest, BodyObservation, NonEmptyBodyObservation, RequestBodyError,
        ResponseAccount,
    };
    use crate::config::{RequestBodyBytes, ResponseBodyBytes};
    use axum::body::Body;
    use core::num::{NonZeroU64, NonZeroUsize};
    use futures_util::stream;
    use pretty_assertions::assert_eq;
    use std::io;

    /// BLAKE3 digest of `hello`, computed independently with `b3sum`.
    const HELLO_DIGEST: &str = "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f";

    /// Returns the observation for non-empty test bytes.
    fn non_empty_body(bytes: &[u8]) -> NonEmptyBodyObservation {
        NonEmptyBodyObservation::for_test(bytes)
    }

    /// Returns digest hex for assertion output.
    fn observation_digest_hex(observation: BodyObservation) -> Option<String> {
        match observation {
            BodyObservation::Empty => None,
            BodyObservation::NonEmpty(non_empty) => Some(non_empty.blake3().to_hex_string()),
        }
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

    #[test]
    fn body_digest_for_test_hashes_non_empty_bytes() {
        assert_eq!(BodyDigest::for_test(b"hello").to_hex_string(), HELLO_DIGEST);
    }

    #[test]
    fn accounted_body_bytes_preserve_empty_single_and_multi_byte_inputs() {
        for bytes in [Vec::new(), vec![1], b"hello".to_vec()] {
            let accounted = AccountedBody::from_bytes(bytes.clone());

            assert_eq!(accounted.bytes(), bytes.as_slice());
        }
    }

    #[tokio::test]
    async fn read_request_accounts_bytes_count_and_digest() {
        let accounted = AccountedBody::read_request(Body::from("hello"), roomy_limit())
            .await
            .expect("body should fit within the limit");

        assert_eq!(accounted.bytes(), b"hello");
        assert_eq!(accounted.byte_count(), 5);
        assert_eq!(
            observation_digest_hex(accounted.observation()).as_deref(),
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
        assert_eq!(accounted.observation(), BodyObservation::Empty);
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
        assert_eq!(
            account.observation(),
            BodyObservation::NonEmpty(non_empty_body(b"hello"))
        );
    }

    #[test]
    fn add_chunk_rejects_totals_over_the_limit() {
        let mut account = ResponseAccount::new(response_limit(4));

        let result = account.add_chunk(b"hello");

        let oversized = result.expect_err("chunk should exceed the response limit");

        assert_eq!(oversized.observation(), non_empty_body(b"hello"));
        assert_eq!(account.observation(), BodyObservation::Empty);
    }

    #[test]
    fn add_chunk_rejects_accumulated_totals_over_the_limit() {
        let mut account = ResponseAccount::new(response_limit(5));
        account
            .add_chunk(b"hell")
            .expect("first chunk should fit within the limit");

        let result = account.add_chunk(b"oo");

        let oversized = result.expect_err("chunk should exceed the accumulated response limit");

        assert_eq!(oversized.observation(), non_empty_body(b"helloo"));
        assert_eq!(
            account.observation(),
            BodyObservation::NonEmpty(non_empty_body(b"hell"))
        );
    }

    #[test]
    fn finalize_digest_is_none_for_empty_responses() {
        let account = ResponseAccount::new(response_limit(5));

        assert_eq!(account.observation(), BodyObservation::Empty);
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

        assert_eq!(
            observation_digest_hex(account.observation()).as_deref(),
            Some(HELLO_DIGEST)
        );
    }
}
