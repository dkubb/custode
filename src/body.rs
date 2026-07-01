//! Bounded body accounting helpers.

use axum::body::{Body, to_bytes};
use blake3::Hasher;
use core::error::Error as CoreError;
use core::num::{NonZeroU64, NonZeroUsize};
use http_body_util::LengthLimitError;
use thiserror::Error;

/// Body bytes plus accounting metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AccountedBody {
    /// Raw body bytes.
    bytes: Vec<u8>,
    /// BLAKE3 digest for non-empty bodies.
    digest: Option<String>,
}

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
    pub(crate) fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }

    /// Creates body accounting from bytes.
    #[must_use]
    fn from_bytes(bytes: Vec<u8>) -> Self {
        let digest = if bytes.is_empty() {
            None
        } else {
            let mut hasher = Hasher::new();
            hasher.update(&bytes);
            Some(hasher.finalize().to_hex().to_string())
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
        let chunk_len = u64::try_from(chunk.len()).map_err(|_error| BodyError::ResponseTooLarge)?;
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

    /// Returns the response byte count.
    #[must_use]
    pub(crate) const fn byte_count(&self) -> u64 {
        self.bytes
    }

    /// Finalizes the response digest.
    #[must_use]
    pub(crate) fn finalize_digest(&self) -> Option<String> {
        if self.bytes == 0 {
            None
        } else {
            Some(self.hasher.finalize().to_hex().to_string())
        }
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

impl RequestBodyError {
    /// Returns a stable audit error class.
    #[must_use]
    pub(crate) const fn error_class(&self) -> &'static str {
        if matches!(self, Self::Read { .. }) {
            "request_body_read_failed"
        } else {
            "request_body_too_large"
        }
    }
}

/// Body handling error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum BodyError {
    /// Response exceeded its configured maximum.
    #[error("response body exceeded configured maximum")]
    ResponseTooLarge,
}
