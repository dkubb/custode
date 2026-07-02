//! Test-only deterministic runtime adapters.

#![expect(
    clippy::redundant_pub_crate,
    reason = "test adapters are shared by sibling test modules through the crate root"
)]

use crate::audit::{AuditError, AuditEvent, AuditTimestamp};
use crate::ports::{
    AuditSink, BoxFuture, Clock, UpstreamClient, UpstreamDeadline, UpstreamError,
    UpstreamErrorKind, UpstreamRequest, UpstreamResponse,
};
use axum::body::Bytes;
use core::future;
use core::time::Duration;
use futures_util::{StreamExt as _, stream};
use http::{Method, StatusCode};
use serde_json::Value;
use std::sync::{Arc, Mutex};

/// Fixed clock used by deterministic handler tests.
#[derive(Clone, Copy, Debug)]
pub(super) struct FixedClock;

/// In-memory audit sink used by deterministic handler tests.
#[derive(Clone, Debug)]
pub(super) struct MemoryAuditSink {
    /// Captured serialized audit events.
    events: Arc<Mutex<Vec<Value>>>,
}

/// Request observed by the scripted upstream client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RecordedUpstreamRequest {
    /// Upstream request body.
    body: Vec<u8>,
    /// Per-request upstream timeout deadline.
    deadline: UpstreamDeadline,
    /// Forwarded upstream request headers.
    headers: Vec<(String, String)>,
    /// Upstream request method.
    method: Method,
    /// Fully joined upstream URL.
    url: String,
}

/// Scripted upstream behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScriptedUpstreamBehavior {
    /// Return the fixed success response immediately.
    Respond,

    /// Simulate an upstream stall for the supplied duration.
    Stall {
        /// Simulated stall duration.
        duration: Duration,
    },
}

/// Scripted upstream client for deterministic handler tests.
#[derive(Clone, Debug)]
pub(super) struct ScriptedUpstreamClient {
    /// Scripted upstream behavior.
    behavior: ScriptedUpstreamBehavior,
    /// Captured upstream requests.
    requests: Arc<Mutex<Vec<RecordedUpstreamRequest>>>,
}

impl AuditSink for MemoryAuditSink {
    fn append_event<'future>(
        &'future self,
        event: &'future AuditEvent,
    ) -> BoxFuture<'future, Result<(), AuditError>> {
        let result = serde_json::to_value(event)
            .map_err(AuditError::Serialize)
            .map(|value| {
                self.events
                    .lock()
                    .expect("memory audit sink should not be poisoned")
                    .push(value);
            });
        Box::pin(future::ready(result))
    }
}

impl Clock for FixedClock {
    fn now(&self) -> AuditTimestamp {
        AuditTimestamp::for_test("2026-07-02T00:00:00.000000000Z")
    }
}

impl MemoryAuditSink {
    /// Builds an audit sink and its event recorder.
    #[must_use]
    pub(super) fn new() -> (Self, Arc<Mutex<Vec<Value>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                events: Arc::clone(&events),
            },
            events,
        )
    }
}

impl RecordedUpstreamRequest {
    /// Builds an expected upstream request record.
    #[must_use]
    pub(super) fn new(
        body: Vec<u8>,
        deadline: UpstreamDeadline,
        headers: Vec<(String, String)>,
        method: Method,
        url: impl Into<String>,
    ) -> Self {
        Self {
            body,
            deadline,
            headers,
            method,
            url: url.into(),
        }
    }
}

impl ScriptedUpstreamClient {
    /// Builds a scripted upstream client and its request recorder.
    #[must_use]
    pub(super) fn new() -> (Self, Arc<Mutex<Vec<RecordedUpstreamRequest>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                behavior: ScriptedUpstreamBehavior::Respond,
                requests: Arc::clone(&requests),
            },
            requests,
        )
    }

    /// Builds a scripted upstream client that stalls deterministically.
    #[must_use]
    pub(super) fn stalling(duration: Duration) -> (Self, Arc<Mutex<Vec<RecordedUpstreamRequest>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                behavior: ScriptedUpstreamBehavior::Stall { duration },
                requests: Arc::clone(&requests),
            },
            requests,
        )
    }
}

impl UpstreamClient for ScriptedUpstreamClient {
    fn send(
        &self,
        request: UpstreamRequest,
    ) -> BoxFuture<'_, Result<UpstreamResponse, UpstreamError>> {
        let mut headers = request
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value
                        .to_str()
                        .expect("test request header should be UTF-8")
                        .to_owned(),
                )
            })
            .collect::<Vec<_>>();
        headers.sort();
        let recorded = RecordedUpstreamRequest::new(
            request.body().to_vec(),
            request.deadline(),
            headers,
            request.method().clone(),
            request.url().to_string(),
        );
        self.requests
            .lock()
            .expect("scripted upstream should not be poisoned")
            .push(recorded);
        if let ScriptedUpstreamBehavior::Stall { duration } = self.behavior
            && duration >= request.deadline().timeout()
        {
            let error = UpstreamError::new(
                UpstreamErrorKind::Timeout,
                format!("scripted upstream stalled for {duration:?}"),
            );
            return Box::pin(future::ready(Err(error)));
        }
        let response = UpstreamResponse::new(
            StatusCode::CREATED,
            ::http::HeaderMap::new(),
            stream::iter([Ok(Bytes::from_static(b"scripted"))]).boxed(),
        );
        Box::pin(future::ready(Ok(response)))
    }
}
