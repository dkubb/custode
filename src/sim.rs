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
use proptest::prelude::{Just, Strategy, any};
use proptest::{collection, prop_oneof};
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

/// One deterministic gateway scenario.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Scenario {
    /// Harness request shape.
    request: ScenarioRequest,
    /// Scripted upstream behavior.
    upstream: ScenarioUpstream,
}

/// Harness request shape for a deterministic gateway scenario.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ScenarioRequest {
    /// Request body.
    body: Vec<u8>,
    /// Request headers.
    headers: Vec<(String, String)>,
    /// Request method.
    method: Method,
    /// Request target.
    target: String,
}

/// Scripted upstream outcome for a deterministic gateway scenario.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScenarioUpstream {
    /// Return the fixed success response immediately.
    Respond,

    /// Return a timeout error immediately.
    Timeout,
}

/// Scripted upstream behavior for deterministic handler tests.
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

impl Scenario {
    /// Builds a deterministic gateway scenario.
    #[must_use]
    pub(super) const fn new(request: ScenarioRequest, upstream: ScenarioUpstream) -> Self {
        Self { request, upstream }
    }

    /// Returns the harness request shape.
    #[must_use]
    pub(super) const fn request(&self) -> &ScenarioRequest {
        &self.request
    }

    /// Returns the scripted upstream behavior.
    #[must_use]
    pub(super) const fn upstream(&self) -> ScenarioUpstream {
        self.upstream
    }
}

impl ScenarioRequest {
    /// Returns the request body.
    #[must_use]
    pub(super) fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the request headers.
    #[must_use]
    pub(super) fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Returns the request method.
    #[must_use]
    pub(super) const fn method(&self) -> &Method {
        &self.method
    }

    /// Builds a harness request shape.
    #[must_use]
    pub(super) fn new(
        body: Vec<u8>,
        headers: Vec<(String, String)>,
        method: Method,
        target: impl Into<String>,
    ) -> Self {
        Self {
            body,
            headers,
            method,
            target: target.into(),
        }
    }

    /// Returns the request target.
    #[must_use]
    pub(super) fn target(&self) -> &str {
        &self.target
    }
}

impl ScriptedUpstreamClient {
    /// Builds a scripted upstream client with explicit upstream behavior.
    #[must_use]
    pub(super) fn from_upstream(
        upstream: ScenarioUpstream,
    ) -> (Self, Arc<Mutex<Vec<RecordedUpstreamRequest>>>) {
        let behavior = match upstream {
            ScenarioUpstream::Respond => ScriptedUpstreamBehavior::Respond,
            ScenarioUpstream::Timeout => ScriptedUpstreamBehavior::Stall {
                duration: Duration::MAX,
            },
        };
        let requests = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                behavior,
                requests: Arc::clone(&requests),
            },
            requests,
        )
    }

    /// Builds a scripted upstream client and its request recorder.
    #[must_use]
    pub(super) fn new() -> (Self, Arc<Mutex<Vec<RecordedUpstreamRequest>>>) {
        Self::from_upstream(ScenarioUpstream::Respond)
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

/// Generates deterministic gateway scenarios.
pub(super) fn scenario_any() -> impl Strategy<Value = Scenario> {
    (
        scenario_body_any(),
        scenario_headers_any(),
        scenario_target_any(),
        scenario_upstream_any(),
    )
        .prop_map(|(body, headers, target, upstream)| {
            Scenario::new(
                ScenarioRequest::new(body, headers, Method::GET, target),
                upstream,
            )
        })
}

/// Generates bounded request bodies.
fn scenario_body_any() -> impl Strategy<Value = Vec<u8>> {
    collection::vec(any::<u8>(), 0..9)
}

/// Generates bounded request header sets.
fn scenario_headers_any() -> impl Strategy<Value = Vec<(String, String)>> {
    prop_oneof![
        Just(Vec::new()),
        Just(vec![
            ("authorization".to_owned(), "Bearer harness".to_owned()),
            ("x-request-id".to_owned(), "trace-1".to_owned()),
        ]),
        Just(vec![
            ("authorization".to_owned(), "Bearer harness".to_owned()),
            ("connection".to_owned(), "x-drop".to_owned()),
            ("host".to_owned(), "proxy:8080".to_owned()),
            ("proxy-authorization".to_owned(), "Basic leak".to_owned()),
            ("x-drop".to_owned(), "secret".to_owned()),
            ("x-request-id".to_owned(), "trace-1".to_owned()),
        ]),
        Just(vec![
            ("connection".to_owned(), "te, x-drop".to_owned()),
            ("cookie".to_owned(), "session=visible".to_owned()),
            ("te".to_owned(), "trailers".to_owned()),
            ("x-drop".to_owned(), "secret".to_owned()),
            ("x-visible".to_owned(), "ok".to_owned()),
        ]),
    ]
}

/// Generates allowed request targets.
fn scenario_target_any() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("/v1/models".to_owned()),
        Just("/v1/models?limit=1".to_owned()),
    ]
}

/// Generates deterministic upstream outcomes.
fn scenario_upstream_any() -> impl Strategy<Value = ScenarioUpstream> {
    prop_oneof![
        Just(ScenarioUpstream::Respond),
        Just(ScenarioUpstream::Timeout),
    ]
}
