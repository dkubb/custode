//! Test-only deterministic runtime adapters.

#![expect(
    clippy::redundant_pub_crate,
    reason = "test adapters are shared by sibling test modules through the crate root"
)]

use crate::audit::{AuditError, AuditEvent, AuditTimestamp};
use crate::ports::{
    AuditSink, BoxFuture, Clock, UpstreamBodyError, UpstreamClient, UpstreamDeadline,
    UpstreamError, UpstreamErrorKind, UpstreamRequest, UpstreamResponse,
};
use axum::body::Bytes;
use core::future;
use core::num::NonZeroUsize;
use core::time::Duration;
use futures_util::{StreamExt as _, stream};
use http::{Method, StatusCode};
use proptest::prelude::{Just, Strategy, any};
use proptest::sample::select;
use proptest::{collection, prop_oneof};
use serde_json::Value;
use std::io;
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, timeout};

/// Fixed clock used by deterministic handler tests.
#[derive(Clone, Copy, Debug)]
pub(super) struct FixedClock;

/// In-memory audit sink used by deterministic handler tests.
#[derive(Clone, Debug)]
pub(super) struct MemoryAuditSink {
    /// Number of audit events observed by this sink.
    event_count: Arc<Mutex<usize>>,
    /// Captured serialized audit events.
    events: Arc<Mutex<Vec<Value>>>,
    /// Audit event ordinal that should fail instead of recording.
    fail_on_event: Option<NonZeroUsize>,
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
    /// Gateway admission state.
    admission: ScenarioAdmission,
    /// Audit sink behavior.
    audit: ScenarioAudit,
    /// Scenario byte bounds.
    bounds: ScenarioBounds,
    /// Downstream response consumption behavior.
    downstream: ScenarioDownstream,
    /// Harness request shape.
    request: ScenarioRequest,
    /// Scripted upstream behavior.
    upstream: ScenarioUpstream,
}

/// Product of deterministic scenario fault-class axes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ScenarioClass {
    /// Gateway admission state.
    admission: ScenarioAdmission,
    /// Audit sink behavior.
    audit: ScenarioAudit,
    /// Scenario byte bounds.
    bounds: ScenarioBounds,
    /// Downstream response consumption behavior.
    downstream: ScenarioDownstream,
    /// Scripted upstream behavior.
    upstream: ScenarioUpstream,
}

/// Gateway admission state for a deterministic scenario.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScenarioAdmission {
    /// Request permit is available.
    Open,

    /// Request permits are exhausted.
    Saturated,
}

/// Audit sink behavior for a deterministic scenario.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScenarioAudit {
    /// Fail the first audit event.
    FailFirst,

    /// Record every audit event.
    Record,
}

/// Scenario byte bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScenarioBounds {
    /// Use the roomy runtime-test bounds.
    Roomy,

    /// Configure a response limit smaller than the scripted success chunk.
    TinyResponse,
}

/// Downstream response consumption behavior for a deterministic scenario.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScenarioDownstream {
    /// Consume the full response body.
    ConsumeAll,

    /// Drop the downstream body after the first chunk and before the final chunk.
    DropBeforeFinalChunk,

    /// Drop the downstream body before the first chunk can be received.
    DropBeforeFirstChunk,
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

    /// Return an error after streaming one response chunk.
    StreamError,

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

    /// Return an error after streaming one response chunk.
    StreamError,
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
        let event_number = {
            let mut count = self
                .event_count
                .lock()
                .expect("memory audit event count should not be poisoned");
            let next = count
                .checked_add(1)
                .expect("memory audit event count should not overflow");
            *count = next;
            next
        };
        let should_fail = self
            .fail_on_event
            .is_some_and(|fail_on| fail_on.get() == event_number);
        if should_fail {
            return Box::pin(future::ready(Err(AuditError::Write(io::Error::other(
                "scripted audit failure",
            )))));
        }
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
    /// Builds an audit sink that fails on a specific event ordinal.
    #[must_use]
    pub(super) fn failing_on(event: NonZeroUsize) -> (Self, Arc<Mutex<Vec<Value>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                event_count: Arc::new(Mutex::new(0)),
                events: Arc::clone(&events),
                fail_on_event: Some(event),
            },
            events,
        )
    }

    /// Builds an audit sink from scenario audit behavior.
    #[must_use]
    pub(super) fn from_audit(audit: ScenarioAudit) -> (Self, Arc<Mutex<Vec<Value>>>) {
        match audit {
            ScenarioAudit::Record => Self::new(),
            ScenarioAudit::FailFirst => {
                Self::failing_on(NonZeroUsize::new(1).expect("literal should be non-zero"))
            }
        }
    }

    /// Builds an audit sink and its event recorder.
    #[must_use]
    pub(super) fn new() -> (Self, Arc<Mutex<Vec<Value>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                event_count: Arc::new(Mutex::new(0)),
                events: Arc::clone(&events),
                fail_on_event: None,
            },
            events,
        )
    }
}

impl RecordedUpstreamRequest {
    /// Returns the recorded request body.
    #[must_use]
    pub(super) fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the recorded upstream deadline.
    #[must_use]
    pub(super) const fn deadline(&self) -> UpstreamDeadline {
        self.deadline
    }

    /// Returns the recorded forwarded headers.
    #[must_use]
    pub(super) fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Returns the recorded request method.
    #[must_use]
    pub(super) const fn method(&self) -> &Method {
        &self.method
    }

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

    /// Returns the recorded upstream URL.
    #[must_use]
    pub(super) fn url(&self) -> &str {
        &self.url
    }
}

impl Scenario {
    /// Returns the gateway admission state.
    #[must_use]
    pub(super) const fn admission(&self) -> ScenarioAdmission {
        self.admission
    }

    /// Returns the audit sink behavior.
    #[must_use]
    pub(super) const fn audit(&self) -> ScenarioAudit {
        self.audit
    }

    /// Returns the scenario byte bounds.
    #[must_use]
    pub(super) const fn bounds(&self) -> ScenarioBounds {
        self.bounds
    }

    /// Returns the downstream response consumption behavior.
    #[must_use]
    pub(super) const fn downstream(&self) -> ScenarioDownstream {
        self.downstream
    }

    /// Builds a deterministic gateway scenario.
    #[must_use]
    pub(super) const fn new(request: ScenarioRequest, upstream: ScenarioUpstream) -> Self {
        Self {
            admission: ScenarioAdmission::Open,
            audit: ScenarioAudit::Record,
            bounds: ScenarioBounds::Roomy,
            downstream: ScenarioDownstream::ConsumeAll,
            request,
            upstream,
        }
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

    /// Builds a deterministic gateway scenario from a generated class.
    #[must_use]
    pub(super) const fn with_class(class: ScenarioClass, request: ScenarioRequest) -> Self {
        Self {
            admission: class.admission,
            audit: class.audit,
            bounds: class.bounds,
            downstream: class.downstream,
            request,
            upstream: class.upstream,
        }
    }
}

impl ScenarioClass {
    /// Returns every scenario fault-class combination.
    #[must_use]
    pub(super) fn all() -> Vec<Self> {
        let mut classes = Vec::with_capacity(26);
        for admission in [ScenarioAdmission::Open, ScenarioAdmission::Saturated] {
            for audit in [ScenarioAudit::FailFirst, ScenarioAudit::Record] {
                for bounds in [ScenarioBounds::Roomy, ScenarioBounds::TinyResponse] {
                    for upstream in [
                        ScenarioUpstream::Respond,
                        ScenarioUpstream::StreamError,
                        ScenarioUpstream::Timeout,
                    ] {
                        classes.push(Self {
                            admission,
                            audit,
                            bounds,
                            downstream: ScenarioDownstream::ConsumeAll,
                            upstream,
                        });
                    }
                }
            }
        }
        for downstream in [
            ScenarioDownstream::DropBeforeFirstChunk,
            ScenarioDownstream::DropBeforeFinalChunk,
        ] {
            classes.push(Self {
                admission: ScenarioAdmission::Open,
                audit: ScenarioAudit::Record,
                bounds: ScenarioBounds::Roomy,
                downstream,
                upstream: ScenarioUpstream::Respond,
            });
        }
        classes
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
            ScenarioUpstream::StreamError => ScriptedUpstreamBehavior::StreamError,
            ScenarioUpstream::Timeout => ScriptedUpstreamBehavior::Stall {
                duration: Duration::from_secs(10),
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
        match self.behavior {
            ScriptedUpstreamBehavior::Respond => Box::pin(future::ready(Ok(scripted_response()))),
            ScriptedUpstreamBehavior::Stall { duration } => Box::pin(async move {
                if timeout(request.deadline().timeout(), sleep(duration))
                    .await
                    .is_err()
                {
                    let error = UpstreamError::new(
                        UpstreamErrorKind::Timeout,
                        format!("scripted upstream stalled for {duration:?}"),
                    );
                    Err(error)
                } else {
                    Ok(scripted_response())
                }
            }),
            ScriptedUpstreamBehavior::StreamError => {
                Box::pin(future::ready(Ok(scripted_stream_error_response())))
            }
        }
    }
}

/// Returns the standard scripted success response.
fn scripted_response() -> UpstreamResponse {
    UpstreamResponse::new(
        StatusCode::CREATED,
        ::http::HeaderMap::new(),
        stream::unfold(0_u8, |step| async move {
            match step {
                0 => Some((Ok(Bytes::from_static(b"script")), 1)),
                1 => Some((Ok(Bytes::from_static(b"ed")), 2)),
                2 => {
                    sleep(Duration::from_secs(1)).await;
                    None
                }
                _ => None,
            }
        })
        .boxed(),
    )
}

/// Returns a response that fails after one body chunk.
fn scripted_stream_error_response() -> UpstreamResponse {
    UpstreamResponse::new(
        StatusCode::CREATED,
        ::http::HeaderMap::new(),
        stream::iter([
            Ok(Bytes::from_static(b"first")),
            Err(UpstreamBodyError::new("scripted upstream stream failed")),
        ])
        .boxed(),
    )
}

/// Generates deterministic gateway scenarios.
pub(super) fn scenario_any() -> impl Strategy<Value = Scenario> {
    scenario_class_any().prop_flat_map(|selected_class| {
        (
            Just(selected_class),
            scenario_body_any(),
            scenario_headers_any(),
            scenario_target_any(),
        )
            .prop_map(|(generated_class, body, headers, target)| {
                Scenario::with_class(
                    generated_class,
                    ScenarioRequest::new(body, headers, Method::GET, target),
                )
            })
    })
}

/// Generates bounded request bodies.
fn scenario_body_any() -> impl Strategy<Value = Vec<u8>> {
    collection::vec(any::<u8>(), 0..9)
}

/// Generates deterministic scenario fault classes.
fn scenario_class_any() -> impl Strategy<Value = ScenarioClass> {
    select(ScenarioClass::all())
}

/// Generates one bounded request header.
fn scenario_header_any() -> impl Strategy<Value = (String, String)> {
    prop_oneof![
        (
            Just("authorization".to_owned()),
            scenario_header_value_any(),
        ),
        (
            Just("connection".to_owned()),
            scenario_connection_value_any(),
        ),
        (Just("cookie".to_owned()), scenario_header_value_any(),),
        (Just("host".to_owned()), scenario_header_value_any(),),
        (Just("keep-alive".to_owned()), scenario_header_value_any(),),
        (
            Just("proxy-authorization".to_owned()),
            scenario_header_value_any(),
        ),
        (Just("te".to_owned()), scenario_header_value_any(),),
        (Just("upgrade".to_owned()), scenario_header_value_any(),),
        (Just("x-drop".to_owned()), scenario_header_value_any(),),
        (Just("x-request-id".to_owned()), scenario_header_value_any(),),
        (Just("x-visible".to_owned()), scenario_header_value_any(),),
    ]
}

/// Generates safe header values.
fn scenario_header_value_any() -> impl Strategy<Value = String> {
    collection::vec(scenario_header_value_char_any(), 0..17)
        .prop_map(|chars| chars.into_iter().collect())
}

/// Generates one safe header value character.
fn scenario_header_value_char_any() -> impl Strategy<Value = char> {
    prop_oneof![
        Just('-'),
        Just('.'),
        Just('/'),
        Just('0'),
        Just('1'),
        Just('9'),
        Just(':'),
        Just('='),
        Just('A'),
        Just('Z'),
        Just('_'),
        Just('a'),
        Just('z'),
    ]
}

/// Generates bounded request header sets.
fn scenario_headers_any() -> impl Strategy<Value = Vec<(String, String)>> {
    collection::vec(scenario_header_any(), 0..7)
}

/// Generates valid `Connection` header values.
fn scenario_connection_value_any() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("te".to_owned()),
        Just("upgrade".to_owned()),
        Just("x-drop".to_owned()),
        Just("x-visible, x-drop".to_owned()),
    ]
}

/// Generates one allowed query character.
fn scenario_query_char_any() -> impl Strategy<Value = char> {
    prop_oneof![
        Just('&'),
        Just('-'),
        Just('.'),
        Just('0'),
        Just('1'),
        Just('9'),
        Just('='),
        Just('_'),
        Just('a'),
        Just('z'),
    ]
}

/// Generates allowed request targets.
fn scenario_target_any() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(None),
        collection::vec(scenario_query_char_any(), 1..17).prop_map(Some),
    ]
    .prop_map(|query| {
        query.map_or_else(
            || "/v1/models".to_owned(),
            |chars| format!("/v1/models?{}", chars.into_iter().collect::<String>()),
        )
    })
}
