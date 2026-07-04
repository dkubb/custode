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
use crate::target::OriginFormQuery;
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

/// Reachable deterministic scenario fault classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScenarioClass {
    /// Reachable downstream disconnect after a response has started.
    DownstreamDisconnect {
        /// Audit sink behavior.
        audit: ScenarioAudit,
        /// Downstream response consumption behavior.
        downstream: ScenarioDisconnect,
        /// Scripted upstream behavior after response start.
        upstream: ScenarioStartedUpstream,
    },

    /// Gateway admission is saturated before any upstream request starts.
    PermitSaturated {
        /// Audit sink behavior.
        audit: ScenarioAudit,
    },

    /// Response body exceeds the configured response byte bound.
    ResponseBodyTooLarge {
        /// Audit sink behavior.
        audit: ScenarioAudit,
    },

    /// Upstream response body stalls after the first chunk.
    UpstreamBodyTimeout {
        /// Audit sink behavior.
        audit: ScenarioAudit,
    },

    /// Upstream returns a successful response.
    UpstreamRespond {
        /// Audit sink behavior.
        audit: ScenarioAudit,
    },

    /// Upstream response stream fails after the first chunk.
    UpstreamStreamError {
        /// Audit sink behavior.
        audit: ScenarioAudit,
    },

    /// Upstream request stalls before response headers arrive.
    UpstreamTimeout {
        /// Audit sink behavior.
        audit: ScenarioAudit,
    },
}

/// Reachable downstream disconnect behavior for generated scenario classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScenarioDisconnect {
    /// Drop the downstream body after the first chunk and before the final chunk.
    BeforeFinalChunk,

    /// Drop the downstream body before the first chunk can be received.
    BeforeFirstChunk,
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

/// Response-starting upstream outcomes for generated disconnect classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScenarioStartedUpstream {
    /// Return a timeout after streaming one response chunk.
    BodyTimeout,

    /// Return the fixed success response immediately.
    Respond,

    /// Return an error after streaming one response chunk.
    StreamError,
}

/// Harness request shape for a deterministic gateway scenario.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ScenarioRequest {
    /// Request body.
    body: Vec<u8>,
    /// Request headers.
    headers: Vec<(String, String)>,
    /// Request target.
    target: ScenarioTarget,
}

/// Allowed request target for deterministic gateway scenarios.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ScenarioTarget {
    /// Optional request query.
    query: Option<OriginFormQuery>,
}

/// Scripted upstream outcome for a deterministic gateway scenario.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScenarioUpstream {
    /// Return a timeout after streaming one response chunk.
    BodyTimeout,

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
    /// Return a timeout after streaming one response chunk.
    BodyTimeout,

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

/// Response stream state for the standard scripted success response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScriptedResponseStep {
    /// Terminal delay before stream completion.
    End,

    /// First response chunk.
    First,

    /// Second response chunk.
    Second,
}

impl ScenarioAudit {
    /// Every scenario audit variant.
    const ALL: [Self; 2] = [Self::FailFirst, Self::Record];
}

impl ScenarioDisconnect {
    /// Every reachable downstream disconnect variant.
    const ALL: [Self; 2] = [Self::BeforeFinalChunk, Self::BeforeFirstChunk];

    /// Returns the full downstream behavior represented by this disconnect.
    const fn into_downstream(self) -> ScenarioDownstream {
        match self {
            Self::BeforeFinalChunk => ScenarioDownstream::DropBeforeFinalChunk,
            Self::BeforeFirstChunk => ScenarioDownstream::DropBeforeFirstChunk,
        }
    }
}

impl ScenarioStartedUpstream {
    /// Every response-starting upstream variant.
    const ALL: [Self; 3] = [Self::BodyTimeout, Self::Respond, Self::StreamError];

    /// Returns the full upstream behavior represented by this started response.
    const fn into_upstream(self) -> ScenarioUpstream {
        match self {
            Self::BodyTimeout => ScenarioUpstream::BodyTimeout,
            Self::Respond => ScenarioUpstream::Respond,
            Self::StreamError => ScenarioUpstream::StreamError,
        }
    }
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
        let value =
            serde_json::to_value(event).expect("audit events contain only infallible JSON values");
        self.events
            .lock()
            .expect("memory audit sink should not be poisoned")
            .push(value);
        Box::pin(future::ready(Ok(())))
    }
}

impl Clock for FixedClock {
    fn now(&self) -> AuditTimestamp {
        AuditTimestamp::for_test("2026-07-02T00:00:00.000000000Z")
    }
}

impl MemoryAuditSink {
    /// Returns the number of audit events attempted by this sink.
    #[must_use]
    pub(super) fn event_count(&self) -> usize {
        *self
            .event_count
            .lock()
            .expect("memory audit event count should not be poisoned")
    }

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
        match class {
            ScenarioClass::DownstreamDisconnect {
                audit,
                downstream,
                upstream,
            } => Self {
                admission: ScenarioAdmission::Open,
                audit,
                bounds: ScenarioBounds::Roomy,
                downstream: downstream.into_downstream(),
                request,
                upstream: upstream.into_upstream(),
            },
            ScenarioClass::PermitSaturated { audit } => Self {
                admission: ScenarioAdmission::Saturated,
                audit,
                bounds: ScenarioBounds::Roomy,
                downstream: ScenarioDownstream::ConsumeAll,
                request,
                upstream: ScenarioUpstream::Respond,
            },
            ScenarioClass::ResponseBodyTooLarge { audit } => Self {
                admission: ScenarioAdmission::Open,
                audit,
                bounds: ScenarioBounds::TinyResponse,
                downstream: ScenarioDownstream::ConsumeAll,
                request,
                upstream: ScenarioUpstream::Respond,
            },
            ScenarioClass::UpstreamBodyTimeout { audit } => Self {
                admission: ScenarioAdmission::Open,
                audit,
                bounds: ScenarioBounds::Roomy,
                downstream: ScenarioDownstream::ConsumeAll,
                request,
                upstream: ScenarioUpstream::BodyTimeout,
            },
            ScenarioClass::UpstreamRespond { audit } => Self {
                admission: ScenarioAdmission::Open,
                audit,
                bounds: ScenarioBounds::Roomy,
                downstream: ScenarioDownstream::ConsumeAll,
                request,
                upstream: ScenarioUpstream::Respond,
            },
            ScenarioClass::UpstreamStreamError { audit } => Self {
                admission: ScenarioAdmission::Open,
                audit,
                bounds: ScenarioBounds::Roomy,
                downstream: ScenarioDownstream::ConsumeAll,
                request,
                upstream: ScenarioUpstream::StreamError,
            },
            ScenarioClass::UpstreamTimeout { audit } => Self {
                admission: ScenarioAdmission::Open,
                audit,
                bounds: ScenarioBounds::Roomy,
                downstream: ScenarioDownstream::ConsumeAll,
                request,
                upstream: ScenarioUpstream::Timeout,
            },
        }
    }
}

impl ScenarioClass {
    /// Number of reachable deterministic scenario classes.
    const COUNT: usize = 24;

    /// Returns every scenario fault-class combination.
    #[must_use]
    pub(super) fn all() -> Vec<Self> {
        let mut classes = Vec::new();
        for audit in ScenarioAudit::ALL {
            classes.push(Self::PermitSaturated { audit });
            classes.push(Self::ResponseBodyTooLarge { audit });
            classes.push(Self::UpstreamBodyTimeout { audit });
            classes.push(Self::UpstreamRespond { audit });
            classes.push(Self::UpstreamStreamError { audit });
            classes.push(Self::UpstreamTimeout { audit });
        }
        for audit in ScenarioAudit::ALL {
            for downstream in ScenarioDisconnect::ALL {
                for upstream in ScenarioStartedUpstream::ALL {
                    classes.push(Self::DownstreamDisconnect {
                        audit,
                        downstream,
                        upstream,
                    });
                }
            }
        }
        classes
    }

    /// Returns the derived number of reachable scenario classes.
    #[must_use]
    pub(super) const fn count() -> usize {
        Self::COUNT
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
    pub(super) fn method() -> Method {
        Method::GET
    }

    /// Builds a harness request shape.
    #[must_use]
    pub(super) fn new(
        body: Vec<u8>,
        headers: Vec<(String, String)>,
        target: ScenarioTarget,
    ) -> Self {
        Self {
            body,
            headers,
            target,
        }
    }

    /// Returns the request target.
    #[must_use]
    pub(super) fn target(&self) -> String {
        self.target.to_uri_target()
    }

    /// Returns the request target query.
    #[must_use]
    pub(super) fn target_query(&self) -> Option<&str> {
        self.target.query()
    }
}

impl ScenarioTarget {
    /// Builds the allowed scenario target.
    #[must_use]
    pub(super) const fn models(query: Option<OriginFormQuery>) -> Self {
        Self { query }
    }

    /// Returns the fixed request path.
    #[must_use]
    pub(super) const fn path() -> &'static str {
        "/v1/models"
    }

    /// Returns the optional request query.
    #[must_use]
    fn query(&self) -> Option<&str> {
        self.query.as_ref().map(OriginFormQuery::as_str)
    }

    /// Returns the request target text accepted by `http::Request`.
    #[must_use]
    pub(super) fn to_uri_target(&self) -> String {
        self.query().map_or_else(
            || Self::path().to_owned(),
            |query| format!("{}?{query}", Self::path()),
        )
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
            ScenarioUpstream::BodyTimeout => ScriptedUpstreamBehavior::BodyTimeout,
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
            ScriptedUpstreamBehavior::BodyTimeout => {
                Box::pin(future::ready(Ok(scripted_body_timeout_response())))
            }
        }
    }
}

/// Returns the standard scripted success response.
fn scripted_response() -> UpstreamResponse {
    UpstreamResponse::new(
        StatusCode::CREATED,
        ::http::HeaderMap::new(),
        stream::unfold(ScriptedResponseStep::First, |step| async move {
            match step {
                ScriptedResponseStep::First => Some((
                    Ok(Bytes::from_static(b"script")),
                    ScriptedResponseStep::Second,
                )),
                ScriptedResponseStep::Second => {
                    Some((Ok(Bytes::from_static(b"ed")), ScriptedResponseStep::End))
                }
                ScriptedResponseStep::End => {
                    sleep(Duration::from_secs(1)).await;
                    None
                }
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
            Err(UpstreamBodyError::stream("scripted upstream stream failed")),
        ])
        .boxed(),
    )
}

/// Returns a response that times out after one body chunk.
fn scripted_body_timeout_response() -> UpstreamResponse {
    UpstreamResponse::new(
        StatusCode::CREATED,
        ::http::HeaderMap::new(),
        stream::iter([
            Ok(Bytes::from_static(b"first")),
            Err(UpstreamBodyError::timeout(
                "scripted upstream body timed out",
            )),
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
                Scenario::with_class(generated_class, ScenarioRequest::new(body, headers, target))
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
fn scenario_target_any() -> impl Strategy<Value = ScenarioTarget> {
    prop_oneof![
        Just(None),
        collection::vec(scenario_query_char_any(), 1..17).prop_map(Some),
    ]
    .prop_map(|query_chars| {
        let query = query_chars.map(|chars| {
            let query_text = chars.into_iter().collect::<String>();
            OriginFormQuery::parse(&query_text).expect("generated query should parse")
        });
        scenario_target(query)
    })
}

/// Builds a scenario request target from an optional query.
fn scenario_target(query: Option<OriginFormQuery>) -> ScenarioTarget {
    ScenarioTarget::models(query)
}

#[cfg(test)]
#[expect(
    clippy::inline_modules,
    reason = "inline tests keep deterministic test adapter ownership explicit"
)]
mod tests {
    use super::{
        MemoryAuditSink, RecordedUpstreamRequest, Scenario, ScenarioAdmission, ScenarioAudit,
        ScenarioBounds, ScenarioClass, ScenarioDisconnect, ScenarioDownstream, ScenarioRequest,
        ScenarioStartedUpstream, ScenarioTarget, ScenarioUpstream, ScriptedUpstreamClient,
        scenario_any, scenario_body_any, scenario_class_any, scenario_connection_value_any,
        scenario_header_any, scenario_header_value_any, scenario_header_value_char_any,
        scenario_headers_any, scenario_query_char_any, scenario_target, scenario_target_any,
        scripted_stream_error_response,
    };
    use crate::config::RequestTimeout;
    use crate::ports::UpstreamDeadline;
    use crate::target::{OriginFormPath, OriginFormQuery};
    use core::time::Duration;
    use http::Method;
    use pretty_assertions::assert_eq;
    use proptest::strategy::{Strategy, ValueTree as _};
    use proptest::test_runner::TestRunner;

    fn sample<S>(runner: &mut TestRunner, strategy: S) -> S::Value
    where
        S: Strategy,
    {
        strategy
            .new_tree(runner)
            .expect("strategy should generate")
            .current()
    }

    #[test]
    fn recorded_upstream_request_accessors_preserve_parts() {
        let deadline =
            UpstreamDeadline::from_timeout(RequestTimeout::from_duration(Duration::from_secs(3)));
        let request = RecordedUpstreamRequest::new(
            b"body".to_vec(),
            deadline,
            vec![("x-test".to_owned(), "visible".to_owned())],
            Method::POST,
            "https://api.openai.com/v1/models",
        );

        assert_eq!(request.body(), b"body");
        assert_eq!(request.deadline(), deadline);
        assert_eq!(
            request.headers(),
            [("x-test".to_owned(), "visible".to_owned())]
        );
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.url(), "https://api.openai.com/v1/models");
    }

    #[test]
    fn scenario_classes_cover_every_reachable_combination() {
        let request = ScenarioRequest::new(Vec::new(), Vec::new(), scenario_target(None));
        let classes = ScenarioClass::all();

        assert_eq!(request.target_query(), None);
        assert_eq!(classes.len(), 24);
        assert_eq!(classes.len(), ScenarioClass::count());
        for audit in ScenarioAudit::ALL {
            assert!(classes.contains(&ScenarioClass::PermitSaturated { audit }));
            assert!(classes.contains(&ScenarioClass::ResponseBodyTooLarge { audit }));
            assert!(classes.contains(&ScenarioClass::UpstreamBodyTimeout { audit }));
            assert!(classes.contains(&ScenarioClass::UpstreamRespond { audit }));
            assert!(classes.contains(&ScenarioClass::UpstreamStreamError { audit }));
            assert!(classes.contains(&ScenarioClass::UpstreamTimeout { audit }));
        }
        for audit in ScenarioAudit::ALL {
            for downstream in ScenarioDisconnect::ALL {
                for upstream in ScenarioStartedUpstream::ALL {
                    assert!(classes.contains(&ScenarioClass::DownstreamDisconnect {
                        audit,
                        downstream,
                        upstream,
                    }));
                }
            }
        }

        for class in classes {
            let scenario = Scenario::with_class(class, request.clone());

            assert_eq!(scenario.request(), &request);
            match scenario.downstream() {
                ScenarioDownstream::ConsumeAll
                | ScenarioDownstream::DropBeforeFirstChunk
                | ScenarioDownstream::DropBeforeFinalChunk => {}
            }
        }
    }

    #[test]
    fn scenario_request_and_defaults_preserve_parts() {
        let request = ScenarioRequest::new(
            b"body".to_vec(),
            vec![("authorization".to_owned(), "Bearer token".to_owned())],
            scenario_target(Some(
                OriginFormQuery::parse("limit=1").expect("test query should parse"),
            )),
        );
        let scenario = Scenario::new(request.clone(), ScenarioUpstream::Respond);

        assert_eq!(request.body(), b"body");
        assert_eq!(
            request.headers(),
            [("authorization".to_owned(), "Bearer token".to_owned())],
        );
        assert_eq!(ScenarioRequest::method(), Method::GET);
        assert_eq!(request.target(), "/v1/models?limit=1");
        assert_eq!(request.target_query(), Some("limit=1"));
        assert_eq!(scenario.admission(), ScenarioAdmission::Open);
        assert_eq!(scenario.audit(), ScenarioAudit::Record);
        assert_eq!(scenario.bounds(), ScenarioBounds::Roomy);
        assert_eq!(scenario.downstream(), ScenarioDownstream::ConsumeAll);
        assert_eq!(scenario.request(), &request);
        assert_eq!(scenario.upstream(), ScenarioUpstream::Respond);
    }

    #[test]
    fn scenario_adapters_cover_scripted_fault_variants() {
        let (audit, audit_events) = MemoryAuditSink::from_audit(ScenarioAudit::FailFirst);
        let (_stream_client, stream_requests) =
            ScriptedUpstreamClient::from_upstream(ScenarioUpstream::StreamError);
        let (_body_timeout_client, body_timeout_requests) =
            ScriptedUpstreamClient::from_upstream(ScenarioUpstream::BodyTimeout);
        let (_timeout_client, timeout_requests) =
            ScriptedUpstreamClient::from_upstream(ScenarioUpstream::Timeout);

        assert_eq!(audit.event_count(), 0);
        assert!(
            audit_events
                .lock()
                .expect("audit events should lock")
                .is_empty()
        );
        assert!(
            stream_requests
                .lock()
                .expect("stream requests should lock")
                .is_empty()
        );
        assert!(
            timeout_requests
                .lock()
                .expect("timeout requests should lock")
                .is_empty()
        );
        assert!(
            body_timeout_requests
                .lock()
                .expect("body timeout requests should lock")
                .is_empty()
        );
    }

    #[test]
    fn scenario_target_formats_bare_and_query_targets() {
        assert_eq!(scenario_target(None).to_uri_target(), "/v1/models");
        assert_eq!(
            scenario_target(Some(
                OriginFormQuery::parse("limit=1").expect("test query should parse")
            ))
            .to_uri_target(),
            "/v1/models?limit=1"
        );
    }

    #[test]
    fn scenario_generators_create_valid_samples() {
        let mut runner = TestRunner::deterministic();

        for _sample in 0_u8..64 {
            let body = sample(&mut runner, scenario_body_any());
            let _class = sample(&mut runner, scenario_class_any());
            let header = sample(&mut runner, scenario_header_any());
            let header_value = sample(&mut runner, scenario_header_value_any());
            let _header_char = sample(&mut runner, scenario_header_value_char_any());
            let headers = sample(&mut runner, scenario_headers_any());
            let connection = sample(&mut runner, scenario_connection_value_any());
            let _query_char = sample(&mut runner, scenario_query_char_any());
            let target = sample(&mut runner, scenario_target_any());
            let scenario = sample(&mut runner, scenario_any());
            let target_text = target.to_uri_target();

            assert!(body.len() <= 8);
            assert!(!header.0.is_empty());
            assert!(header_value.len() <= 16);
            assert!(headers.len() <= 6);
            assert!(!connection.is_empty());
            let (path, query_text) = target_text
                .split_once('?')
                .map_or((target_text.as_str(), None), |(path, query)| {
                    (path, Some(query))
                });
            assert_eq!(
                OriginFormPath::parse(path)
                    .expect("path should parse")
                    .as_str(),
                "/v1/models"
            );
            if let Some(query_value) = query_text {
                OriginFormQuery::parse(query_value).expect("query should parse");
            }
            assert_eq!(ScenarioTarget::path(), "/v1/models");
            assert!(
                scenario
                    .request()
                    .target()
                    .starts_with(ScenarioTarget::path())
            );
            assert_eq!(ScenarioRequest::method(), Method::GET);
        }

        let response = scripted_stream_error_response();
        assert_eq!(response.status(), http::StatusCode::CREATED);
    }
}
