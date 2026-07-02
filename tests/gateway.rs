//! Integration tests exercising the gateway binary end-to-end: allowed and
//! denied requests, header forwarding, single-upstream targeting, audit
//! events, and fail-closed startup behavior.

use blake3 as _;
use clap as _;
use custode as _;
use futures_util as _;
use http as _;
use http_body_util as _;
use humantime as _;
use pretty_assertions as _;
use proptest as _;
use serde as _;
use thiserror as _;
use tokio_stream as _;
use tower as _;
use tracing as _;
use tracing_subscriber as _;
use url as _;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::routing::any;
use core::net::SocketAddr;
use core::time::Duration;
use serde_json::Value;
use std::env::temp_dir;
use std::fs::{DirBuilder, remove_dir};
use std::io::Error;
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use tempfile::{TempDir, tempdir};
use tokio::fs::read_to_string;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

/// POSIX `EEXIST` returned when another process holds the lock directory.
const ALREADY_EXISTS_OS_ERROR: i32 = 17;

/// One request observed by the recording upstream.
#[derive(Clone, Debug)]
struct RecordedRequest {
    /// `x-api-key` header value, when present.
    api_key: Option<String>,
    /// `Authorization` header value, when present.
    authorization: Option<String>,
    /// Request method.
    method: String,
    /// Request path.
    path: String,
}

/// Shared recording of upstream requests.
type Recorder = Arc<Mutex<Vec<RecordedRequest>>>;

/// A gateway child process that is killed on drop.
#[derive(Debug)]
struct GatewayProcess {
    /// Temporary state directory kept alive for the process lifetime.
    _directory: TempDir,
    /// Gateway bind address.
    addr: SocketAddr,
    /// Audit log path.
    audit_log: PathBuf,
    /// Gateway child process.
    child: Child,
}

/// Cross-process lock for gateway subprocess tests.
#[derive(Debug)]
struct GatewayTestLock {
    /// Lock directory created atomically while the lock is held.
    path: PathBuf,
}

impl GatewayProcess {
    /// Returns the gateway base URL.
    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Polls the audit log until it holds `expected` events.
    async fn read_audit_events(&self, expected: usize) -> Vec<Value> {
        for _attempt in 0_u32..100 {
            let text = read_to_string(&self.audit_log).await.unwrap_or_default();
            let events: Vec<Value> = text
                .lines()
                .map(|line| serde_json::from_str(line).expect("audit lines should be JSON"))
                .collect();
            if events.len() >= expected {
                return events;
            }
            sleep(Duration::from_millis(50)).await;
        }
        Vec::new()
    }

    /// Spawns a gateway, retrying when the reserved port is lost to a race.
    async fn spawn(upstream_origin: &str, allowed_operations: &str) -> Self {
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        let mut started = None;
        for _spawn_attempt in 0_u32..5 {
            started = Self::try_start(upstream_origin, allowed_operations, &audit_log).await;
            if started.is_some() {
                break;
            }
        }
        let (addr, child) = started.expect("gateway should start listening within five attempts");
        Self {
            _directory: directory,
            addr,
            audit_log,
            child,
        }
    }

    /// Starts one gateway process, returning None when it loses the bind race.
    async fn try_start(
        upstream_origin: &str,
        allowed_operations: &str,
        audit_log: &Path,
    ) -> Option<(SocketAddr, Child)> {
        let addr = free_local_addr();
        let mut child = spawn_gateway_command(addr, upstream_origin, allowed_operations, audit_log);
        for _poll in 0_u32..100 {
            if child
                .try_wait()
                .expect("child status should be observable")
                .is_some()
            {
                return None;
            }
            if TcpStream::connect(addr).await.is_ok() {
                return Some((addr, child));
            }
            sleep(Duration::from_millis(50)).await;
        }
        let _kill_result = child.kill();
        let _wait_result = child.wait();
        None
    }
}

impl GatewayTestLock {
    /// Acquires the global gateway test lock.
    async fn acquire() -> Result<Self, Error> {
        let path = temp_dir().join("custode-gateway-tests.lock");
        for _attempt in 0_u32..200 {
            match DirBuilder::new().create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.raw_os_error() == Some(ALREADY_EXISTS_OS_ERROR) => {
                    sleep(Duration::from_millis(50)).await;
                }
                Err(error) => return Err(error),
            }
        }
        Err(Error::other("gateway test lock should be acquired"))
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "only the stable Drop::drop method can be implemented"
)]
impl Drop for GatewayProcess {
    fn drop(&mut self) {
        let _kill_result = self.child.kill();
        let _wait_result = self.child.wait();
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "only the stable Drop::drop method can be implemented"
)]
impl Drop for GatewayTestLock {
    fn drop(&mut self) {
        let _remove_result = remove_dir(&self.path);
    }
}

/// Records one upstream request and returns a fixed body.
async fn record(State(recorder): State<Recorder>, request: Request<Body>) -> &'static str {
    let header_text = |name: &str| {
        request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    let entry = RecordedRequest {
        api_key: header_text("x-api-key"),
        authorization: header_text("authorization"),
        method: request.method().to_string(),
        path: request.uri().path().to_owned(),
    };
    recorder
        .lock()
        .expect("recorder mutex should not be poisoned")
        .push(entry);
    "ok"
}

/// Starts a local recording upstream and returns its address and recorder.
async fn start_upstream() -> (SocketAddr, Recorder) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream listener should bind");
    let addr = listener
        .local_addr()
        .expect("upstream listener should report its address");
    let recorder: Recorder = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .fallback(any(record))
        .with_state(Arc::clone(&recorder));
    drop(tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("test upstream should serve");
    }));
    (addr, recorder)
}

/// Reserves a local address for the gateway to bind.
fn free_local_addr() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("probe listener should bind");
    listener
        .local_addr()
        .expect("probe listener should report its address")
}

/// Spawns the gateway binary with explicit serve configuration.
fn spawn_gateway_command(
    bind: SocketAddr,
    upstream_origin: &str,
    allowed_operations: &str,
    audit_log: &Path,
) -> Child {
    Command::new(env!("CARGO_BIN_EXE_custode-proxy"))
        .arg("serve")
        .env("CUSTODE_BIND", bind.to_string())
        .env("CUSTODE_UPSTREAM_ORIGIN", upstream_origin)
        .env("CUSTODE_ALLOWED_OPERATIONS", allowed_operations)
        .env("CUSTODE_AUDIT_LOG", audit_log)
        .env("CUSTODE_REQUEST_TIMEOUT_SECS", "5")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("gateway binary should spawn")
}

/// Waits for a child process to exit, returning true when it failed.
fn wait_for_failure(mut child: Child) -> bool {
    for _attempt in 0_u32..100 {
        if let Some(status) = child.try_wait().expect("child status should be observable") {
            return !status.success();
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _kill_result = child.kill();
    let _wait_result = child.wait();
    false
}

#[cfg(test)]
mod tests {
    use super::{
        Command, GatewayProcess, GatewayTestLock, RecordedRequest, Stdio, free_local_addr,
        spawn_gateway_command, start_upstream, tempdir, wait_for_failure,
    };
    use pretty_assertions::{assert_eq, assert_ne};

    /// Serializes gateway subprocess tests across nextest processes.
    async fn lock_gateway_test() -> GatewayTestLock {
        GatewayTestLock::acquire()
            .await
            .expect("gateway test lock should be acquired")
    }

    /// Clones the recorded upstream hits.
    fn recorded_hits(recorder: &super::Recorder) -> Vec<RecordedRequest> {
        recorder
            .lock()
            .expect("recorder mutex should not be poisoned")
            .clone()
    }

    #[tokio::test]
    async fn allowed_request_reaches_upstream_and_audits() {
        let _guard = lock_gateway_test().await;
        let (upstream, recorder) = start_upstream().await;
        let gateway =
            GatewayProcess::spawn(&format!("http://{upstream}"), "GET:exact:/v1/models").await;

        let response = reqwest::get(format!("{}/v1/models", gateway.base_url()))
            .await
            .expect("gateway request should succeed");

        assert_eq!(response.status(), 200);
        assert_eq!(
            response.text().await.expect("response body should read"),
            "ok"
        );
        let hits = recorded_hits(&recorder);
        assert_eq!(hits.len(), 1);
        let hit = hits.first().expect("one hit should be recorded");
        assert_eq!(hit.method, "GET");
        assert_eq!(hit.path, "/v1/models");

        let events = gateway.read_audit_events(1).await;
        assert_eq!(events.len(), 1);
        let event = events.first().expect("one audit event should exist");
        assert_eq!(event["decision"], "allowed");
        assert_eq!(event["upstream_path"], "/v1/models");
        assert_eq!(event["status"], 200_u64);
        assert_eq!(event["version"], 1_u64);
    }

    #[tokio::test]
    async fn allowed_request_reaches_only_the_configured_upstream() {
        let _guard = lock_gateway_test().await;
        let (configured, configured_recorder) = start_upstream().await;
        let (decoy, decoy_recorder) = start_upstream().await;
        let gateway =
            GatewayProcess::spawn(&format!("http://{configured}"), "GET:exact:/v1/models").await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/v1/models", gateway.base_url()))
            .header("host", decoy.to_string())
            .send()
            .await
            .expect("gateway request should succeed");

        assert_eq!(response.status(), 200);
        assert_eq!(
            recorded_hits(&configured_recorder).len(),
            1,
            "configured upstream should be reached"
        );
        assert_eq!(
            recorded_hits(&decoy_recorder).len(),
            0,
            "host header must not select the upstream"
        );
    }

    #[tokio::test]
    async fn denied_method_does_not_reach_upstream() {
        let _guard = lock_gateway_test().await;
        let (upstream, recorder) = start_upstream().await;
        let gateway =
            GatewayProcess::spawn(&format!("http://{upstream}"), "GET:exact:/v1/models").await;

        let client = reqwest::Client::new();
        let response = client
            .delete(format!("{}/v1/models", gateway.base_url()))
            .send()
            .await
            .expect("gateway request should complete");

        assert_eq!(response.status(), 403);
        assert_eq!(
            recorded_hits(&recorder).len(),
            0,
            "denied methods must not reach the upstream"
        );

        let events = gateway.read_audit_events(1).await;
        assert_eq!(events.len(), 1);
        let event = events.first().expect("one audit event should exist");
        assert_eq!(event["decision"], "denied");
        assert!(event["upstream_path"].is_null());
    }

    #[tokio::test]
    async fn denied_path_does_not_reach_upstream() {
        let _guard = lock_gateway_test().await;
        let (upstream, recorder) = start_upstream().await;
        let gateway =
            GatewayProcess::spawn(&format!("http://{upstream}"), "GET:exact:/v1/models").await;

        let response = reqwest::get(format!("{}/admin", gateway.base_url()))
            .await
            .expect("gateway request should complete");

        assert_eq!(response.status(), 403);
        assert_eq!(
            recorded_hits(&recorder).len(),
            0,
            "denied paths must not reach the upstream"
        );

        let events = gateway.read_audit_events(1).await;
        assert_eq!(events.len(), 1);
        let event = events.first().expect("one audit event should exist");
        assert_eq!(event["decision"], "denied");
        assert_eq!(event["error_class"], "path_denied");
    }

    #[tokio::test]
    async fn harness_authorization_headers_reach_the_upstream() {
        let _guard = lock_gateway_test().await;
        let (upstream, recorder) = start_upstream().await;
        let gateway =
            GatewayProcess::spawn(&format!("http://{upstream}"), "GET:exact:/v1/models").await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/v1/models", gateway.base_url()))
            .header("authorization", "Bearer harness-token")
            .header("x-api-key", "harness-key")
            .send()
            .await
            .expect("gateway request should succeed");

        assert_eq!(response.status(), 200);
        let hits = recorded_hits(&recorder);
        assert_eq!(hits.len(), 1);
        let hit = hits.first().expect("one hit should be recorded");
        assert_eq!(hit.authorization.as_deref(), Some("Bearer harness-token"));
        assert_eq!(hit.api_key.as_deref(), Some("harness-key"));
    }

    #[tokio::test]
    async fn every_allowed_and_denied_request_produces_an_audit_event() {
        let _guard = lock_gateway_test().await;
        let (upstream, _recorder) = start_upstream().await;
        let gateway =
            GatewayProcess::spawn(&format!("http://{upstream}"), "GET:exact:/v1/models").await;

        let client = reqwest::Client::new();
        let allowed = client
            .get(format!("{}/v1/models", gateway.base_url()))
            .send()
            .await
            .expect("allowed request should succeed");
        assert_eq!(allowed.status(), 200);
        drop(allowed.text().await.expect("allowed body should read"));
        let denied = client
            .delete(format!("{}/v1/models", gateway.base_url()))
            .send()
            .await
            .expect("denied request should complete");
        assert_eq!(denied.status(), 403);

        let events = gateway.read_audit_events(2).await;
        assert_eq!(events.len(), 2);
        let decisions: Vec<&str> = events
            .iter()
            .map(|event| {
                event["decision"]
                    .as_str()
                    .expect("decision should be a string")
            })
            .collect();
        assert!(decisions.contains(&"allowed"));
        assert!(decisions.contains(&"denied"));
        let identities: Vec<&str> = events
            .iter()
            .map(|event| {
                event["request_id"]
                    .as_str()
                    .expect("request id should be a string")
            })
            .collect();
        let first = identities.first().expect("first identity should exist");
        let second = identities.get(1).expect("second identity should exist");
        assert_ne!(first, second, "request identities must be unique");
    }

    #[tokio::test]
    async fn unopenable_audit_log_fails_closed_at_startup() {
        let _guard = lock_gateway_test().await;
        let directory = tempdir().expect("temporary directory should be created");
        let addr = free_local_addr();

        let child = spawn_gateway_command(
            addr,
            "http://127.0.0.1:9",
            "GET:exact:/v1/models",
            directory.path(),
        );

        assert!(
            wait_for_failure(child),
            "a gateway that cannot open its audit log must exit non-zero"
        );
    }

    #[tokio::test]
    async fn missing_allowlist_fails_closed_at_startup() {
        let _guard = lock_gateway_test().await;
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        let addr = free_local_addr();

        let child = Command::new(env!("CARGO_BIN_EXE_custode-proxy"))
            .arg("serve")
            .env("CUSTODE_BIND", addr.to_string())
            .env("CUSTODE_UPSTREAM_ORIGIN", "http://127.0.0.1:9")
            .env("CUSTODE_AUDIT_LOG", &audit_log)
            .env_remove("CUSTODE_ALLOWED_OPERATIONS")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("gateway binary should spawn");

        assert!(
            wait_for_failure(child),
            "a gateway without an explicit allowlist must exit non-zero"
        );
    }

    #[tokio::test]
    async fn wildcard_upstream_origin_fails_closed_at_startup() {
        let _guard = lock_gateway_test().await;
        let directory = tempdir().expect("temporary directory should be created");
        let audit_log = directory.path().join("audit.ndjson");
        let addr = free_local_addr();

        let child = spawn_gateway_command(
            addr,
            "https://*.example.com",
            "GET:exact:/v1/models",
            &audit_log,
        );

        assert!(
            wait_for_failure(child),
            "a wildcard upstream origin must exit non-zero"
        );
    }
}
