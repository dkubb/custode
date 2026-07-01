use super::{ResponseAuditContext, run_until_server_stops};
use crate::allowlist::AcceptedTarget;
use crate::audit::{AuditDecision, AuditError, RequestId};
use crate::body::{AccountedBody, ResponseAccount};
use crate::config::GatewayConfig;
use crate::gateway::{Gateway, GatewayError};
use ::http::Method;
use axum::body::Body;
use core::future;
use core::num::{NonZeroU64, NonZeroUsize};
use std::io;
use tempfile::tempdir;
use tokio::sync::mpsc;

#[tokio::test]
async fn audit_after_response_started_reports_fatal_error() {
    let directory = tempdir().expect("temporary directory should be created");
    let config = GatewayConfig::for_test(
        directory.path().join("audit.ndjson"),
        NonZeroUsize::new(1).expect("limit should be non-zero"),
    );
    let gateway = Gateway::new(config)
        .await
        .expect("gateway should initialize");
    let request_body = AccountedBody::read_request(
        Body::empty(),
        NonZeroUsize::new(1).expect("limit should be non-zero"),
    )
    .await
    .expect("request body should be accounted");
    let mut response_account =
        ResponseAccount::new(NonZeroU64::new(1_024).expect("limit should be non-zero"));
    response_account
        .add_chunk(b"hello")
        .expect("response chunk should be accounted");
    let (fatal_errors, mut fatal_receiver) = mpsc::unbounded_channel();
    let context = ResponseAuditContext {
        fatal_errors,
        gateway,
        method: Method::GET,
        request_body,
        request_id: RequestId::from_sequence(1),
        response_account,
        status: 200,
        target: AcceptedTarget::new("/v1/models", None).expect("target should parse"),
        upstream_path: "/v1/models".to_owned(),
        upstream_query: None,
    };

    let result = context
        .audit_after_response_started(AuditDecision::Allowed, None)
        .await;
    let fatal = fatal_receiver
        .recv()
        .await
        .expect("fatal error should be reported");

    assert!(result.is_err());
    assert!(matches!(
        fatal,
        GatewayError::Audit(AuditError::EventTooLarge { .. }),
    ));
}

#[tokio::test]
async fn run_until_server_stops_returns_fatal_error() {
    let (fatal_errors, fatal_receiver) = mpsc::unbounded_channel();
    fatal_errors
        .send(GatewayError::Audit(AuditError::EventTooLarge {
            bytes: 2,
            max: 1,
        }))
        .expect("fatal error should be sent");

    let result =
        run_until_server_stops(future::pending::<Result<(), io::Error>>(), fatal_receiver).await;

    assert!(matches!(
        result,
        Err(GatewayError::Audit(AuditError::EventTooLarge {
            bytes: 2,
            max: 1,
        })),
    ));
}
