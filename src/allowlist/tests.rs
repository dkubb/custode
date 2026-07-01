use super::{AcceptedTarget, RejectionReason};
use crate::config::AllowedPath;

#[test]
fn prefix_matches_path_segments_only() {
    let allowed = AllowedPath::prefix("/v1/responses").expect("prefix should be valid");

    assert!(allowed.matches("/v1/responses"));
    assert!(allowed.matches("/v1/responses/abc"));
    assert!(!allowed.matches("/v1/responses-abc"));
}

#[test]
fn target_rejects_invalid_percent_encoding() {
    assert_eq!(
        AcceptedTarget::new("/v1/%zz", None),
        Err(RejectionReason::InvalidPercentEncoding),
    );
}

#[test]
fn target_rejects_literal_dot_segments() {
    assert_eq!(
        AcceptedTarget::new("/v1/responses/../models", None),
        Err(RejectionReason::DotSegment),
    );
    assert_eq!(
        AcceptedTarget::new("/v1/responses/./models", None),
        Err(RejectionReason::DotSegment),
    );
}

#[test]
fn target_rejects_percent_encoded_dot_segments() {
    assert_eq!(
        AcceptedTarget::new("/v1/responses/%2e%2e/models", None),
        Err(RejectionReason::DotSegment),
    );
    assert_eq!(
        AcceptedTarget::new("/v1/responses/%2E/models", None),
        Err(RejectionReason::DotSegment),
    );
}
