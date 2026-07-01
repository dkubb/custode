use super::{
    AllowedOperation, AllowedPath, ConfigError, UpstreamOrigin, parse_authorization_source,
};
use std::path::Path;

#[test]
fn allowed_path_requires_leading_slash() {
    assert!(matches!(
        AllowedPath::exact("v1/models"),
        Err(ConfigError::InvalidAllowedPath { .. }),
    ));
}

#[test]
fn authorization_source_rejects_conflicting_files() {
    let result = parse_authorization_source(
        "/run/secrets/bearer".to_owned(),
        "/run/secrets/x-api-key".to_owned(),
    );

    assert!(matches!(
        result,
        Err(ConfigError::ConflictingAuthorizationSources),
    ));
}

#[test]
fn authorization_source_treats_empty_file_as_absent() {
    let source = parse_authorization_source(String::new(), "/run/secrets/x-api-key".to_owned())
        .expect("authorization source should parse");

    assert_eq!(
        source.x_api_key_file_path(),
        Some(Path::new("/run/secrets/x-api-key")),
    );
    assert_eq!(source.bearer_file_path(), None);
}

#[test]
fn operation_binds_method_to_path() {
    let operation =
        AllowedOperation::parse("GET:exact:/v1/models").expect("operation should parse");

    assert!(operation.matches(&http::Method::GET, "/v1/models"));
    assert!(!operation.matches(&http::Method::POST, "/v1/models"));
}

#[test]
fn upstream_origin_rejects_path() {
    assert!(matches!(
        UpstreamOrigin::parse("https://api.openai.com/v1"),
        Err(ConfigError::UpstreamOriginHasComponents),
    ));
}
