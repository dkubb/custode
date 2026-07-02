use super::{AllowedOperation, AllowedPath, ConfigError, UpstreamOrigin, parse_allowed_operations};

#[test]
fn allowed_path_requires_leading_slash() {
    assert!(matches!(
        AllowedPath::exact("v1/models"),
        Err(ConfigError::InvalidAllowedPath { .. }),
    ));
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

#[test]
fn upstream_origin_rejects_wildcard_hosts() {
    for origin in ["https://*", "https://*.openai.com"] {
        assert!(
            matches!(
                UpstreamOrigin::parse(origin),
                Err(ConfigError::WildcardUpstreamHost),
            ),
            "origin {origin} should be rejected"
        );
    }
}

#[test]
fn empty_operations_fail_closed() {
    for operations in [Vec::new(), vec![String::new()]] {
        assert!(matches!(
            parse_allowed_operations(operations),
            Err(ConfigError::EmptyOperations),
        ));
    }
}

#[test]
fn operations_with_a_stray_empty_entry_fail_closed() {
    let operations = vec!["GET:exact:/v1/models".to_owned(), String::new()];

    assert!(matches!(
        parse_allowed_operations(operations),
        Err(ConfigError::InvalidAllowedOperation { .. }),
    ));
}
