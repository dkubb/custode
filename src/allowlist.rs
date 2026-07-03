//! Method and path allowlist decisions.

use crate::config::GatewayConfig;
use crate::target::{OriginFormPath, OriginFormPathError, OriginFormQuery, OriginFormQueryError};
use ::http::Method;

/// Request target accepted by the gateway.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcceptedTarget {
    /// Origin-form path.
    path: OriginFormPath,
    /// Optional query string without `?`.
    query: Option<OriginFormQuery>,
}

/// Request target proven to match the configured allowlist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AllowedTarget {
    /// Allowed request method.
    method: Method,
    /// Accepted target matched by the method.
    target: AcceptedTarget,
}

impl AcceptedTarget {
    /// Creates a target from an origin-form request path and optional query.
    ///
    /// # Errors
    ///
    /// Returns a rejection when the path is not origin-form, when the path or
    /// query exceeds the byte limit, when the path or query contains invalid
    /// percent-encoding, or when the path contains a literal or
    /// percent-encoded dot segment.
    pub(crate) fn new(path: &str, query: Option<&str>) -> Result<Self, RejectionReason> {
        let accepted_path = OriginFormPath::parse(path).map_err(rejection_from_path_error)?;
        let accepted_query = query
            .map(OriginFormQuery::parse)
            .transpose()
            .map_err(rejection_from_query_error)?;

        Ok(Self {
            path: accepted_path,
            query: accepted_query,
        })
    }

    /// Returns the accepted origin-form path witness.
    #[must_use]
    pub(crate) const fn origin_form_path(&self) -> &OriginFormPath {
        &self.path
    }

    /// Returns the accepted origin-form query witness.
    #[must_use]
    pub(crate) const fn origin_form_query(&self) -> Option<&OriginFormQuery> {
        self.query.as_ref()
    }

    /// Returns the accepted path.
    #[must_use]
    pub(crate) fn path(&self) -> &str {
        self.path.as_str()
    }

    /// Returns the accepted query.
    #[must_use]
    pub(crate) fn query(&self) -> Option<&str> {
        self.query.as_ref().map(OriginFormQuery::as_str)
    }
}

impl AllowedTarget {
    /// Returns the allowed request method.
    #[must_use]
    pub(crate) const fn method(&self) -> &Method {
        &self.method
    }

    /// Returns the allowlist-matched target.
    #[must_use]
    pub(crate) const fn target(&self) -> &AcceptedTarget {
        &self.target
    }
}

/// Reason a request is rejected before upstream forwarding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RejectionReason {
    /// The path contained a literal or percent-encoded `.` or `..` segment.
    DotSegment,

    /// The path contained a percent-encoded separator.
    EncodedSeparator,

    /// The path contained invalid percent-encoding.
    InvalidPercentEncoding,

    /// The method was not in the allowlist.
    MethodDenied,

    /// The target was not an origin-form path beginning with `/`.
    NonOriginForm,

    /// The path was not in the allowlist.
    PathDenied,

    /// The path exceeded the supported byte limit.
    PathTooLong,

    /// The query exceeded the supported byte limit.
    QueryTooLong,
}

/// Checks whether a request is allowed by the configured method and path sets.
#[must_use]
fn is_allowed(config: &GatewayConfig, method: &Method, target: &AcceptedTarget) -> bool {
    config
        .allowed_operations()
        .iter()
        .any(|operation| operation.matches(method, target.origin_form_path()))
}

/// Returns the rejection reason for a denied method.
#[must_use]
fn rejection_for(config: &GatewayConfig, method: &Method) -> RejectionReason {
    if config
        .allowed_operations()
        .iter()
        .any(|operation| operation.has_method(method))
    {
        RejectionReason::PathDenied
    } else {
        RejectionReason::MethodDenied
    }
}

/// Maps origin-form path errors into request rejection reasons.
const fn rejection_from_path_error(error: OriginFormPathError) -> RejectionReason {
    match error {
        OriginFormPathError::DotSegment => RejectionReason::DotSegment,
        OriginFormPathError::EncodedSeparator => RejectionReason::EncodedSeparator,
        OriginFormPathError::InvalidPercentEncoding => RejectionReason::InvalidPercentEncoding,
        OriginFormPathError::NonOriginForm => RejectionReason::NonOriginForm,
        OriginFormPathError::TooLong => RejectionReason::PathTooLong,
    }
}

/// Maps origin-form query errors into request rejection reasons.
const fn rejection_from_query_error(error: OriginFormQueryError) -> RejectionReason {
    match error {
        OriginFormQueryError::InvalidPercentEncoding => RejectionReason::InvalidPercentEncoding,
        OriginFormQueryError::TooLong => RejectionReason::QueryTooLong,
    }
}

/// Proves that an accepted target is allowed for the supplied method.
///
/// # Errors
///
/// Returns a rejection reason when the method or path is outside the
/// configured allowlist.
pub(crate) fn allow_target(
    config: &GatewayConfig,
    method: &Method,
    target: AcceptedTarget,
) -> Result<AllowedTarget, RejectionReason> {
    if is_allowed(config, method, &target) {
        Ok(AllowedTarget {
            method: method.clone(),
            target,
        })
    } else {
        Err(rejection_for(config, method))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[expect(
    clippy::inline_modules,
    reason = "inline tests keep file-local coverage ownership explicit"
)]
mod tests {
    use super::{AcceptedTarget, RejectionReason, is_allowed, rejection_for};
    use crate::config::{AllowedPath, GatewayConfig};
    use crate::target::{
        MAX_ORIGIN_FORM_PATH_BYTES, MAX_ORIGIN_FORM_QUERY_BYTES, OriginFormPath, OriginFormQuery,
    };
    use ::http::Method;
    use core::num::NonZeroUsize;
    use pretty_assertions::assert_eq;
    use std::path::PathBuf;

    /// Builds a config allowing only `GET:exact:/v1/models`.
    fn config_with_get_models() -> GatewayConfig {
        GatewayConfig::for_test(
            PathBuf::from("/unused/audit.ndjson"),
            NonZeroUsize::new(0x4000).expect("limit should be non-zero"),
        )
    }

    /// Parses a test origin-form path.
    fn origin_form_path(path: &str) -> OriginFormPath {
        OriginFormPath::parse(path).expect("test path should parse")
    }

    #[test]
    fn prefix_matches_path_segments_only() {
        let allowed = AllowedPath::prefix("/v1/responses").expect("prefix should be valid");

        assert!(allowed.matches(&origin_form_path("/v1/responses")));
        assert!(allowed.matches(&origin_form_path("/v1/responses/abc")));
        assert!(!allowed.matches(&origin_form_path("/v1/responses-abc")));
    }

    #[test]
    fn target_rejects_invalid_percent_encoding() {
        assert_eq!(
            AcceptedTarget::new("/v1/%zz", None),
            Err(RejectionReason::InvalidPercentEncoding),
        );
        assert_eq!(
            AcceptedTarget::new("/v1/models", Some("bad=%zz")),
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

    #[test]
    fn target_rejects_percent_encoded_separators() {
        assert_eq!(
            AcceptedTarget::new("/v1/responses/%2e%2e%2fmodels", None),
            Err(RejectionReason::EncodedSeparator),
        );
        assert_eq!(
            AcceptedTarget::new("/v1/responses/%5cmodels", None),
            Err(RejectionReason::EncodedSeparator),
        );
    }

    #[test]
    fn target_preserves_accepted_path_and_query() {
        let target = AcceptedTarget::new("/v1/models", Some("limit=1"))
            .expect("origin-form path should be accepted");

        assert_eq!(target.path(), "/v1/models");
        assert_eq!(target.query(), Some("limit=1"));
        assert_eq!(
            target.origin_form_query().map(OriginFormQuery::as_str),
            Some("limit=1"),
        );
    }

    #[test]
    fn target_rejects_non_origin_form_paths() {
        assert_eq!(
            AcceptedTarget::new("v1/models", None),
            Err(RejectionReason::NonOriginForm),
        );
    }

    #[test]
    fn target_rejects_truncated_percent_escapes() {
        assert_eq!(
            AcceptedTarget::new("/v1/%", None),
            Err(RejectionReason::InvalidPercentEncoding),
        );
        assert_eq!(
            AcceptedTarget::new("/v1/%2", None),
            Err(RejectionReason::InvalidPercentEncoding),
        );
    }

    #[test]
    fn target_rejects_paths_over_the_supported_maximum() {
        let path = format!("/{}", "a".repeat(MAX_ORIGIN_FORM_PATH_BYTES));

        assert_eq!(
            AcceptedTarget::new(&path, None),
            Err(RejectionReason::PathTooLong),
        );
    }

    #[test]
    fn target_rejects_queries_over_the_supported_maximum() {
        let query = "a".repeat(MAX_ORIGIN_FORM_QUERY_BYTES + 1);

        assert_eq!(
            AcceptedTarget::new("/v1/models", Some(&query)),
            Err(RejectionReason::QueryTooLong),
        );
    }

    #[test]
    fn target_accepts_segments_of_three_or_more_dots() {
        for path in ["/.../x", "/...."] {
            let target = AcceptedTarget::new(path, None)
                .expect("segments of three or more dots should be accepted");

            assert_eq!(target.path(), path, "path {path}");
        }
    }

    #[test]
    fn is_allowed_accepts_only_configured_operations() {
        let config = config_with_get_models();
        let allowed = AcceptedTarget::new("/v1/models", None).expect("path should be accepted");
        let denied = AcceptedTarget::new("/v1/other", None).expect("path should be accepted");

        assert!(is_allowed(&config, &Method::GET, &allowed));
        assert!(!is_allowed(&config, &Method::POST, &allowed));
        assert!(!is_allowed(&config, &Method::GET, &denied));
    }

    #[test]
    fn rejection_for_reports_path_denied_for_known_methods() {
        let config = config_with_get_models();

        assert_eq!(
            rejection_for(&config, &Method::GET),
            RejectionReason::PathDenied,
        );
    }

    #[test]
    fn rejection_for_reports_method_denied_for_unknown_methods() {
        let config = config_with_get_models();

        assert_eq!(
            rejection_for(&config, &Method::DELETE),
            RejectionReason::MethodDenied,
        );
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[expect(
    clippy::inline_modules,
    reason = "inline proptests keep file-local coverage ownership explicit"
)]
mod proptests {
    use super::{AcceptedTarget, RejectionReason, is_allowed, rejection_for};
    use crate::config::GatewayConfig;
    use crate::target::{MAX_ORIGIN_FORM_PATH_BYTES, MAX_ORIGIN_FORM_QUERY_BYTES};
    use ::http::Method;
    use core::num::NonZeroUsize;
    use proptest::prelude::*;
    use proptest::{collection, option};
    use std::path::PathBuf;

    /// Builds the fixed test config allowing only `GET:exact:/v1/models`.
    fn config_with_get_models() -> GatewayConfig {
        GatewayConfig::for_test(
            PathBuf::from("/unused/audit.ndjson"),
            NonZeroUsize::new(0x4000).expect("limit should be non-zero"),
        )
    }

    /// Percent escapes that cannot change path segment structure.
    fn path_escape_valid() -> impl Strategy<Value = String> {
        (any::<u8>(), any::<bool>()).prop_filter_map(
            "path escapes cannot decode to dots or separators",
            |(byte, uppercase)| {
                (!matches!(byte, b'.' | b'/' | b'\\')).then(|| {
                    if uppercase {
                        format!("%{byte:02X}")
                    } else {
                        format!("%{byte:02x}")
                    }
                })
            },
        )
    }

    /// Methods spanning the configured operation and representative others.
    fn method_any() -> impl Strategy<Value = Method> {
        prop_oneof![
            Just(Method::DELETE),
            Just(Method::GET),
            Just(Method::POST),
            Just(Method::PUT),
        ]
    }

    /// Path segments that decode to something other than `.` or `..`:
    /// broad alphanumeric segments plus biased near-dot spellings that are
    /// still legal, such as `...`, `a.`, `.a`, and dotted file names, plus
    /// percent escapes of non-dot bytes.
    fn segment_valid() -> impl Strategy<Value = String> {
        prop_oneof![
            2 => "[A-Za-z0-9_-]{1,8}",
            1 => prop_oneof![
                Just("...".to_owned()),
                Just("a.".to_owned()),
                Just(".a".to_owned()),
                Just("a.b".to_owned()),
                Just("%2ea".to_owned()),
                Just("a%2e".to_owned()),
            ],
            1 => path_escape_valid(),
        ]
    }

    /// Origin-form paths built only from non-empty valid segments.
    fn path_plain() -> impl Strategy<Value = String> {
        collection::vec(segment_valid(), 1..4)
            .prop_map(|segments| format!("/{}", segments.join("/")))
    }

    /// Origin-form paths built only from valid segments, biased toward
    /// boundary shapes with an empty leading segment or a trailing slash.
    fn path_valid() -> impl Strategy<Value = String> {
        prop_oneof![
            3 => path_plain(),
            1 => path_plain().prop_map(|path| format!("{path}/")),
            1 => path_plain().prop_map(|path| format!("/{path}")),
        ]
    }

    /// Segments that decode exactly to `.` or `..` in any encoding mix.
    fn segment_dot() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(".".to_owned()),
            Just("..".to_owned()),
            Just("%2e".to_owned()),
            Just("%2E".to_owned()),
            Just("%2e%2e".to_owned()),
            Just(".%2e".to_owned()),
            Just("%2E.".to_owned()),
        ]
    }

    /// Valid paths with one dot segment spliced in.
    fn path_with_dot_segment() -> impl Strategy<Value = String> {
        (path_valid(), segment_dot(), path_valid())
            .prop_map(|(prefix, dot, suffix)| format!("{prefix}/{dot}{suffix}"))
    }

    /// Paths whose final percent escape is truncated or non-hex.
    fn path_with_invalid_percent() -> impl Strategy<Value = String> {
        (
            path_valid(),
            prop_oneof![
                Just(String::new()),
                "[0-9a-fA-F]",
                "[g-zG-Z]{2}",
                "[0-9a-fA-F][g-zG-Z]",
            ],
        )
            .prop_map(|(path, escape)| format!("{path}%{escape}"))
    }

    /// Paths containing one encoded path separator.
    fn path_with_encoded_separator() -> impl Strategy<Value = String> {
        (
            path_valid(),
            prop_oneof![Just("%2f"), Just("%2F"), Just("%5c"), Just("%5C"),],
            "[A-Za-z0-9_-]{1,8}",
        )
            .prop_map(|(prefix, separator, suffix)| format!("{prefix}{separator}{suffix}"))
    }

    /// Paths missing the leading slash (first invalid origin-form).
    fn path_non_origin_form() -> impl Strategy<Value = String> {
        "[A-Za-z0-9_-][A-Za-z0-9/_-]{0,12}"
    }

    /// Origin-form paths that exceed the supported byte limit.
    fn path_too_long() -> impl Strategy<Value = String> {
        (MAX_ORIGIN_FORM_PATH_BYTES..=MAX_ORIGIN_FORM_PATH_BYTES + 64)
            .prop_map(|tail_len| format!("/{}", "a".repeat(tail_len)))
    }

    /// Queries that exceed the supported byte limit.
    fn query_too_long() -> impl Strategy<Value = String> {
        (MAX_ORIGIN_FORM_QUERY_BYTES + 1..=MAX_ORIGIN_FORM_QUERY_BYTES + 64)
            .prop_map(|len| "a".repeat(len))
    }

    proptest! {
        #[test]
        fn new_accepts_every_valid_path(
            path in path_valid(),
            query in option::of("[a-z]{1,5}=[a-z]{1,5}"),
        ) {
            let target = AcceptedTarget::new(&path, query.as_deref())
                .expect("valid paths should be accepted");

            prop_assert_eq!(target.path(), path.as_str());
            prop_assert_eq!(target.query(), query.as_deref());
        }

        #[test]
        fn new_rejects_every_dot_segment_path(path in path_with_dot_segment()) {
            prop_assert_eq!(
                AcceptedTarget::new(&path, None),
                Err(RejectionReason::DotSegment)
            );
        }

        #[test]
        fn new_rejects_every_invalid_percent_escape(path in path_with_invalid_percent()) {
            prop_assert_eq!(
                AcceptedTarget::new(&path, None),
                Err(RejectionReason::InvalidPercentEncoding)
            );
        }

        #[test]
        fn new_rejects_every_encoded_separator(path in path_with_encoded_separator()) {
            prop_assert_eq!(
                AcceptedTarget::new(&path, None),
                Err(RejectionReason::EncodedSeparator)
            );
        }

        #[test]
        fn new_rejects_every_non_origin_form_path(path in path_non_origin_form()) {
            prop_assert_eq!(
                AcceptedTarget::new(&path, None),
                Err(RejectionReason::NonOriginForm)
            );
        }

        #[test]
        fn new_rejects_every_too_long_path(path in path_too_long()) {
            prop_assert_eq!(
                AcceptedTarget::new(&path, None),
                Err(RejectionReason::PathTooLong)
            );
        }

        #[test]
        fn new_rejects_every_too_long_query(query in query_too_long()) {
            prop_assert_eq!(
                AcceptedTarget::new("/v1/models", Some(&query)),
                Err(RejectionReason::QueryTooLong)
            );
        }

        #[test]
        fn is_allowed_accepts_exactly_the_configured_operation(
            method in method_any(),
            path in prop_oneof![1 => Just("/v1/models".to_owned()), 3 => path_valid()],
        ) {
            let config = config_with_get_models();
            let target = AcceptedTarget::new(&path, None)
                .expect("valid paths should be accepted");

            let allowed = is_allowed(&config, &method, &target);

            let expected = method == Method::GET && path == "/v1/models";
            prop_assert_eq!(allowed, expected);
        }

        #[test]
        fn rejection_reflects_method_membership(method in method_any()) {
            let config = config_with_get_models();

            let rejection = rejection_for(&config, &method);

            let expected = if method == Method::GET {
                RejectionReason::PathDenied
            } else {
                RejectionReason::MethodDenied
            };
            prop_assert_eq!(rejection, expected);
        }
    }
}
