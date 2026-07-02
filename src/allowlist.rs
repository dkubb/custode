//! Method and path allowlist decisions.

use crate::config::GatewayConfig;
use ::http::Method;

/// Request target accepted by the gateway.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AcceptedTarget {
    /// Origin-form path.
    path: String,
    /// Optional query string without `?`.
    query: Option<String>,
}

impl AcceptedTarget {
    /// Creates a target from an origin-form request path and optional query.
    ///
    /// # Errors
    ///
    /// Returns a rejection when the path is not origin-form, contains invalid
    /// percent-encoding, or contains a literal or percent-encoded dot segment.
    pub(crate) fn new(path: &str, query: Option<&str>) -> Result<Self, RejectionReason> {
        if !path.starts_with('/') {
            return Err(RejectionReason::NonOriginForm);
        }
        if !has_valid_percent_encoding(path) {
            return Err(RejectionReason::InvalidPercentEncoding);
        }
        if has_dot_segment(path) {
            return Err(RejectionReason::DotSegment);
        }

        Ok(Self {
            path: path.to_owned(),
            query: query.map(str::to_owned),
        })
    }

    /// Returns the accepted path.
    #[must_use]
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    /// Returns the accepted query.
    #[must_use]
    pub(crate) fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }
}

/// Reason a request is rejected before upstream forwarding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RejectionReason {
    /// The request target included a scheme or authority.
    AbsoluteFormUnsupported,

    /// `CONNECT` is never accepted.
    ConnectUnsupported,

    /// The path contained a literal or percent-encoded `.` or `..` segment.
    DotSegment,

    /// The path contained invalid percent-encoding.
    InvalidPercentEncoding,

    /// The method was not in the allowlist.
    MethodDenied,

    /// The target was not an origin-form path beginning with `/`.
    NonOriginForm,

    /// The path was not in the allowlist.
    PathDenied,
}

/// Decoded dot-segment recognition state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DotSegmentState {
    /// No dot bytes have been decoded.
    Empty,
    /// One dot byte has been decoded.
    OneDot,
    /// More than two dot bytes have been decoded.
    TooLong,
    /// Two dot bytes have been decoded.
    TwoDots,
}

impl DotSegmentState {
    /// Advances the state after decoding one dot byte.
    const fn accept_dot(self) -> Self {
        match self {
            Self::Empty => Self::OneDot,
            Self::OneDot => Self::TwoDots,
            Self::TooLong | Self::TwoDots => Self::TooLong,
        }
    }

    /// Returns true when the state is a forbidden dot segment.
    const fn is_rejected(self) -> bool {
        matches!(self, Self::OneDot | Self::TwoDots)
    }
}

impl RejectionReason {
    /// Returns a stable audit error class.
    #[must_use]
    pub(crate) const fn error_class(self) -> &'static str {
        match self {
            Self::AbsoluteFormUnsupported => "absolute_form_unsupported",
            Self::ConnectUnsupported => "connect_unsupported",
            Self::DotSegment => "dot_segment",
            Self::InvalidPercentEncoding => "invalid_percent_encoding",
            Self::MethodDenied => "method_denied",
            Self::NonOriginForm => "non_origin_form",
            Self::PathDenied => "path_denied",
        }
    }
}

/// Checks whether a request is allowed by the configured method and path sets.
#[must_use]
pub(crate) fn is_allowed(config: &GatewayConfig, method: &Method, target: &AcceptedTarget) -> bool {
    config
        .allowed_operations()
        .iter()
        .any(|operation| operation.matches(method, target.path()))
}

/// Returns the rejection reason for a denied method.
#[must_use]
pub(crate) fn rejection_for(config: &GatewayConfig, method: &Method) -> RejectionReason {
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

/// Returns true when all percent escape sequences have two hex digits.
fn has_valid_percent_encoding(path: &str) -> bool {
    let mut bytes = path.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let Some(first) = bytes.next() else {
                return false;
            };
            let Some(second) = bytes.next() else {
                return false;
            };
            if !first.is_ascii_hexdigit() || !second.is_ascii_hexdigit() {
                return false;
            }
        }
    }
    true
}

/// Returns true when any path segment decodes exactly to `.` or `..`.
fn has_dot_segment(path: &str) -> bool {
    path.split('/').any(segment_is_dot_segment)
}

/// Returns true when a path segment is a literal or percent-encoded dot segment.
fn segment_is_dot_segment(segment: &str) -> bool {
    let mut state = DotSegmentState::Empty;
    let mut bytes = segment.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        let decoded = if byte == b'%' {
            let Some(first) = bytes.next() else {
                return false;
            };
            let Some(second) = bytes.next() else {
                return false;
            };
            let Some(decoded) = decode_hex_pair(first, second) else {
                return false;
            };
            decoded
        } else {
            byte
        };

        if decoded != b'.' {
            return false;
        }
        state = state.accept_dot();
        if state == DotSegmentState::TooLong {
            return false;
        }
    }

    state.is_rejected()
}

/// Decodes two ASCII hex digits into one byte.
fn decode_hex_pair(first: u8, second: u8) -> Option<u8> {
    let high = hex_value(first)?;
    let low = hex_value(second)?;
    // The nibbles occupy disjoint bit ranges, so `|` is exact here and a
    // `^` mutation is equivalent.
    Some((high << 4) | low)
}

/// Decodes one ASCII hex digit.
const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0' => Some(0),
        b'1' => Some(1),
        b'2' => Some(2),
        b'3' => Some(3),
        b'4' => Some(4),
        b'5' => Some(5),
        b'6' => Some(6),
        b'7' => Some(7),
        b'8' => Some(8),
        b'9' => Some(9),
        b'A' | b'a' => Some(10),
        b'B' | b'b' => Some(11),
        b'C' | b'c' => Some(12),
        b'D' | b'd' => Some(13),
        b'E' | b'e' => Some(14),
        b'F' | b'f' => Some(15),
        _ => None,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{AcceptedTarget, DotSegmentState, RejectionReason, is_allowed, rejection_for};
    use crate::config::{AllowedPath, GatewayConfig};
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

    #[test]
    fn error_class_is_stable_for_every_reason() {
        let expected = [
            (
                RejectionReason::AbsoluteFormUnsupported,
                "absolute_form_unsupported",
            ),
            (RejectionReason::ConnectUnsupported, "connect_unsupported"),
            (RejectionReason::DotSegment, "dot_segment"),
            (
                RejectionReason::InvalidPercentEncoding,
                "invalid_percent_encoding",
            ),
            (RejectionReason::MethodDenied, "method_denied"),
            (RejectionReason::NonOriginForm, "non_origin_form"),
            (RejectionReason::PathDenied, "path_denied"),
        ];

        for (reason, class) in expected {
            assert_eq!(reason.error_class(), class);
        }
    }

    #[test]
    fn hex_value_decodes_every_hex_digit() {
        let digits = b"0123456789ABCDEF";
        let lowercase = b"0123456789abcdef";

        for (value, (upper, lower)) in digits.iter().zip(lowercase).enumerate() {
            let expected = Some(u8::try_from(value).expect("hex values fit in u8"));
            assert_eq!(super::hex_value(*upper), expected, "byte {upper:#x}");
            assert_eq!(super::hex_value(*lower), expected, "byte {lower:#x}");
        }
    }

    #[test]
    fn hex_value_rejects_non_hex_bytes() {
        for byte in [b'g', b'G', b'z', b'/', b':', b'@', b'`', 0, 0xFF] {
            assert_eq!(super::hex_value(byte), None, "byte {byte:#x}");
        }
    }

    #[test]
    fn decode_hex_pair_combines_nibbles() {
        assert_eq!(super::decode_hex_pair(b'2', b'e'), Some(0x2e));
        assert_eq!(super::decode_hex_pair(b'3', b'0'), Some(0x30));
        assert_eq!(super::decode_hex_pair(b'z', b'0'), None);
        assert_eq!(super::decode_hex_pair(b'0', b'z'), None);
    }

    #[test]
    fn target_preserves_accepted_path_and_query() {
        let target = AcceptedTarget::new("/v1/models", Some("limit=1"))
            .expect("origin-form path should be accepted");

        assert_eq!(target.path(), "/v1/models");
        assert_eq!(target.query(), Some("limit=1"));
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

    #[test]
    fn accept_dot_walks_every_transition() {
        let transitions = [
            (DotSegmentState::Empty, DotSegmentState::OneDot),
            (DotSegmentState::OneDot, DotSegmentState::TwoDots),
            (DotSegmentState::TwoDots, DotSegmentState::TooLong),
            (DotSegmentState::TooLong, DotSegmentState::TooLong),
        ];

        for (state, expected) in transitions {
            assert_eq!(state.accept_dot(), expected, "state {state:?}");
        }
    }

    #[test]
    fn is_rejected_forbids_exactly_one_and_two_dots() {
        let expected = [
            (DotSegmentState::Empty, false),
            (DotSegmentState::OneDot, true),
            (DotSegmentState::TooLong, false),
            (DotSegmentState::TwoDots, true),
        ];

        for (state, rejected) in expected {
            assert_eq!(state.is_rejected(), rejected, "state {state:?}");
        }
    }

    #[test]
    fn segment_is_dot_segment_tolerates_malformed_escapes() {
        // Truncated and non-hex escapes are rejected by percent-encoding
        // validation before segment checks; the early returns here keep the
        // function total over arbitrary segment inputs.
        assert!(!super::segment_is_dot_segment("%"));
        assert!(!super::segment_is_dot_segment("%2"));
        assert!(!super::segment_is_dot_segment("%zz"));
    }
}
