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
}
