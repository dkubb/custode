//! Request target parsing.

/// Origin-form request path accepted by the gateway.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OriginFormPath {
    /// Parsed origin-form path.
    value: String,
}

/// Origin-form path parsing error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OriginFormPathError {
    /// Path contained a literal or percent-encoded dot segment.
    DotSegment,

    /// Path contained invalid percent-encoding.
    InvalidPercentEncoding,

    /// Path was not origin-form.
    NonOriginForm,
}

/// Origin-form request query accepted by the gateway.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OriginFormQuery {
    /// Parsed query string without `?`.
    value: String,
}

/// Origin-form query parsing error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OriginFormQueryError {
    /// Query contained invalid percent-encoding.
    InvalidPercentEncoding,
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

impl OriginFormPath {
    /// Returns the origin-form path string.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.value
    }

    /// Parses an origin-form path.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is not origin-form, contains invalid
    /// percent-encoding, or contains a literal or percent-encoded dot segment.
    pub(crate) fn parse(path: &str) -> Result<Self, OriginFormPathError> {
        if !path.starts_with('/') {
            return Err(OriginFormPathError::NonOriginForm);
        }
        if !has_valid_percent_encoding(path) {
            return Err(OriginFormPathError::InvalidPercentEncoding);
        }
        if has_dot_segment(path) {
            return Err(OriginFormPathError::DotSegment);
        }

        Ok(Self {
            value: path.to_owned(),
        })
    }
}

impl OriginFormQuery {
    /// Returns the origin-form query string without `?`.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.value
    }

    /// Parses an origin-form query string without `?`.
    ///
    /// # Errors
    ///
    /// Returns an error when the query contains invalid percent-encoding.
    pub(crate) fn parse(query: &str) -> Result<Self, OriginFormQueryError> {
        if !has_valid_percent_encoding(query) {
            return Err(OriginFormQueryError::InvalidPercentEncoding);
        }

        Ok(Self {
            value: query.to_owned(),
        })
    }
}

/// Returns true when all percent escape sequences have two hex digits.
pub(crate) fn has_valid_percent_encoding(value: &str) -> bool {
    let mut bytes = value.as_bytes().iter().copied();
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
#[expect(
    clippy::inline_modules,
    reason = "inline tests keep file-local coverage ownership explicit"
)]
mod tests {
    use super::{
        DotSegmentState, OriginFormPath, OriginFormPathError, OriginFormQuery, OriginFormQueryError,
    };
    use pretty_assertions::assert_eq;

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
    fn decode_hex_pair_combines_nibbles() {
        assert_eq!(super::decode_hex_pair(b'2', b'e'), Some(0x2e));
        assert_eq!(super::decode_hex_pair(b'3', b'0'), Some(0x30));
        assert_eq!(super::decode_hex_pair(b'z', b'0'), None);
        assert_eq!(super::decode_hex_pair(b'0', b'z'), None);
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
    fn path_rejects_invalid_percent_encoding() {
        assert_eq!(
            OriginFormPath::parse("/v1/%zz"),
            Err(OriginFormPathError::InvalidPercentEncoding),
        );
    }

    #[test]
    fn path_rejects_literal_dot_segments() {
        assert_eq!(
            OriginFormPath::parse("/v1/responses/../models"),
            Err(OriginFormPathError::DotSegment),
        );
        assert_eq!(
            OriginFormPath::parse("/v1/responses/./models"),
            Err(OriginFormPathError::DotSegment),
        );
    }

    #[test]
    fn path_rejects_non_origin_form_paths() {
        assert_eq!(
            OriginFormPath::parse("v1/models"),
            Err(OriginFormPathError::NonOriginForm),
        );
    }

    #[test]
    fn path_rejects_percent_encoded_dot_segments() {
        assert_eq!(
            OriginFormPath::parse("/v1/responses/%2e%2e/models"),
            Err(OriginFormPathError::DotSegment),
        );
        assert_eq!(
            OriginFormPath::parse("/v1/responses/%2E/models"),
            Err(OriginFormPathError::DotSegment),
        );
    }

    #[test]
    fn path_rejects_truncated_percent_escapes() {
        assert_eq!(
            OriginFormPath::parse("/v1/%"),
            Err(OriginFormPathError::InvalidPercentEncoding),
        );
        assert_eq!(
            OriginFormPath::parse("/v1/%2"),
            Err(OriginFormPathError::InvalidPercentEncoding),
        );
    }

    #[test]
    fn query_accepts_empty_string() {
        let query = OriginFormQuery::parse("").expect("empty query should parse");

        assert_eq!(query.as_str(), "");
    }

    #[test]
    fn query_accepts_valid_percent_encoding() {
        let query = OriginFormQuery::parse("q=%2e&limit=1").expect("valid query should parse");

        assert_eq!(query.as_str(), "q=%2e&limit=1");
    }

    #[test]
    fn query_rejects_invalid_percent_encoding() {
        assert_eq!(
            OriginFormQuery::parse("bad=%zz"),
            Err(OriginFormQueryError::InvalidPercentEncoding),
        );
    }

    #[test]
    fn query_rejects_truncated_percent_escapes() {
        assert_eq!(
            OriginFormQuery::parse("bad=%"),
            Err(OriginFormQueryError::InvalidPercentEncoding),
        );
        assert_eq!(
            OriginFormQuery::parse("bad=%2"),
            Err(OriginFormQueryError::InvalidPercentEncoding),
        );
    }

    #[test]
    fn path_accepts_segments_of_three_or_more_dots() {
        for path in ["/.../x", "/...."] {
            let parsed = OriginFormPath::parse(path)
                .expect("segments of three or more dots should be accepted");

            assert_eq!(parsed.as_str(), path, "path {path}");
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[expect(
    clippy::inline_modules,
    reason = "inline proptests keep file-local coverage ownership explicit"
)]
mod proptests {
    use super::{OriginFormPath, OriginFormPathError, OriginFormQuery, OriginFormQueryError};
    use proptest::collection;
    use proptest::prelude::*;

    /// Percent escapes of non-dot bytes, spanning the full hex alphabet in
    /// both cases.
    fn escape_non_dot() -> impl Strategy<Value = String> {
        (any::<u8>(), any::<bool>()).prop_filter_map(
            "dot escapes decode to dot segments",
            |(byte, uppercase)| {
                (byte != b'.').then(|| {
                    if uppercase {
                        format!("%{byte:02X}")
                    } else {
                        format!("%{byte:02x}")
                    }
                })
            },
        )
    }

    /// Path segments that decode to something other than `.` or `..`.
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
            1 => escape_non_dot(),
        ]
    }

    /// Origin-form paths built only from non-empty valid segments.
    fn path_plain() -> impl Strategy<Value = String> {
        collection::vec(segment_valid(), 1..4)
            .prop_map(|segments| format!("/{}", segments.join("/")))
    }

    /// Origin-form paths built only from valid segments.
    fn path_valid() -> impl Strategy<Value = String> {
        prop_oneof![
            3 => path_plain(),
            1 => path_plain().prop_map(|path| format!("{path}/")),
            1 => path_plain().prop_map(|path| format!("/{path}")),
        ]
    }

    /// Segments with a representative malformed escape.
    fn segment_malformed_escape() -> impl Strategy<Value = String> {
        (
            "[.]{0,2}",
            prop_oneof![Just(String::new()), "[0-9a-fA-F]", "[g-zG-Z]{2}"],
        )
            .prop_map(|(dots, escape)| format!("{dots}%{escape}"))
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

    /// Paths missing the leading slash.
    fn path_non_origin_form() -> impl Strategy<Value = String> {
        "[A-Za-z0-9_-][A-Za-z0-9/_-]{0,12}"
    }

    /// Valid query strings accepted as origin-form query witnesses.
    fn query_valid() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(String::new()),
            "[A-Za-z0-9_=&.-]{1,24}",
            escape_non_dot(),
        ]
    }

    /// Queries whose final percent escape is truncated or non-hex.
    fn query_with_invalid_percent() -> impl Strategy<Value = String> {
        (
            "[A-Za-z0-9_=&.-]{0,12}",
            prop_oneof![
                Just(String::new()),
                "[0-9a-fA-F]",
                "[g-zG-Z]{2}",
                "[0-9a-fA-F][g-zG-Z]",
            ],
        )
            .prop_map(|(prefix, escape)| format!("{prefix}%{escape}"))
    }

    proptest! {
        #[test]
        fn parse_accepts_every_valid_path(path in path_valid()) {
            let parsed = OriginFormPath::parse(&path)
                .expect("valid paths should be accepted");

            prop_assert_eq!(parsed.as_str(), path.as_str());
        }

        #[test]
        fn parse_rejects_every_dot_segment_path(path in path_with_dot_segment()) {
            prop_assert_eq!(
                OriginFormPath::parse(&path),
                Err(OriginFormPathError::DotSegment)
            );
        }

        #[test]
        fn parse_rejects_every_invalid_percent_escape(path in path_with_invalid_percent()) {
            prop_assert_eq!(
                OriginFormPath::parse(&path),
                Err(OriginFormPathError::InvalidPercentEncoding)
            );
        }

        #[test]
        fn parse_rejects_every_non_origin_form_path(path in path_non_origin_form()) {
            prop_assert_eq!(
                OriginFormPath::parse(&path),
                Err(OriginFormPathError::NonOriginForm)
            );
        }

        #[test]
        fn query_parse_accepts_every_valid_query(query in query_valid()) {
            let parsed = OriginFormQuery::parse(&query)
                .expect("valid query should be accepted");

            prop_assert_eq!(parsed.as_str(), query.as_str());
        }

        #[test]
        fn query_parse_rejects_every_invalid_percent_escape(
            query in query_with_invalid_percent(),
        ) {
            prop_assert_eq!(
                OriginFormQuery::parse(&query),
                Err(OriginFormQueryError::InvalidPercentEncoding)
            );
        }

        #[test]
        fn segment_scanning_is_total_over_malformed_escapes(
            segment in segment_malformed_escape(),
        ) {
            // Percent validation rejects these before segment scanning at
            // runtime; the scanner must still stay total over them.
            prop_assert!(!super::segment_is_dot_segment(&segment));
        }
    }
}
