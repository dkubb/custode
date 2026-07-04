//! Request target parsing.

/// Maximum accepted origin-form request path bytes.
pub(crate) const MAX_ORIGIN_FORM_PATH_BYTES: usize = 4_096;
/// Maximum accepted origin-form request query bytes.
pub(crate) const MAX_ORIGIN_FORM_QUERY_BYTES: usize = 8_192;

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

    /// Path contained a percent-encoded path separator.
    EncodedSeparator,

    /// Path contained invalid percent-encoding.
    InvalidPercentEncoding,

    /// Path was not origin-form.
    NonOriginForm,

    /// Path exceeded the supported byte limit.
    TooLong,
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

    /// Query exceeded the supported byte limit.
    TooLong,
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
    /// Returns an error when the path exceeds the byte limit, is not
    /// origin-form, contains invalid percent-encoding, contains a
    /// percent-encoded path separator, or contains a literal or
    /// percent-encoded dot segment.
    pub(crate) fn parse(path: &str) -> Result<Self, OriginFormPathError> {
        if path.len() > MAX_ORIGIN_FORM_PATH_BYTES {
            return Err(OriginFormPathError::TooLong);
        }
        if !path.starts_with('/') {
            return Err(OriginFormPathError::NonOriginForm);
        }
        if !has_valid_percent_encoding(path) {
            return Err(OriginFormPathError::InvalidPercentEncoding);
        }
        if has_encoded_separator(path) {
            return Err(OriginFormPathError::EncodedSeparator);
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
    /// Returns an error when the query exceeds the byte limit or contains
    /// invalid percent-encoding.
    pub(crate) fn parse(query: &str) -> Result<Self, OriginFormQueryError> {
        if query.len() > MAX_ORIGIN_FORM_QUERY_BYTES {
            return Err(OriginFormQueryError::TooLong);
        }
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

/// Returns true when a percent escape decodes to a path separator byte.
fn has_encoded_separator(path: &str) -> bool {
    let mut bytes = path.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let Some(first) = bytes.next() else {
                return false;
            };
            let Some(second) = bytes.next() else {
                return false;
            };
            let Some(decoded) = decode_hex_pair(first, second) else {
                return false;
            };
            if matches!(decoded, b'/' | b'\\') {
                return true;
            }
        }
    }
    false
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
#[expect(
    clippy::inline_modules,
    reason = "inline test generators keep parser and generator contracts adjacent"
)]
pub mod testing {
    //! Test-only generators for origin-form targets.

    use proptest::collection;
    use proptest::prelude::*;

    /// Valid percent escapes spanning every byte and both hex cases.
    fn percent_escape_valid() -> impl Strategy<Value = String> {
        (any::<u8>(), any::<bool>()).prop_map(|(byte, uppercase)| {
            if uppercase {
                format!("%{byte:02X}")
            } else {
                format!("%{byte:02x}")
            }
        })
    }

    /// Query atom accepted by the parser.
    fn query_atom_valid() -> impl Strategy<Value = String> {
        prop_oneof![
            "[A-Za-z0-9._~-]{1,8}",
            prop_oneof![
                Just("!".to_owned()),
                Just("$".to_owned()),
                Just("&".to_owned()),
                Just("'".to_owned()),
                Just("(".to_owned()),
                Just(")".to_owned()),
                Just("*".to_owned()),
                Just("+".to_owned()),
                Just(",".to_owned()),
                Just("/".to_owned()),
                Just(":".to_owned()),
                Just(";".to_owned()),
                Just("=".to_owned()),
                Just("?".to_owned()),
                Just("@".to_owned()),
            ],
            percent_escape_valid(),
        ]
    }

    /// Query atom accepted by the parser and preserved by `url::Url`.
    fn url_preserved_query_atom_valid() -> impl Strategy<Value = String> {
        prop_oneof![
            "[A-Za-z0-9._~-]{1,8}",
            prop_oneof![
                Just("!".to_owned()),
                Just("$".to_owned()),
                Just("&".to_owned()),
                Just("(".to_owned()),
                Just(")".to_owned()),
                Just("*".to_owned()),
                Just("+".to_owned()),
                Just(",".to_owned()),
                Just("/".to_owned()),
                Just(":".to_owned()),
                Just(";".to_owned()),
                Just("=".to_owned()),
                Just("?".to_owned()),
                Just("@".to_owned()),
            ],
            percent_escape_valid(),
        ]
    }

    /// Valid query strings accepted as origin-form query witnesses.
    pub(crate) fn origin_form_query_valid() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(String::new()),
            collection::vec(query_atom_valid(), 1..=8).prop_map(|atoms| atoms.concat()),
        ]
    }

    /// Accepted query strings whose raw spelling is preserved by `url::Url`.
    pub(crate) fn url_preserved_origin_form_query_valid() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(String::new()),
            collection::vec(url_preserved_query_atom_valid(), 1..=8)
                .prop_map(|atoms| atoms.concat()),
        ]
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
        DotSegmentState, MAX_ORIGIN_FORM_PATH_BYTES, MAX_ORIGIN_FORM_QUERY_BYTES, OriginFormPath,
        OriginFormPathError, OriginFormQuery, OriginFormQueryError,
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
    fn path_rejects_percent_encoded_separators() {
        for path in [
            "/v1/responses/%2fmodels",
            "/v1/responses/%2Fmodels",
            "/v1/responses/%5cmodels",
            "/v1/responses/%5Cmodels",
            "/v1/responses/%2e%2e%2fmodels",
        ] {
            assert_eq!(
                OriginFormPath::parse(path),
                Err(OriginFormPathError::EncodedSeparator),
                "path {path}"
            );
        }
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
    fn path_accepts_the_maximum_supported_length() {
        let path = format!("/{}", "a".repeat(MAX_ORIGIN_FORM_PATH_BYTES - 1));
        let parsed = OriginFormPath::parse(&path).expect("maximum path should parse");

        assert_eq!(parsed.as_str(), path);
    }

    #[test]
    fn path_rejects_lengths_over_the_supported_maximum() {
        let path = format!("/{}", "a".repeat(MAX_ORIGIN_FORM_PATH_BYTES));

        assert_eq!(
            OriginFormPath::parse(&path),
            Err(OriginFormPathError::TooLong),
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
    fn query_accepts_the_maximum_supported_length() {
        let query = "a".repeat(MAX_ORIGIN_FORM_QUERY_BYTES);
        let parsed = OriginFormQuery::parse(&query).expect("maximum query should parse");

        assert_eq!(parsed.as_str(), query);
    }

    #[test]
    fn query_rejects_invalid_percent_encoding() {
        assert_eq!(
            OriginFormQuery::parse("bad=%zz"),
            Err(OriginFormQueryError::InvalidPercentEncoding),
        );
    }

    #[test]
    fn query_rejects_lengths_over_the_supported_maximum() {
        let query = "a".repeat(MAX_ORIGIN_FORM_QUERY_BYTES + 1);

        assert_eq!(
            OriginFormQuery::parse(&query),
            Err(OriginFormQueryError::TooLong),
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
        assert!(!super::has_encoded_separator("%"));
        assert!(!super::has_encoded_separator("%2"));
        assert!(!super::has_encoded_separator("%zz"));
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
    use super::testing::origin_form_query_valid;
    use super::{
        MAX_ORIGIN_FORM_PATH_BYTES, MAX_ORIGIN_FORM_QUERY_BYTES, OriginFormPath,
        OriginFormPathError, OriginFormQuery, OriginFormQueryError,
    };
    use proptest::collection;
    use proptest::prelude::*;

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
            1 => path_escape_valid(),
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

    /// Paths containing one encoded path separator.
    fn path_with_encoded_separator() -> impl Strategy<Value = String> {
        (
            path_valid(),
            prop_oneof![Just("%2f"), Just("%2F"), Just("%5c"), Just("%5C"),],
            "[A-Za-z0-9_-]{1,8}",
        )
            .prop_map(|(prefix, separator, suffix)| format!("{prefix}{separator}{suffix}"))
    }

    /// Paths missing the leading slash.
    fn path_non_origin_form() -> impl Strategy<Value = String> {
        "[A-Za-z0-9_-][A-Za-z0-9/_-]{0,12}"
    }

    /// Origin-form paths longer than the supported byte limit.
    fn path_too_long() -> impl Strategy<Value = String> {
        (MAX_ORIGIN_FORM_PATH_BYTES..=MAX_ORIGIN_FORM_PATH_BYTES + 64)
            .prop_map(|tail_len| format!("/{}", "a".repeat(tail_len)))
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

    /// Queries longer than the supported byte limit.
    fn query_too_long() -> impl Strategy<Value = String> {
        (MAX_ORIGIN_FORM_QUERY_BYTES + 1..=MAX_ORIGIN_FORM_QUERY_BYTES + 64)
            .prop_map(|len| "a".repeat(len))
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
        fn parse_rejects_every_encoded_separator(path in path_with_encoded_separator()) {
            prop_assert_eq!(
                OriginFormPath::parse(&path),
                Err(OriginFormPathError::EncodedSeparator)
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
        fn parse_rejects_every_too_long_path(path in path_too_long()) {
            prop_assert_eq!(
                OriginFormPath::parse(&path),
                Err(OriginFormPathError::TooLong)
            );
        }

        #[test]
        fn query_parse_accepts_every_valid_query(query in origin_form_query_valid()) {
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
        fn query_parse_rejects_every_too_long_query(query in query_too_long()) {
            prop_assert_eq!(
                OriginFormQuery::parse(&query),
                Err(OriginFormQueryError::TooLong)
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
