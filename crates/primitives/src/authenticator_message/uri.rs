//! Percent-encoding and validation of URI query components, as defined in
//! [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986).

use std::borrow::Cow;

use percent_encoding::{
    AsciiSet, NON_ALPHANUMERIC, PercentEncode, percent_decode_str, utf8_percent_encode,
};

/// Characters that are percent-encoded in query components: everything except the RFC 3986
/// unreserved characters.
const QUERY_COMPONENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Percent-encodes a query key or value.
pub(super) fn encode_query_component(component: &str) -> PercentEncode<'_> {
    utf8_percent_encode(component, QUERY_COMPONENT_ENCODE_SET)
}

/// Percent-decodes a query key or value exactly once. `+` is a literal plus sign.
///
/// Returns `None` if `component` contains a character not allowed in an RFC 3986 query or a
/// malformed `%XX` escape, or if it does not decode to UTF-8.
pub(super) fn decode_query_component(component: &str) -> Option<String> {
    if !is_valid_query_component(component) {
        return None;
    }
    percent_decode_str(component)
        .decode_utf8()
        .ok()
        .map(Cow::into_owned)
}

/// Returns whether `component` is valid in an RFC 3986 query: every byte is a query character,
/// and every `%` starts a `%XX` escape with two hex digits.
fn is_valid_query_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let escape = bytes.get(i + 1..i + 3);
            if !escape.is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit)) {
                return false;
            }
            i += 3;
        } else if is_query_char(bytes[i]) {
            i += 1;
        } else {
            return false;
        }
    }
    true
}

/// Returns whether `byte` may appear unescaped in an RFC 3986 query: an unreserved character, a
/// sub-delimiter, `:`, `@`, `/` or `?`.
fn is_query_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?".contains(&byte)
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case("%2541", "%41"; "decodes_once")]
    #[test_case("a+b", "a+b"; "plus_is_literal")]
    fn decodes_query_components(component: &str, expected: &str) {
        assert_eq!(decode_query_component(component).as_deref(), Some(expected));
    }

    #[test_case("%zz"; "invalid_hex_escape")]
    #[test_case("%4"; "short_escape")]
    #[test_case("%ff"; "invalid_utf8")]
    #[test_case("hello world"; "raw_space")]
    #[test_case("caf\u{e9}"; "raw_non_ascii")]
    #[test_case("\u{7}"; "raw_control")]
    #[test_case("a<b"; "raw_delimiter")]
    fn rejects_invalid_query_components(component: &str) {
        assert_eq!(decode_query_component(component), None);
    }
}
