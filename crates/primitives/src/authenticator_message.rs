//! The message and deeplink formats that World ID authenticators use to talk to each other, as
//! defined in [WIP-105](https://github.com/worldcoin/world-id-protocol/blob/main/docs/WIPs/wip-105.md).
//!
//! Use [`encode`] and [`decode`] for CBOR at transport boundaries. Decoding checks encoding
//! rules and resource limits; typed requests and responses validate their own fields.
//! Deeplinks are `worldid://` URIs represented by [`Deeplink`].

use std::{borrow::Cow, fmt, str::FromStr};

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

pub mod cbor;
pub use cbor::{MessageError, decode, encode};
pub use ciborium::Value;

/// The URI scheme of World ID deeplinks.
pub const DEEPLINK_SCHEME: &str = "worldid";

const METHOD_PREFIX: &str = "worldid";

/// A method invocation, with an ID when a response is expected.
///
/// An absent ID represents a notification. Receivers must never reply to notifications, even
/// when the method is unknown or execution fails. Session owners must prevent concurrent ID
/// reuse. Callers are responsible for choosing a parameter type that enforces the method schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(deserialize = "P: Deserialize<'de>"))]
pub struct Request<P> {
    /// The message format version.
    pub version: Version,
    /// The request ID, echoed back in the response, or `None` for a notification.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub id: Option<Id>,
    /// The method being invoked.
    pub method: MethodName,
    /// Arguments, or `None` when no arguments were supplied.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub params: Option<P>,
}

impl<P> Request<P> {
    /// Creates a request invoking `method` with `params`.
    pub const fn new(id: Option<Id>, method: MethodName, params: P) -> Self {
        Self {
            version: Version::V1,
            id,
            method,
            params: Some(params),
        }
    }

    /// Creates a request without an arguments field.
    pub const fn without_params(id: Option<Id>, method: MethodName) -> Self {
        Self {
            version: Version::V1,
            id,
            method,
            params: None,
        }
    }
}

/// A response containing exactly one result or error.
///
/// A null ID (`None`) is reserved for uncorrelated errors and must never match a pending request.
/// Callers must match other responses by ID and report invalid or unmatched responses locally,
/// without replying. Use [`encode`] and [`decode`] at the transport boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response<R, D = Value> {
    /// The message format version.
    pub version: Version,
    /// The request ID, or `None` for an uncorrelated error.
    pub id: Option<Id>,
    /// The method result, or the error that prevented it.
    pub outcome: Result<R, ErrorObject<D>>,
}

/// A method failure. Callers identify errors by their case-sensitive code, not message text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(deserialize = "D: Deserialize<'de>"))]
pub struct ErrorObject<D = Value> {
    /// A shared WIP-105 or method-specific failure code.
    pub code: String,
    /// A short human-readable explanation.
    pub message: String,
    /// Optional method-specific details; a present null value is preserved.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub data: Option<D>,
}

/// The envelope version defined by WIP-105.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Version {
    /// WIP-105 version 1.0.
    #[default]
    #[serde(rename = "1.0")]
    V1,
}

/// A request ID. Integer and text IDs are distinct; null is never a request ID.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Id {
    /// A CBOR integer, in the range -2^64 through 2^64 - 1.
    Number(i128),
    /// A text ID.
    String(String),
}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Number(number) => {
                let integer = ciborium::value::Integer::try_from(*number)
                    .map_err(serde::ser::Error::custom)?;
                Value::Integer(integer).serialize(serializer)
            }
            Self::String(text) => serializer.serialize_str(text),
        }
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Value::deserialize(deserializer)? {
            Value::Integer(number) => Ok(Self::Number(number.into())),
            Value::Text(text) => Ok(Self::String(text)),
            _ => Err(D::Error::custom("request ID must be text or integer")),
        }
    }
}

impl From<String> for Id {
    fn from(id: String) -> Self {
        Self::String(id)
    }
}

impl From<i64> for Id {
    fn from(id: i64) -> Self {
        Self::Number(id.into())
    }
}

/// The name of a WIP-105 method, e.g. `worldid_auth_v1_register`.
///
/// A method name consists of `camelCase` segments joined by underscores, and the first segment is
/// always `worldid`. Each segment starts with a lowercase ASCII letter followed by ASCII letters
/// and digits.
///
/// # Examples
///
/// ```
/// use world_id_primitives::authenticator_message::MethodName;
///
/// const REGISTER: MethodName = MethodName::from_static("worldid_auth_v1_register");
///
/// assert_eq!(REGISTER.as_str(), "worldid_auth_v1_register");
/// assert!("worldid_Auth".parse::<MethodName>().is_err());
/// assert!("other_auth_v1_register".parse::<MethodName>().is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MethodName(Cow<'static, str>);

impl MethodName {
    /// Creates a method name from a string literal, validating it at compile time when used in a
    /// `const` context.
    ///
    /// # Panics
    ///
    /// Panics if `name` is not a valid method name.
    #[must_use]
    pub const fn from_static(name: &'static str) -> Self {
        assert!(is_valid_method_name(name), "invalid WIP-105 method name");
        Self(Cow::Borrowed(name))
    }

    /// Returns the method name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for MethodName {
    type Err = InvalidMethodName;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if !is_valid_method_name(name) {
            return Err(InvalidMethodName);
        }
        Ok(Self(Cow::Owned(name.to_owned())))
    }
}

impl fmt::Display for MethodName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for MethodName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for MethodName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        if !is_valid_method_name(&name) {
            return Err(D::Error::custom(InvalidMethodName));
        }
        Ok(Self(Cow::Owned(name)))
    }
}

/// The error returned when a string is not a valid [`MethodName`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("method name must be camelCase segments joined by `_`, starting with `worldid`")]
pub struct InvalidMethodName;

/// A WIP-105 deeplink of the form `worldid://{namespace}/v{version}/{action}?{parameters}`.
///
/// `namespace` and `action` are `camelCase` identifiers and `version` is a positive integer.
/// Parameters are kept in order, with their keys and values percent-decoded exactly once.
/// Parsing rejects URIs with any other scheme or structure, including user info, a port, a
/// fragment, extra path segments and parameters without a `=`. The WIP that defines a deeplink
/// decides which parameters it accepts.
///
/// # Examples
///
/// ```
/// use world_id_primitives::authenticator_message::Deeplink;
///
/// let link: Deeplink = "worldid://auth/v1/register?b=bridge.example.org".parse().unwrap();
/// assert_eq!(link.namespace(), "auth");
/// assert_eq!(link.version(), 1);
/// assert_eq!(link.action(), "register");
/// assert_eq!(link.params(), [("b".to_string(), "bridge.example.org".to_string())]);
/// assert_eq!(link.to_string(), "worldid://auth/v1/register?b=bridge.example.org");
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deeplink {
    namespace: String,
    version: u32,
    action: String,
    params: Vec<(String, String)>,
}

impl Deeplink {
    /// Creates a deeplink without parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if `namespace` or `action` is not a `camelCase` identifier, or if
    /// `version` is zero.
    pub fn new(
        namespace: impl Into<String>,
        version: u32,
        action: impl Into<String>,
    ) -> Result<Self, DeeplinkError> {
        let namespace = namespace.into();
        let action = action.into();
        if !is_camel_case_segment(&namespace) {
            return Err(DeeplinkError::InvalidNamespace);
        }
        if version == 0 {
            return Err(DeeplinkError::InvalidVersion);
        }
        if !is_camel_case_segment(&action) {
            return Err(DeeplinkError::InvalidAction);
        }
        Ok(Self {
            namespace,
            version,
            action,
            params: Vec::new(),
        })
    }

    /// Appends a parameter. Its key and value are percent-encoded when the link is formatted.
    ///
    /// # Errors
    ///
    /// Returns an error if `key` is empty. Empty values and repeated keys are allowed.
    pub fn with_param(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, DeeplinkError> {
        let key = key.into();
        if key.is_empty() {
            return Err(DeeplinkError::MalformedParameter);
        }
        self.params.push((key, value.into()));
        Ok(self)
    }

    /// The protocol area of the deeplink, e.g. `auth`.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The version of the deeplink, e.g. `1` for `v1`.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// The operation the deeplink starts, e.g. `register`.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    /// The decoded parameters, in the order they appear in the URI. Keys may repeat.
    #[must_use]
    pub fn params(&self) -> &[(String, String)] {
        &self.params
    }
}

impl fmt::Display for Deeplink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{DEEPLINK_SCHEME}://{}/v{}/{}",
            self.namespace, self.version, self.action
        )?;
        for (i, (key, value)) in self.params.iter().enumerate() {
            let separator = if i == 0 { '?' } else { '&' };
            write!(
                f,
                "{separator}{}={}",
                utf8_percent_encode(key, QUERY_VALUE_ENCODE_SET),
                utf8_percent_encode(value, QUERY_VALUE_ENCODE_SET)
            )?;
        }
        Ok(())
    }
}

impl FromStr for Deeplink {
    type Err = DeeplinkError;

    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        let rest = uri
            .split_once("://")
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case(DEEPLINK_SCHEME))
            .map(|(_, rest)| rest)
            .ok_or(DeeplinkError::InvalidScheme)?;
        if rest.contains('#') {
            return Err(DeeplinkError::UnexpectedFragment);
        }
        let (path, query) = match rest.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (rest, None),
        };

        let mut segments = path.split('/');
        let namespace = segments.next().unwrap_or_default();
        let version = segments
            .next()
            .ok_or(DeeplinkError::InvalidVersion)
            .and_then(parse_version)?;
        let action = segments.next().ok_or(DeeplinkError::InvalidAction)?;
        if segments.next().is_some() {
            return Err(DeeplinkError::UnexpectedPathSegments);
        }

        let mut link = Self::new(namespace, version, action)?;
        if let Some(query) = query {
            link.params = query
                .split('&')
                .map(parse_param)
                .collect::<Result<_, _>>()?;
        }
        Ok(link)
    }
}

/// The error returned when a string is not a valid [`Deeplink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeeplinkError {
    /// The URI does not use the `worldid` scheme.
    #[error("deeplink must use the `worldid` scheme")]
    InvalidScheme,
    /// The namespace is not a `camelCase` identifier, or the URI has user info or a port.
    #[error("deeplink namespace must be a camelCase identifier")]
    InvalidNamespace,
    /// The version segment is not `v` followed by a positive integer.
    #[error("deeplink version must be `v` followed by a positive integer")]
    InvalidVersion,
    /// The action is missing or is not a `camelCase` identifier.
    #[error("deeplink action must be a camelCase identifier")]
    InvalidAction,
    /// The path has more than the namespace, version and action segments.
    #[error("deeplink path must be `/{{version}}/{{action}}`")]
    UnexpectedPathSegments,
    /// The URI has a fragment.
    #[error("deeplink must not have a fragment")]
    UnexpectedFragment,
    /// A parameter is not `key=value`, has an empty key, or is not valid percent-encoded UTF-8.
    #[error("deeplink parameters must be percent-encoded `key=value` pairs")]
    MalformedParameter,
}

#[derive(Serialize)]
struct WireResponseRef<'a, R, D> {
    version: Version,
    id: &'a Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<&'a R>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a ErrorObject<D>>,
}

#[derive(Deserialize)]
#[serde(bound(deserialize = "R: Deserialize<'de>, D: Deserialize<'de>"))]
struct WireResponse<R, D> {
    version: Version,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    id: Option<Id>,
    #[serde(default, deserialize_with = "deserialize_present")]
    result: Option<R>,
    #[serde(default, deserialize_with = "deserialize_present")]
    error: Option<ErrorObject<D>>,
}

impl<R: Serialize, D: Serialize> Serialize for Response<R, D> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.id.is_none() && self.outcome.is_ok() {
            return Err(serde::ser::Error::custom(
                "successful response requires a non-null ID",
            ));
        }
        WireResponseRef {
            version: self.version,
            id: &self.id,
            result: self.outcome.as_ref().ok(),
            error: self.outcome.as_ref().err(),
        }
        .serialize(serializer)
    }
}

impl<'de, R: Deserialize<'de>, D: Deserialize<'de>> Deserialize<'de> for Response<R, D> {
    fn deserialize<De: Deserializer<'de>>(deserializer: De) -> Result<Self, De::Error> {
        let wire = WireResponse::<R, D>::deserialize(deserializer)?;
        let outcome = match (wire.result, wire.error) {
            (Some(result), None) if wire.id.is_some() => Ok(result),
            (None, Some(error)) => Err(error),
            _ => {
                return Err(De::Error::custom(
                    "response requires exactly one outcome and successes require a non-null ID",
                ));
            }
        };
        Ok(Self {
            version: wire.version,
            id: wire.id,
            outcome,
        })
    }
}

/// Preserves the distinction between an absent field and a present value, including null.
/// With `serde(default)`, absence becomes `None`; a present value is parsed as `T` and wrapped in
/// `Some`. This preserves nullable results and error data, while rejecting a null request ID
/// because `Id` itself does not accept null. Deserializing `Option<T>` would treat both as absent.
fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

const fn is_valid_method_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let prefix = METHOD_PREFIX.as_bytes();
    if bytes.len() < prefix.len() {
        return false;
    }
    let mut i = 0;
    while i < prefix.len() {
        if bytes[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    while i < bytes.len() {
        if bytes[i] != b'_' {
            return false;
        }
        i += 1;
        if i >= bytes.len() || !bytes[i].is_ascii_lowercase() {
            return false;
        }
        i += 1;
        while i < bytes.len() && bytes[i] != b'_' {
            if !bytes[i].is_ascii_alphanumeric() {
                return false;
            }
            i += 1;
        }
    }
    true
}

/// Returns whether `segment` is a `camelCase` identifier: a lowercase ASCII letter followed by
/// ASCII letters and digits.
fn is_camel_case_segment(segment: &str) -> bool {
    let mut chars = segment.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase()) && chars.all(|c| c.is_ascii_alphanumeric())
}

/// Characters that are percent-encoded in deeplink query values: everything except the RFC 3986
/// unreserved characters.
const QUERY_VALUE_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Parses a version segment of the form `v{n}`, where `n` is a positive integer without leading
/// zeros.
fn parse_version(segment: &str) -> Result<u32, DeeplinkError> {
    let digits = segment
        .strip_prefix('v')
        .filter(|digits| !digits.is_empty() && !digits.starts_with('0'))
        .filter(|digits| digits.bytes().all(|b| b.is_ascii_digit()))
        .ok_or(DeeplinkError::InvalidVersion)?;
    digits.parse().map_err(|_| DeeplinkError::InvalidVersion)
}

fn parse_param(pair: &str) -> Result<(String, String), DeeplinkError> {
    let (key, value) = pair
        .split_once('=')
        .ok_or(DeeplinkError::MalformedParameter)?;
    if key.is_empty() {
        return Err(DeeplinkError::MalformedParameter);
    }
    Ok((percent_decode(key)?, percent_decode(value)?))
}

fn percent_decode(component: &str) -> Result<String, DeeplinkError> {
    if !is_well_formed_percent_encoding(component) {
        return Err(DeeplinkError::MalformedParameter);
    }
    percent_decode_str(component)
        .decode_utf8()
        .map(Cow::into_owned)
        .map_err(|_| DeeplinkError::MalformedParameter)
}

/// Returns whether every `%` in `component` starts a `%XX` escape with two hex digits.
fn is_well_formed_percent_encoding(component: &str) -> bool {
    let bytes = component.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let escape = bytes.get(i + 1..i + 3);
            if !escape.is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit)) {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use test_case::test_case;

    #[test_case("worldid"; "prefix")]
    #[test_case("worldid_auth_v1_register"; "registration")]
    #[test_case("worldid_auth"; "namespace")]
    #[test_case("worldid_someMethod_v2"; "camel_case")]
    fn accepts_valid_method_names(valid: &str) {
        assert!(valid.parse::<MethodName>().is_ok(), "{valid}");
    }

    #[test_case(""; "empty")]
    #[test_case("worldidx_auth"; "wrong_prefix")]
    #[test_case("worldId_auth"; "uppercase_prefix")]
    #[test_case("worldid_"; "empty_suffix")]
    #[test_case("worldid__auth"; "empty_segment")]
    #[test_case("worldid_auth_"; "trailing_separator")]
    #[test_case("worldid_Auth"; "uppercase_segment")]
    #[test_case("worldid_1auth"; "numeric_segment")]
    #[test_case("worldid_au-th"; "hyphen")]
    #[test_case("auth_worldid"; "reversed_prefix")]
    fn rejects_invalid_method_names(invalid: &str) {
        assert!(invalid.parse::<MethodName>().is_err(), "{invalid}");
    }

    #[test]
    fn method_name_deserialization_validates() {
        assert!(serde_json::from_value::<MethodName>(json!("worldid_auth_v1_register")).is_ok());
        assert!(serde_json::from_value::<MethodName>(json!("worldid_Auth")).is_err());
    }

    #[test]
    fn deeplink_round_trips_with_encoded_params() {
        let link = Deeplink::new("auth", 1, "register")
            .unwrap()
            .with_param("s", "a b&c=d")
            .unwrap()
            .with_param("b", "bridge.example.org")
            .unwrap();
        let uri = link.to_string();
        assert_eq!(
            uri,
            "worldid://auth/v1/register?s=a%20b%26c%3Dd&b=bridge.example.org"
        );
        assert_eq!(uri.parse::<Deeplink>().unwrap(), link);
    }

    #[test]
    fn deeplink_builder_requires_nonempty_keys_but_allows_empty_values() {
        let link = Deeplink::new("auth", 1, "register").unwrap();
        assert_eq!(
            link.clone().with_param("", "value"),
            Err(DeeplinkError::MalformedParameter)
        );
        let link = link.with_param("a&b", "").unwrap();
        assert_eq!(link.to_string().parse::<Deeplink>().unwrap(), link);
    }

    #[test]
    fn deeplink_decodes_params_exactly_once() {
        let link: Deeplink = "worldid://auth/v1/register?s=%2541".parse().unwrap();
        assert_eq!(link.params(), [("s".to_string(), "%41".to_string())]);
    }

    #[test]
    fn deeplink_keeps_duplicate_and_empty_params() {
        let link: Deeplink = "worldid://auth/v12/register?a=1&a=&b=2".parse().unwrap();
        assert_eq!(link.version(), 12);
        assert_eq!(
            link.params(),
            [
                ("a".to_string(), "1".to_string()),
                ("a".to_string(), String::new()),
                ("b".to_string(), "2".to_string()),
            ]
        );
    }

    #[test_case("https://auth/v1/register", DeeplinkError::InvalidScheme; "https")]
    #[test_case("worldid:auth/v1/register", DeeplinkError::InvalidScheme; "missing_slashes")]
    #[test_case("worldid://user@auth/v1/register",
                DeeplinkError::InvalidNamespace; "user_info")]
    #[test_case("worldid://auth:443/v1/register",
                DeeplinkError::InvalidNamespace; "port")]
    #[test_case("worldid:///v1/register", DeeplinkError::InvalidNamespace; "empty_namespace")]
    #[test_case("worldid://Auth/v1/register",
                DeeplinkError::InvalidNamespace; "uppercase_namespace")]
    #[test_case("worldid://auth", DeeplinkError::InvalidVersion; "missing_version")]
    #[test_case("worldid://auth/1/register", DeeplinkError::InvalidVersion; "missing_version_prefix")]
    #[test_case("worldid://auth/v0/register", DeeplinkError::InvalidVersion; "zero_version")]
    #[test_case("worldid://auth/v01/register", DeeplinkError::InvalidVersion; "leading_zero_version")]
    #[test_case("worldid://auth/v99999999999/register",
                DeeplinkError::InvalidVersion; "version_overflow")]
    #[test_case("worldid://auth/v1", DeeplinkError::InvalidAction; "missing_action")]
    #[test_case("worldid://auth/v1/", DeeplinkError::InvalidAction; "empty_action")]
    #[test_case("worldid://auth/v1/register/",
                DeeplinkError::UnexpectedPathSegments; "trailing_slash")]
    #[test_case("worldid://auth/v1/register/x",
                DeeplinkError::UnexpectedPathSegments; "extra_path")]
    #[test_case("worldid://auth/v1/register#x",
                DeeplinkError::UnexpectedFragment; "fragment")]
    #[test_case("worldid://auth/v1/register?",
                DeeplinkError::MalformedParameter; "empty_query")]
    #[test_case("worldid://auth/v1/register?a",
                DeeplinkError::MalformedParameter; "missing_equals")]
    #[test_case("worldid://auth/v1/register?=a",
                DeeplinkError::MalformedParameter; "empty_key")]
    #[test_case("worldid://auth/v1/register?a=1&&b=2",
                DeeplinkError::MalformedParameter; "empty_parameter")]
    #[test_case("worldid://auth/v1/register?a=%zz",
                DeeplinkError::MalformedParameter; "invalid_hex_escape")]
    #[test_case("worldid://auth/v1/register?a=%4",
                DeeplinkError::MalformedParameter; "short_escape")]
    #[test_case("worldid://auth/v1/register?a=%ff",
                DeeplinkError::MalformedParameter; "invalid_utf8")]
    fn deeplink_parsing_rejects_malformed_uris(uri: &str, expected: DeeplinkError) {
        assert_eq!(uri.parse::<Deeplink>(), Err(expected), "{uri}");
    }

    #[test]
    fn deeplink_scheme_is_case_insensitive() {
        assert!("WorldID://auth/v1/register".parse::<Deeplink>().is_ok());
    }
}
