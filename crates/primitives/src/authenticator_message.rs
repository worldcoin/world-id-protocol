//! The message and deeplink formats that World ID authenticators use to talk to each other, as
//! defined in [WIP-105](https://github.com/worldcoin/world-id-protocol/blob/main/docs/WIPs/wip-105.md).
//!
//! Use [`Request::encode`]/[`Request::decode`] and [`Response::encode`]/[`Response::decode`]
//! for CBOR at transport boundaries. Decoding enforces message size, nesting and framing limits; typed requests and responses validate their own fields.
//! Deeplinks are `worldid://` URIs represented by [`Deeplink`].

use std::{borrow::Cow, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::serde_utils::deserialize_present;

mod cbor;
mod uri;
pub use cbor::MessageError;
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
#[serde(deny_unknown_fields, bound(deserialize = "P: Deserialize<'de>"))]
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
    /// Method-defined arguments, or `None` when no arguments were supplied.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub params: Option<P>,
}

impl<P> Request<P> {
    /// Creates a version 1 request; omit `id` for a notification and `params` for no arguments.
    #[must_use]
    pub const fn new(id: Option<Id>, method: MethodName, params: Option<P>) -> Self {
        Self {
            version: Version::V1,
            id,
            method,
            params,
        }
    }

    /// Encodes this message as CBOR. The transport must enforce its encoded size limit.
    ///
    /// # Errors
    ///
    /// Returns an error if a payload cannot be serialized.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError>
    where
        P: Serialize,
    {
        cbor::encode(self)
    }

    /// Decodes one message, rejecting input above `max_size`, nesting beyond 32 and trailing bytes.
    /// The payload types determine field validation and nullable values.
    ///
    /// # Errors
    ///
    /// Returns an error if a bound is exceeded or the message does not match its schema.
    pub fn decode(bytes: &[u8], max_size: usize) -> Result<Self, MessageError>
    where
        P: serde::de::DeserializeOwned,
    {
        cbor::decode(bytes, max_size)
    }
}

/// A response containing exactly one success or error outcome.
///
/// Callers must match responses by the outcome's ID and report invalid or unmatched responses
/// locally, without replying. A null error ID is uncorrelated and must never match a pending
/// request. Use [`Response::encode`] and [`Response::decode`] at the transport boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    bound(deserialize = "R: Deserialize<'de>, D: Deserialize<'de>")
)]
pub struct Response<R, D = Value> {
    /// The message format version.
    pub version: Version,
    /// The successful result or the error that prevented it.
    #[serde(deserialize_with = "deserialize_outcome")]
    pub outcome: Outcome<R, D>,
}

impl<R, D> Response<R, D> {
    /// Creates a version 1 response with exactly one outcome.
    #[must_use]
    pub const fn new(outcome: Outcome<R, D>) -> Self {
        Self {
            version: Version::V1,
            outcome,
        }
    }

    /// Encodes this message as CBOR. The transport must enforce its encoded size limit.
    ///
    /// # Errors
    ///
    /// Returns an error if a payload cannot be serialized.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError>
    where
        R: Serialize,
        D: Serialize,
    {
        cbor::encode(self)
    }

    /// Decodes one message, rejecting input above `max_size`, nesting beyond 32 and trailing bytes.
    /// The payload types determine field validation and nullable values.
    ///
    /// # Errors
    ///
    /// Returns an error if a bound is exceeded or the message does not match its schema.
    pub fn decode(bytes: &[u8], max_size: usize) -> Result<Self, MessageError>
    where
        R: serde::de::DeserializeOwned,
        D: serde::de::DeserializeOwned,
    {
        cbor::decode(bytes, max_size)
    }
}

/// The mutually exclusive outcomes of a method invocation.
///
/// On the wire this is a single-entry map keyed by `success` or `error`.
/// Successful responses always have a request ID; only errors can be uncorrelated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "snake_case",
    deny_unknown_fields,
    bound(deserialize = "R: Deserialize<'de>, D: Deserialize<'de>")
)]
pub enum Outcome<R, D = Value> {
    /// A successful invocation with a required result, including when that result is null.
    Success {
        /// The ID of the request that succeeded.
        id: Id,
        /// The method-defined result.
        // Keep the field required even when R is nullable; serde otherwise defaults it.
        #[serde(deserialize_with = "Deserialize::deserialize")]
        result: R,
    },
    /// A failed invocation, optionally correlated with a request.
    Error {
        /// The request ID, or null when the failure cannot be correlated.
        // Keep the field required even though Option would otherwise default it to None.
        #[serde(deserialize_with = "Deserialize::deserialize")]
        id: Option<Id>,
        /// The method failure.
        error: ErrorObject<D>,
    },
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

impl<D> ErrorObject<D> {
    /// Creates a method failure, preserving present null data when `D` accepts null.
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>, data: Option<D>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            data,
        }
    }
}

/// The envelope version defined by WIP-105.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Version {
    /// WIP-105 version 1.0.
    #[default]
    #[serde(rename = "1.0")]
    V1,
}

/// A text request ID; null is never a request ID.
pub type Id = String;

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
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
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
                uri::encode_query_component(key),
                uri::encode_query_component(value)
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
                .collect::<Option<_>>()
                .ok_or(DeeplinkError::MalformedParameter)?;
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

/// Dispatches [`Outcome`] through a single-entry map so Ciborium cannot read a bare discriminator's
/// body from another CBOR item. Serde's map dispatcher also requires struct-variant map bodies.
fn deserialize_outcome<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct OutcomeVisitor<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for OutcomeVisitor<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a single-entry outcome map")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<T, A::Error> {
            let outcome = T::deserialize(serde::de::value::MapAccessDeserializer::new(&mut map))?;
            if map.next_key::<serde::de::IgnoredAny>()?.is_some() {
                return Err(A::Error::custom("outcome must be a map with one entry"));
            }
            Ok(outcome)
        }
    }

    deserializer.deserialize_map(OutcomeVisitor(std::marker::PhantomData))
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

/// Parses a `key=value` query parameter with a nonempty key.
fn parse_param(pair: &str) -> Option<(String, String)> {
    let (key, value) = pair.split_once('=').filter(|(key, _)| !key.is_empty())?;
    Some((
        uri::decode_query_component(key)?,
        uri::decode_query_component(value)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case("worldid"; "prefix")]
    #[test_case("worldid_someMethod_v2"; "camel_case")]
    fn accepts_valid_method_names(valid: &str) {
        assert!(valid.parse::<MethodName>().is_ok(), "{valid}");
    }

    #[test_case(""; "empty")]
    #[test_case("worldidx_auth"; "wrong_prefix")]
    #[test_case("worldId_auth"; "uppercase_prefix")]
    #[test_case("worldid__auth"; "empty_segment")]
    #[test_case("worldid_auth_"; "trailing_separator")]
    #[test_case("worldid_Auth"; "uppercase_segment")]
    #[test_case("worldid_1auth"; "numeric_segment")]
    #[test_case("worldid_au-th"; "hyphen")]
    fn rejects_invalid_method_names(invalid: &str) {
        assert!(invalid.parse::<MethodName>().is_err(), "{invalid}");
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
    #[test_case("worldid://auth/v1/register?a<b=1",
                DeeplinkError::MalformedParameter; "raw_delimiter_in_key")]
    fn deeplink_parsing_rejects_malformed_uris(uri: &str, expected: DeeplinkError) {
        assert_eq!(uri.parse::<Deeplink>(), Err(expected), "{uri}");
    }

    #[test]
    fn deeplink_scheme_is_case_insensitive() {
        assert!("WorldID://auth/v1/register".parse::<Deeplink>().is_ok());
    }
}
