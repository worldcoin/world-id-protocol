//! The message and deeplink formats that World ID authenticators use to talk to each other, as
//! defined in [WIP-105](https://github.com/worldcoin/world-id-protocol/blob/main/docs/WIPs/wip-105.md).
//!
//! Messages are [JSON-RPC 2.0](https://www.jsonrpc.org/specification) objects whose `method` is a
//! [`MethodName`], and deeplinks are `worldid://` URIs represented by [`Deeplink`]. The concrete
//! methods and deeplinks, together with their parameters, are defined by the WIPs that use them.
//!
//! Parsing is strict: unknown envelope members, a `jsonrpc` version other than `"2.0"`, and
//! responses carrying both or neither of `result` and `error` are rejected.

use std::{borrow::Cow, fmt, str::FromStr};

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// The URI scheme of World ID deeplinks.
pub const DEEPLINK_SCHEME: &str = "worldid";

const METHOD_PREFIX: &str = "worldid";

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

/// The `jsonrpc` member of every message. It only (de)serializes the literal `"2.0"`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
enum JsonRpcVersion {
    #[default]
    #[serde(rename = "2.0")]
    V2,
}

/// The `id` of a JSON-RPC request, echoed back in its response.
///
/// Requests without an `id` (notifications) and `null` ids are not supported.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Id {
    /// A numeric id.
    Number(i64),
    /// A string id.
    String(String),
}

impl From<String> for Id {
    fn from(id: String) -> Self {
        Self::String(id)
    }
}

impl From<i64> for Id {
    fn from(id: i64) -> Self {
        Self::Number(id)
    }
}

/// A JSON-RPC 2.0 request carrying `params` of type `P`.
///
/// # Examples
///
/// ```
/// use serde::{Deserialize, Serialize};
/// use world_id_primitives::authenticator_message::{MethodName, Request};
///
/// #[derive(Serialize, Deserialize)]
/// struct Ping {
///     nonce: String,
/// }
///
/// let request = Request::new(
///     "1".to_string().into(),
///     MethodName::from_static("worldid_ping_v1_ping"),
///     Ping { nonce: "abc".into() },
/// );
/// let json = serde_json::to_string(&request).unwrap();
/// assert_eq!(
///     json,
///     r#"{"jsonrpc":"2.0","id":"1","method":"worldid_ping_v1_ping","params":{"nonce":"abc"}}"#
/// );
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request<P> {
    jsonrpc: JsonRpcVersion,
    /// The request id, echoed back in the response.
    pub id: Id,
    /// The method being invoked.
    pub method: MethodName,
    /// The method parameters.
    pub params: P,
}

impl<P> Request<P> {
    /// Creates a request invoking `method` with `params`.
    pub const fn new(id: Id, method: MethodName, params: P) -> Self {
        Self {
            jsonrpc: JsonRpcVersion::V2,
            id,
            method,
            params,
        }
    }
}

/// A JSON-RPC 2.0 error object whose optional `data` member is of type `D`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, bound(deserialize = "D: Deserialize<'de>"))]
pub struct ErrorObject<D = serde_json::Value> {
    /// The error code.
    pub code: i64,
    /// A short, informational description of the error.
    pub message: String,
    /// Additional information about the error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<D>,
}

/// A JSON-RPC 2.0 response with either a result of type `R` or an [`ErrorObject`] with `data` of
/// type `D`.
///
/// On the wire a response carries exactly one of `result` and `error`. Deserialization rejects
/// responses with both or neither.
///
/// # Examples
///
/// ```
/// use world_id_primitives::authenticator_message::{ErrorObject, Response};
///
/// let json = r#"{"jsonrpc":"2.0","id":"1","error":{"code":1000,"message":"rejected"}}"#;
/// let response: Response<String> = serde_json::from_str(json).unwrap();
/// assert_eq!(response.outcome.unwrap_err().code, 1000);
///
/// let both = r#"{"jsonrpc":"2.0","id":"1","result":"ok","error":{"code":1,"message":"x"}}"#;
/// assert!(serde_json::from_str::<Response<String>>(both).is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response<R, D = serde_json::Value> {
    /// The id of the request this response answers.
    pub id: Id,
    /// The method result, or the error that prevented it.
    pub outcome: Result<R, ErrorObject<D>>,
}

#[derive(Serialize)]
struct WireResponseRef<'a, R, D> {
    jsonrpc: JsonRpcVersion,
    id: &'a Id,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<&'a R>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a ErrorObject<D>>,
}

#[derive(Deserialize)]
#[serde(
    deny_unknown_fields,
    bound(deserialize = "R: Deserialize<'de>, D: Deserialize<'de>")
)]
struct WireResponse<R, D> {
    #[serde(rename = "jsonrpc")]
    _jsonrpc: JsonRpcVersion,
    id: Id,
    #[serde(default, deserialize_with = "deserialize_present")]
    result: Option<R>,
    #[serde(default)]
    error: Option<ErrorObject<D>>,
}

/// Deserializes a member that is present on the wire, even if its value is `null`, as `Some`.
fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl<R: Serialize, D: Serialize> Serialize for Response<R, D> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        WireResponseRef {
            jsonrpc: JsonRpcVersion::V2,
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
            (Some(result), None) => Ok(result),
            (None, Some(error)) => Err(error),
            (Some(_), Some(_)) => {
                return Err(De::Error::custom(
                    "response must not contain both `result` and `error`",
                ));
            }
            (None, None) => {
                return Err(De::Error::custom(
                    "response must contain either `result` or `error`",
                ));
            }
        };
        Ok(Self {
            id: wire.id,
            outcome,
        })
    }
}

/// Characters that are percent-encoded in deeplink query values: everything except the RFC 3986
/// unreserved characters.
const QUERY_VALUE_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

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
    #[must_use]
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.push((key.into(), value.into()));
        self
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn method_names_follow_wip_105() {
        for valid in [
            "worldid",
            "worldid_auth_v1_register",
            "worldid_auth",
            "worldid_someMethod_v2",
        ] {
            assert!(valid.parse::<MethodName>().is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "worldidx_auth",
            "worldId_auth",
            "worldid_",
            "worldid__auth",
            "worldid_auth_",
            "worldid_Auth",
            "worldid_1auth",
            "worldid_au-th",
            "auth_worldid",
        ] {
            assert!(invalid.parse::<MethodName>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn method_name_deserialization_validates() {
        assert!(serde_json::from_value::<MethodName>(json!("worldid_auth_v1_register")).is_ok());
        assert!(serde_json::from_value::<MethodName>(json!("worldid_Auth")).is_err());
    }

    #[test]
    fn request_round_trips() {
        let json = json!({
            "jsonrpc": "2.0",
            "id": "abc",
            "method": "worldid_auth_v1_register",
            "params": {"name": "phone"},
        });
        let request: Request<serde_json::Value> = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(request.id, Id::String("abc".into()));
        assert_eq!(request.method.as_str(), "worldid_auth_v1_register");
        assert_eq!(serde_json::to_value(&request).unwrap(), json);
    }

    #[test]
    fn request_parsing_is_strict() {
        let base = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "worldid_auth_v1_register",
            "params": {},
        });
        assert!(serde_json::from_value::<Request<serde_json::Value>>(base.clone()).is_ok());

        let mutations: [(&str, serde_json::Value); 4] = [
            ("jsonrpc", json!("1.0")),
            ("method", json!("auth_register")),
            ("id", json!(null)),
            ("extra", json!(true)),
        ];
        for (key, value) in mutations {
            let mut request = base.clone();
            request[key] = value;
            assert!(
                serde_json::from_value::<Request<serde_json::Value>>(request).is_err(),
                "{key}"
            );
        }

        let mut missing_version = base;
        missing_version.as_object_mut().unwrap().remove("jsonrpc");
        assert!(serde_json::from_value::<Request<serde_json::Value>>(missing_version).is_err());
    }

    #[test]
    fn response_round_trips_result_and_error() {
        let success = json!({"jsonrpc": "2.0", "id": "x", "result": {"ok": true}});
        let response: Response<serde_json::Value> =
            serde_json::from_value(success.clone()).unwrap();
        assert_eq!(response.outcome, Ok(json!({"ok": true})));
        assert_eq!(serde_json::to_value(&response).unwrap(), success);

        let failure = json!({
            "jsonrpc": "2.0",
            "id": "x",
            "error": {"code": -32602, "message": "bad", "data": {"reason": "invalid_params"}},
        });
        let response: Response<serde_json::Value> =
            serde_json::from_value(failure.clone()).unwrap();
        let error = response.outcome.as_ref().unwrap_err();
        assert_eq!(error.code, -32602);
        assert_eq!(error.data, Some(json!({"reason": "invalid_params"})));
        assert_eq!(serde_json::to_value(&response).unwrap(), failure);
    }

    #[test]
    fn response_with_null_result_is_a_success() {
        let response: Response<()> =
            serde_json::from_value(json!({"jsonrpc": "2.0", "id": 1, "result": null})).unwrap();
        assert_eq!(response.outcome, Ok(()));
    }

    #[test]
    fn response_requires_exactly_one_outcome() {
        let neither = json!({"jsonrpc": "2.0", "id": 1});
        assert!(serde_json::from_value::<Response<serde_json::Value>>(neither).is_err());

        let both = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": 1,
            "error": {"code": 1, "message": "x"},
        });
        assert!(serde_json::from_value::<Response<serde_json::Value>>(both).is_err());

        let unknown = json!({"jsonrpc": "2.0", "id": 1, "result": 1, "extra": 1});
        assert!(serde_json::from_value::<Response<serde_json::Value>>(unknown).is_err());
    }

    #[test]
    fn deeplink_round_trips_with_encoded_params() {
        let link = Deeplink::new("auth", 1, "register")
            .unwrap()
            .with_param("s", "a b&c=d")
            .with_param("b", "bridge.example.org");
        let uri = link.to_string();
        assert_eq!(
            uri,
            "worldid://auth/v1/register?s=a%20b%26c%3Dd&b=bridge.example.org"
        );
        assert_eq!(uri.parse::<Deeplink>().unwrap(), link);
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

    #[test]
    fn deeplink_parsing_rejects_malformed_uris() {
        let cases = [
            ("https://auth/v1/register", DeeplinkError::InvalidScheme),
            ("worldid:auth/v1/register", DeeplinkError::InvalidScheme),
            (
                "worldid://user@auth/v1/register",
                DeeplinkError::InvalidNamespace,
            ),
            (
                "worldid://auth:443/v1/register",
                DeeplinkError::InvalidNamespace,
            ),
            ("worldid:///v1/register", DeeplinkError::InvalidNamespace),
            (
                "worldid://Auth/v1/register",
                DeeplinkError::InvalidNamespace,
            ),
            ("worldid://auth", DeeplinkError::InvalidVersion),
            ("worldid://auth/1/register", DeeplinkError::InvalidVersion),
            ("worldid://auth/v0/register", DeeplinkError::InvalidVersion),
            ("worldid://auth/v01/register", DeeplinkError::InvalidVersion),
            (
                "worldid://auth/v99999999999/register",
                DeeplinkError::InvalidVersion,
            ),
            ("worldid://auth/v1", DeeplinkError::InvalidAction),
            ("worldid://auth/v1/", DeeplinkError::InvalidAction),
            (
                "worldid://auth/v1/register/",
                DeeplinkError::UnexpectedPathSegments,
            ),
            (
                "worldid://auth/v1/register/x",
                DeeplinkError::UnexpectedPathSegments,
            ),
            (
                "worldid://auth/v1/register#x",
                DeeplinkError::UnexpectedFragment,
            ),
            (
                "worldid://auth/v1/register?",
                DeeplinkError::MalformedParameter,
            ),
            (
                "worldid://auth/v1/register?a",
                DeeplinkError::MalformedParameter,
            ),
            (
                "worldid://auth/v1/register?=a",
                DeeplinkError::MalformedParameter,
            ),
            (
                "worldid://auth/v1/register?a=1&&b=2",
                DeeplinkError::MalformedParameter,
            ),
            (
                "worldid://auth/v1/register?a=%zz",
                DeeplinkError::MalformedParameter,
            ),
            (
                "worldid://auth/v1/register?a=%4",
                DeeplinkError::MalformedParameter,
            ),
            (
                "worldid://auth/v1/register?a=%ff",
                DeeplinkError::MalformedParameter,
            ),
        ];
        for (uri, expected) in cases {
            assert_eq!(uri.parse::<Deeplink>(), Err(expected), "{uri}");
        }
    }

    #[test]
    fn deeplink_scheme_is_case_insensitive() {
        assert!("WorldID://auth/v1/register".parse::<Deeplink>().is_ok());
    }
}
