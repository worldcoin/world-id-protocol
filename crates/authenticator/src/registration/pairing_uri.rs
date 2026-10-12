//! The Pairing URI that hands a registration session to the Approving Authenticator (WIP-109
//! §3.4).

use std::{fmt, str::FromStr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use world_id_primitives::authenticator_message::{Deeplink, DeeplinkError};

use super::{request::RegistrationDigest, session::PairingSecret};

const NAMESPACE: &str = "auth";
const VERSION: u32 = 1;
const ACTION: &str = "register";

const SECRET_PARAM: &str = "s";
const DIGEST_PARAM: &str = "d";
const BRIDGE_PARAM: &str = "b";

/// The length of a 32-byte value encoded as unpadded base64url.
const ENCODED_32_BYTES_LEN: usize = 43;

/// The domain of a bridge deployment, e.g. `bridge.example.org`.
///
/// It is a DNS name only: no scheme, port, path, user info, query or fragment. Letters are
/// normalized to lowercase, and the final label must start with an ASCII letter so URL parsers
/// cannot interpret it as an IP address. The bridge is always reached over `https`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BridgeDomain(String);

impl BridgeDomain {
    /// Returns the domain as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for BridgeDomain {
    type Err = PairingUriError;

    fn from_str(domain: &str) -> Result<Self, Self::Err> {
        let is_valid_label = |label: &str| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        };
        if domain.len() > 253 || !domain.split('.').all(is_valid_label) {
            return Err(PairingUriError::InvalidBridge);
        }
        let final_label = domain
            .rsplit('.')
            .next()
            .ok_or(PairingUriError::InvalidBridge)?;
        if !final_label.starts_with(|c: char| c.is_ascii_alphabetic()) {
            return Err(PairingUriError::InvalidBridge);
        }
        Ok(Self(domain.to_ascii_lowercase()))
    }
}

impl fmt::Display for BridgeDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The `worldid://auth/v1/register` deeplink, shown as a QR code by the Requesting Authenticator.
///
/// It carries the [`PairingSecret`], the [`RegistrationDigest`] and the bridge the Requesting
/// Authenticator uses. Anyone who holds it can retrieve and consume the encrypted
/// registration request; reading its plaintext also requires the independently transferred
/// pairing code. The URI must not be logged or sent to analytics. Its `Debug` output redacts the
/// secret.
///
/// Parsing is strict: it rejects any other deeplink, unknown, missing or duplicated parameters,
/// and values that are not canonical unpadded base64url of 32 bytes.
///
/// # Examples
///
/// ```
/// use world_id_authenticator::registration::{
///     BridgeDomain, PairingSecret, PairingUri, RegistrationDigest,
/// };
///
/// let uri = PairingUri {
///     secret: PairingSecret::from_bytes([1; 32]),
///     digest: RegistrationDigest::from_bytes([2; 32]),
///     bridge: "bridge.example.org".parse::<BridgeDomain>().unwrap(),
/// };
/// let link = uri.to_string();
/// assert!(link.starts_with("worldid://auth/v1/register?s="));
/// assert_eq!(link.parse::<PairingUri>().unwrap(), uri);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingUri {
    /// The session secret used to derive the request ID and code-bound transport key.
    pub secret: PairingSecret,
    /// The commitment to the registration parameters.
    pub digest: RegistrationDigest,
    /// The bridge the Requesting Authenticator uses. The Approving Authenticator must use this
    /// bridge and no other.
    pub bridge: BridgeDomain,
}

impl fmt::Display for PairingUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let link = Deeplink::new(NAMESPACE, VERSION, ACTION)
            .expect("the registration deeplink is valid")
            .with_param(SECRET_PARAM, URL_SAFE_NO_PAD.encode(self.secret.as_bytes()))
            .expect("the secret parameter key is nonempty")
            .with_param(DIGEST_PARAM, URL_SAFE_NO_PAD.encode(self.digest.as_bytes()))
            .expect("the digest parameter key is nonempty")
            .with_param(BRIDGE_PARAM, self.bridge.as_str())
            .expect("the bridge parameter key is nonempty");
        write!(f, "{link}")
    }
}

impl FromStr for PairingUri {
    type Err = PairingUriError;

    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        let link: Deeplink = uri.parse()?;
        if link.namespace() != NAMESPACE || link.version() != VERSION || link.action() != ACTION {
            return Err(PairingUriError::NotARegistrationLink);
        }

        let mut secret = None;
        let mut digest = None;
        let mut bridge = None;
        for (key, value) in link.params() {
            match key.as_str() {
                SECRET_PARAM => set_once(&mut secret, decode_32_bytes(value)?)?,
                DIGEST_PARAM => set_once(&mut digest, decode_32_bytes(value)?)?,
                BRIDGE_PARAM => set_once(&mut bridge, value.parse()?)?,
                _ => return Err(PairingUriError::UnknownParameter),
            }
        }

        Ok(Self {
            secret: PairingSecret::from_bytes(secret.ok_or(PairingUriError::MissingParameter)?),
            digest: RegistrationDigest::from_bytes(
                digest.ok_or(PairingUriError::MissingParameter)?,
            ),
            bridge: bridge.ok_or(PairingUriError::MissingParameter)?,
        })
    }
}

/// The error returned when a string is not a valid [`PairingUri`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PairingUriError {
    /// The URI is not a well-formed WIP-105 deeplink.
    #[error(transparent)]
    Deeplink(#[from] DeeplinkError),
    /// The deeplink is not `worldid://auth/v1/register`.
    #[error("not an authenticator registration link")]
    NotARegistrationLink,
    /// A parameter other than `s`, `d` and `b` is present.
    #[error("unknown pairing parameter")]
    UnknownParameter,
    /// A parameter appears more than once.
    #[error("duplicated pairing parameter")]
    DuplicateParameter,
    /// The `s`, `d` or `b` parameter is missing.
    #[error("missing pairing parameter")]
    MissingParameter,
    /// `s` or `d` is not 32 bytes of canonical unpadded base64url.
    #[error("pairing secret and digest must be 32 bytes of unpadded base64url")]
    InvalidEncoding,
    /// `b` is not a bare DNS domain.
    #[error("bridge must be a bare domain name")]
    InvalidBridge,
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), PairingUriError> {
    if slot.replace(value).is_some() {
        return Err(PairingUriError::DuplicateParameter);
    }
    Ok(())
}

fn decode_32_bytes(value: &str) -> Result<[u8; 32], PairingUriError> {
    if value.len() != ENCODED_32_BYTES_LEN {
        return Err(PairingUriError::InvalidEncoding);
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| PairingUriError::InvalidEncoding)?
        .try_into()
        .map_err(|_| PairingUriError::InvalidEncoding)
}

#[cfg(test)]
mod tests {
    use test_case::test_case;

    use super::*;

    fn uri() -> PairingUri {
        PairingUri {
            secret: PairingSecret::from_bytes([0xff; 32]),
            digest: RegistrationDigest::from_bytes([0x00; 32]),
            bridge: "bridge.example.org".parse().unwrap(),
        }
    }

    /// The valid `s` parameter of [`uri`].
    fn secret_param() -> String {
        "_".repeat(42) + "8"
    }

    /// The valid `d` parameter of [`uri`].
    fn digest_param() -> String {
        "A".repeat(43)
    }

    /// The link of [`uri`] without its `b` parameter.
    fn link_without_bridge() -> String {
        format!(
            "worldid://auth/v1/register?s={}&d={}",
            secret_param(),
            digest_param()
        )
    }

    #[test]
    fn round_trips() {
        let link = uri().to_string();
        assert_eq!(link.parse::<PairingUri>().unwrap(), uri(), "{link}");
    }

    #[test]
    fn uses_unpadded_base64url() {
        assert_eq!(
            uri().to_string(),
            format!("{}&b=bridge.example.org", link_without_bridge())
        );
    }

    #[test]
    fn accepts_parameters_in_any_order_and_percent_encoded() {
        let link = uri().to_string();
        let (base, query) = link.split_once('?').unwrap();
        let mut params: Vec<&str> = query.split('&').collect();
        params.reverse();
        let reordered = format!("{base}?{}", params.join("&")).replace("bridge.", "bridge%2E");
        assert_eq!(reordered.parse::<PairingUri>().unwrap(), uri());
    }

    #[test]
    fn debug_redacts_the_secret() {
        let debug = format!("{:?}", uri());
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("255"));
    }

    #[test_case(uri().to_string().replace("auth/v1/register", "auth/v2/register"),
                PairingUriError::NotARegistrationLink; "other version")]
    #[test_case(uri().to_string().replace("auth/v1/register", "pay/v1/register"),
                PairingUriError::NotARegistrationLink; "other namespace")]
    #[test_case(uri().to_string().replace("worldid://", "https://"),
                PairingUriError::Deeplink(DeeplinkError::InvalidScheme); "other scheme")]
    #[test_case(format!("{}#frag", uri()),
                PairingUriError::Deeplink(DeeplinkError::UnexpectedFragment); "fragment")]
    #[test_case(format!("{}&x=1", uri()), PairingUriError::UnknownParameter; "unknown parameter")]
    #[test_case(format!("{}&s={}", uri(), secret_param()),
                PairingUriError::DuplicateParameter; "duplicated secret")]
    #[test_case(format!("{}&b=bridge.example.org", uri()),
                PairingUriError::DuplicateParameter; "duplicated bridge")]
    #[test_case(format!("worldid://auth/v1/register?s={}&b=bridge.example.org", secret_param()),
                PairingUriError::MissingParameter; "missing digest")]
    #[test_case(format!("worldid://auth/v1/register?d={}&b=bridge.example.org", digest_param()),
                PairingUriError::MissingParameter; "missing secret")]
    #[test_case(link_without_bridge(), PairingUriError::MissingParameter; "missing bridge")]
    #[test_case(format!("worldid://auth/v1/register?s={}=&d={}", secret_param(), digest_param()),
                PairingUriError::InvalidEncoding; "padded secret")]
    #[test_case(format!("worldid://auth/v1/register?s={}&d={}", &secret_param()[1..], digest_param()),
                PairingUriError::InvalidEncoding; "short secret")]
    #[test_case(format!("worldid://auth/v1/register?s={}+w&d={}", &secret_param()[..41], digest_param()),
                PairingUriError::InvalidEncoding; "standard base64 secret")]
    #[test_case(format!("worldid://auth/v1/register?s={}x&d={}", &secret_param()[..42], digest_param()),
                PairingUriError::InvalidEncoding; "non-canonical trailing bits")]
    #[test_case(format!("{}&b=https%3A%2F%2Fbridge.example.org", link_without_bridge()),
                PairingUriError::InvalidBridge; "bridge with scheme")]
    #[test_case(format!("{}&b=bridge.example.org%3A443", link_without_bridge()),
                PairingUriError::InvalidBridge; "bridge with port")]
    #[test_case(format!("{}&b=", link_without_bridge()), PairingUriError::InvalidBridge; "empty bridge")]
    #[test_case(format!("{}&b=-bridge.org", link_without_bridge()),
                PairingUriError::InvalidBridge; "bridge label starting with a hyphen")]
    #[test_case(format!("{}&b=bridge..org", link_without_bridge()),
                PairingUriError::InvalidBridge; "empty bridge label")]
    fn rejects_malformed_links(link: String, expected: PairingUriError) {
        assert_eq!(link.parse::<PairingUri>(), Err(expected));
    }

    #[test_case("127.0.0.1"; "dotted decimal")]
    #[test_case("127.1"; "short dotted decimal")]
    #[test_case("2130706433"; "decimal")]
    #[test_case("0177.0.0.1"; "octal")]
    #[test_case("127.0x1"; "hexadecimal part")]
    #[test_case("10.0xa"; "hexadecimal letter")]
    #[test_case("127.0X1"; "uppercase hexadecimal prefix")]
    #[test_case("127.0x"; "empty hexadecimal part")]
    #[test_case("0x7f000001"; "hexadecimal")]
    #[test_case("[::1]"; "ipv6")]
    fn rejects_bridge_hosts_that_url_parsers_treat_as_ip_addresses(domain: &str) {
        assert_eq!(
            domain.parse::<BridgeDomain>(),
            Err(PairingUriError::InvalidBridge)
        );
        // Brackets are not valid in a URI query, so they arrive percent-encoded.
        let encoded = domain.replace('[', "%5B").replace(']', "%5D");
        let link = format!("{}&b={encoded}", link_without_bridge());
        assert_eq!(
            link.parse::<PairingUri>(),
            Err(PairingUriError::InvalidBridge)
        );
    }

    #[test_case("bridge.example.org"; "subdomain")]
    #[test_case("127.example.org"; "numeric label")]
    #[test_case("bridge.xn--p1ai"; "punycode top-level label")]
    fn accepts_bridge_domains(domain: &str) {
        assert_eq!(domain.parse::<BridgeDomain>().unwrap().as_str(), domain);
    }

    #[test]
    fn bridge_domain_is_lowercased() {
        assert_eq!(
            "Bridge.Example.ORG"
                .parse::<BridgeDomain>()
                .unwrap()
                .as_str(),
            "bridge.example.org"
        );
    }
}
