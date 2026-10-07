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

/// The `worldid://auth/v1/register` deeplink, shown as a QR code by the Requesting Authenticator.
///
/// It carries the [`PairingSecret`], the [`RegistrationDigest`] and optionally the bridge the
/// Requesting Authenticator uses. Anyone who holds it can retrieve and consume the encrypted
/// registration request; reading its plaintext also requires the independently transferred
/// pairing code. The URI must not be logged or sent to analytics. Its `Debug` output is redacted.
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
///     bridge: Some("bridge.example.org".parse::<BridgeDomain>().unwrap()),
/// };
/// let link = uri.to_string();
/// assert!(link.starts_with("worldid://auth/v1/register?s="));
/// assert_eq!(link.parse::<PairingUri>().unwrap(), uri);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct PairingUri {
    /// The session secret used to derive the request ID and code-bound transport key.
    pub secret: PairingSecret,
    /// The commitment to the registration parameters.
    pub digest: RegistrationDigest,
    /// The bridge to use, or `None` for the Approving Authenticator's default bridge.
    pub bridge: Option<BridgeDomain>,
}

impl fmt::Debug for PairingUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingUri")
            .field("secret", &self.secret)
            .field("digest", &self.digest)
            .field("bridge", &self.bridge)
            .finish()
    }
}

impl fmt::Display for PairingUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut link = Deeplink::new(NAMESPACE, VERSION, ACTION)
            .expect("the registration deeplink is valid")
            .with_param(SECRET_PARAM, URL_SAFE_NO_PAD.encode(self.secret.as_bytes()))
            .expect("the secret parameter key is nonempty")
            .with_param(DIGEST_PARAM, URL_SAFE_NO_PAD.encode(self.digest.as_bytes()))
            .expect("the digest parameter key is nonempty");
        if let Some(bridge) = &self.bridge {
            link = link
                .with_param(BRIDGE_PARAM, bridge.as_str())
                .expect("the bridge parameter key is nonempty");
        }
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
            bridge,
        })
    }
}

/// The domain of a bridge deployment, e.g. `bridge.example.org`.
///
/// It is a DNS name with at least two labels and a final label starting with an ASCII letter,
/// so URL parsers cannot interpret it as an IP address. No scheme, port, path, user info, query
/// or fragment is allowed. Letters are normalized to lowercase; the bridge is reached over `https`.
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
        let has_named_tld = domain
            .rsplit_once('.')
            .is_some_and(|(_, tld)| tld.starts_with(|c: char| c.is_ascii_alphabetic()));
        if domain.len() > 253 || !has_named_tld || !domain.split('.').all(is_valid_label) {
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
    /// The `s` or `d` parameter is missing.
    #[error("missing pairing parameter")]
    MissingParameter,
    /// `s` or `d` is not 32 bytes of canonical unpadded base64url.
    #[error("pairing secret and digest must be 32 bytes of unpadded base64url")]
    InvalidEncoding,
    /// `b` is not a bare DNS domain with a named top-level label.
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
    use super::*;

    fn uri(bridge: Option<&str>) -> PairingUri {
        PairingUri {
            secret: PairingSecret::from_bytes([0xff; 32]),
            digest: RegistrationDigest::from_bytes([0x00; 32]),
            bridge: bridge.map(|b| b.parse().unwrap()),
        }
    }

    #[test]
    fn round_trips_with_and_without_bridge() {
        for bridge in [None, Some("bridge.example.org")] {
            let original = uri(bridge);
            let link = original.to_string();
            assert_eq!(link.parse::<PairingUri>().unwrap(), original, "{link}");
        }
    }

    #[test]
    fn uses_unpadded_base64url() {
        let link = uri(None).to_string();
        assert_eq!(
            link,
            format!(
                "worldid://auth/v1/register?s={}8&d={}",
                "_".repeat(42),
                "A".repeat(43)
            )
        );
    }

    #[test]
    fn accepts_parameters_in_any_order_and_percent_encoded() {
        let link = uri(Some("bridge.example.org")).to_string();
        let (base, query) = link.split_once('?').unwrap();
        let mut params: Vec<&str> = query.split('&').collect();
        params.reverse();
        let reordered = format!("{base}?{}", params.join("&")).replace("bridge.", "bridge%2E");
        assert_eq!(
            reordered.parse::<PairingUri>().unwrap(),
            uri(Some("bridge.example.org"))
        );
    }

    #[test]
    fn debug_redacts_the_secret() {
        let debug = format!("{:?}", uri(None));
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("255"));
    }

    #[test]
    fn rejects_malformed_links() {
        let valid = uri(None).to_string();
        let s = "_".repeat(42) + "8";
        let d = "A".repeat(43);
        let cases = [
            (
                valid.replace("auth/v1/register", "auth/v2/register"),
                PairingUriError::NotARegistrationLink,
            ),
            (
                valid.replace("auth/v1/register", "pay/v1/register"),
                PairingUriError::NotARegistrationLink,
            ),
            (
                valid.replace("worldid://", "https://"),
                PairingUriError::Deeplink(DeeplinkError::InvalidScheme),
            ),
            (format!("{valid}&x=1"), PairingUriError::UnknownParameter),
            (
                format!("{valid}&s={s}"),
                PairingUriError::DuplicateParameter,
            ),
            (
                format!("worldid://auth/v1/register?s={s}"),
                PairingUriError::MissingParameter,
            ),
            (
                format!("worldid://auth/v1/register?d={d}"),
                PairingUriError::MissingParameter,
            ),
            (
                format!("worldid://auth/v1/register?s={s}=&d={d}"),
                PairingUriError::InvalidEncoding,
            ),
            (
                format!("worldid://auth/v1/register?s={}&d={d}", &s[1..]),
                PairingUriError::InvalidEncoding,
            ),
            (
                format!("worldid://auth/v1/register?s={}+w&d={d}", &s[..41]),
                PairingUriError::InvalidEncoding,
            ),
            (
                format!("worldid://auth/v1/register?s={}x&d={d}", &s[..42]),
                PairingUriError::InvalidEncoding,
            ),
            (
                format!("{valid}&b=https%3A%2F%2Fbridge.example.org"),
                PairingUriError::InvalidBridge,
            ),
            (
                format!("{valid}&b=bridge.example.org%3A443"),
                PairingUriError::InvalidBridge,
            ),
            (format!("{valid}&b="), PairingUriError::InvalidBridge),
            (
                format!("{valid}&b=-bridge.org"),
                PairingUriError::InvalidBridge,
            ),
            (
                format!("{valid}&b=bridge..org"),
                PairingUriError::InvalidBridge,
            ),
            (
                format!("{valid}#frag"),
                PairingUriError::Deeplink(DeeplinkError::UnexpectedFragment),
            ),
        ];
        for (link, expected) in cases {
            assert_eq!(link.parse::<PairingUri>(), Err(expected), "{link}");
        }
    }

    #[test]
    fn rejects_bridge_hosts_that_url_parsers_treat_as_ip_addresses() {
        for domain in [
            "127.0.0.1",
            "127.1",
            "2130706433",
            "0177.0.0.1",
            "127.0x1",
            "10.0xa",
            "127.0X1",
            "127.0x",
            "0x7f000001",
            "[::1]",
        ] {
            assert_eq!(
                domain.parse::<BridgeDomain>(),
                Err(PairingUriError::InvalidBridge)
            );
            let link = format!("{}&b={domain}", uri(None));
            assert_eq!(
                link.parse::<PairingUri>(),
                Err(PairingUriError::InvalidBridge)
            );
        }
        for domain in ["bridge.example.org", "127.example.org", "bridge.xn--p1ai"] {
            assert_eq!(domain.parse::<BridgeDomain>().unwrap().as_str(), domain);
        }
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
