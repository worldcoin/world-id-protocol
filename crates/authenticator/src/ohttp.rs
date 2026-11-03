use base64::Engine as _;
use bhttp::{Message, Mode};
use ohttp::{ClientRequest, ClientResponse, KeyConfig};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
pub use world_id_primitives::OhttpKem;

use crate::{AuthenticatorError, service_client::REQUEST_TIMEOUT};

/// Configuration for routing requests through a single OHTTP relay endpoint.
///
/// Stores the relay URL and the relay's `application/ohttp-keys` payload as a
/// base64-encoded string. The target origin is supplied separately when
/// constructing an [`OhttpClient`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OhttpClientConfig {
    /// URL of the OHTTP relay that receives encrypted requests.
    pub relay_url: String,
    /// Base64-encoded `application/ohttp-keys` payload which contains a list of length prefixed HPKE configs
    pub key_config_base64: String,
    /// Which key in the payload to use. Defaults to [`OhttpKem::Auto`].
    #[serde(default)]
    pub kem: OhttpKem,
}

impl OhttpClientConfig {
    pub fn new(relay_url: String, key_config_base64: String) -> Self {
        Self {
            relay_url,
            key_config_base64,
            kem: OhttpKem::Auto,
        }
    }

    /// Selects which key in the payload to use.
    #[must_use]
    pub const fn with_kem(mut self, kem: OhttpKem) -> Self {
        self.kem = kem;
        self
    }
}

/// Returns `true` if `content_type` is the OHTTP response media type
/// `message/ohttp-res`, matched loosely: case-insensitive and ignoring any
/// parameters (e.g. `message/ohttp-res; charset=utf-8`).
fn is_ohttp_res_content_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .map(str::trim)
        .is_some_and(|media_type| media_type.eq_ignore_ascii_case("message/ohttp-res"))
}

const KEM_XWING: u16 = 0x647a;
const KEM_X25519: u16 = 0x0020;

/// Picks the key configs to use from an `application/ohttp-keys` payload.
///
/// The payload's order depends on the gateway implementation, so the choice
/// is made by KEM, each using the last (newest) listed config of that KEM.
/// [`OhttpKem::Auto`] uses X-Wing if present, with X25519 as the fallback; a
/// payload with neither uses its last supported config. An explicit KEM must
/// be present and has no fallback.
fn preferred_configs(
    encoded_config_list: &[u8],
    kem: OhttpKem,
) -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
    let configs: Vec<Vec<u8>> = KeyConfig::decode_list(encoded_config_list)
        .and_then(|configs| configs.iter().map(KeyConfig::encode).collect())
        .map_err(|err| format!("invalid application/ohttp-keys payload: {err}"))?;
    // An encoded key config starts with the key ID, then the 2-byte KEM ID.
    let last_with_kem = |kem: u16| {
        configs
            .iter()
            .rev()
            .find(|config| config[1..3] == kem.to_be_bytes())
            .cloned()
    };
    let only = |kem_id: u16, name: &str| {
        last_with_kem(kem_id)
            .map(|config| (config, None))
            .ok_or_else(|| format!("application/ohttp-keys payload has no {name} key config"))
    };
    match kem {
        OhttpKem::X25519 => only(KEM_X25519, "X25519"),
        OhttpKem::XWing => only(KEM_XWING, "X-Wing"),
        OhttpKem::Auto => match (last_with_kem(KEM_XWING), last_with_kem(KEM_X25519)) {
            (Some(xwing), x25519) => Ok((xwing, x25519)),
            (None, Some(x25519)) => Ok((x25519, None)),
            (None, None) => configs
                .last()
                .cloned()
                .map(|config| (config, None))
                .ok_or_else(|| {
                    "invalid application/ohttp-keys payload: no supported key config".to_owned()
                }),
        },
    }
}

/// Whether the gateway rejected an Encapsulated Request before forwarding
/// it: 400 for an unknown key or failed decryption, 401 for an unknown key on
/// the Go gateway. Retrying such a request with another key is safe.
fn is_key_rejection(status: StatusCode) -> bool {
    matches!(status, StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED)
}

/// Parsed response from an OHTTP-decapsulated Binary HTTP message.
#[derive(Debug)]
pub struct OhttpResponse {
    /// HTTP status code from the inner response.
    pub status: StatusCode,
    /// Raw body bytes from the inner response.
    pub body: Vec<u8>,
}

/// Reusable OHTTP client that owns validated relay configuration and a shared
/// HTTP client for sending encrypted requests.
#[derive(Clone, Debug)]
pub struct OhttpClient {
    client: Client,
    config_scope: String,
    relay_url: String,
    target_scheme: String,
    target_authority: String,
    key_config: Vec<u8>,
    fallback_key_config: Option<Vec<u8>>,
}

impl OhttpClient {
    /// Constructs a new OHTTP client from the given configuration.
    ///
    /// `target_url` is the origin (`scheme://authority`) of the upstream
    /// service; it is placed inside the encrypted BHTTP message so the
    /// OHTTP gateway can route to the correct backend.
    ///
    /// Decodes the base64 key config and validates it eagerly by
    /// parsing the `application/ohttp-keys` payload. Returns
    /// [`AuthenticatorError::InvalidConfig`] if the config is malformed.
    ///
    /// `config_scope` identifies which service this client is for
    /// (e.g. `"ohttp_indexer"` or `"ohttp_gateway"`), and is used to
    /// build fully qualified error attributes.
    pub fn new(
        client: Client,
        config_scope: &str,
        target_url: &str,
        config: OhttpClientConfig,
    ) -> Result<Self, AuthenticatorError> {
        let (target_scheme, target_authority) =
            target_url
                .split_once("://")
                .ok_or_else(|| AuthenticatorError::InvalidConfig {
                    attribute: format!("{config_scope}.target_url"),
                    reason: format!("expected scheme://authority, got {:?}", target_url),
                })?;

        let target_scheme = target_scheme.to_owned();
        let target_authority = target_authority.trim_end_matches('/').to_owned();

        let attribute = format!("{config_scope}.key_config_base64");

        let encoded_config_list = base64::engine::general_purpose::STANDARD
            .decode(&config.key_config_base64)
            .map_err(|err| AuthenticatorError::InvalidConfig {
                attribute: attribute.clone(),
                reason: format!("invalid base64: {err}"),
            })?;

        let (key_config, fallback_key_config) = preferred_configs(&encoded_config_list, config.kem)
            .map_err(|reason| AuthenticatorError::InvalidConfig { attribute, reason })?;

        Ok(Self {
            client,
            config_scope: config_scope.to_owned(),
            relay_url: config.relay_url,
            target_scheme,
            target_authority,
            key_config,
            fallback_key_config,
        })
    }

    /// Sends a JSON-serialized POST request through the OHTTP relay.
    ///
    /// # Errors
    /// Returns an [`AuthenticatorError`] on serialization, encryption, transport,
    /// or relay-level failures.
    pub async fn post_json<T: serde::Serialize>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<OhttpResponse, AuthenticatorError> {
        let body = serde_json::to_vec(body).map_err(|e| {
            AuthenticatorError::Generic(format!("failed to serialize request body: {e}"))
        })?;
        self.request(b"POST", path, Some(&body)).await
    }

    /// Sends a GET request through the OHTTP relay.
    ///
    /// # Errors
    /// Returns an [`AuthenticatorError`] on encryption, transport, or relay-level failures.
    pub async fn get(&self, path: &str) -> Result<OhttpResponse, AuthenticatorError> {
        self.request(b"GET", path, None).await
    }

    async fn request(
        &self,
        method: &[u8],
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<OhttpResponse, AuthenticatorError> {
        let mut msg = Message::request(
            method.to_vec(),
            self.target_scheme.as_bytes().to_vec(),
            self.target_authority.as_bytes().to_vec(),
            path.as_bytes().to_vec(),
        );
        if let Some(body) = body {
            msg.put_header("content-type", "application/json");
            msg.write_content(body);
        }
        let mut bhttp_buf = Vec::new();
        msg.write_bhttp(Mode::KnownLength, &mut bhttp_buf)?;

        let (mut resp, mut ohttp_resp_ctx) = self.send(&self.key_config, &bhttp_buf).await?;
        if let Some(fallback) = &self.fallback_key_config
            && is_key_rejection(resp.status())
        {
            (resp, ohttp_resp_ctx) = self.send(fallback, &bhttp_buf).await?;
        }

        if !resp.status().is_success() {
            return Err(AuthenticatorError::OhttpRelayError {
                service: self.config_scope.clone(),
                relay_url: self.relay_url.clone(),
                status: resp.status(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        // RFC 9458: a successful OHTTP exchange is returned as `message/ohttp-res`.
        // The gateway sets this content-type only on a 2xx success; any other 2xx
        // body (e.g. a captive portal or proxy HTML page) is not decryptable, so
        // reject it with a clear error instead of a cryptic decapsulation failure.
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if !content_type
            .as_deref()
            .is_some_and(is_ohttp_res_content_type)
        {
            return Err(AuthenticatorError::OhttpRelayInvalidResponse {
                service: self.config_scope.clone(),
                relay_url: self.relay_url.clone(),
                content_type,
            });
        }

        let enc_response = resp.bytes().await?;
        let response_buf = ohttp_resp_ctx
            .decapsulate(&enc_response)
            .map_err(AuthenticatorError::OhttpDecapsulationError)?;

        let response_msg = Message::read_bhttp(&mut std::io::Cursor::new(&response_buf))?;
        let status_code = response_msg
            .control()
            .status()
            .map(|s| s.code())
            .ok_or_else(|| {
                AuthenticatorError::Generic("OHTTP response missing HTTP status line".into())
            })?;
        let status = StatusCode::from_u16(status_code).map_err(|_| bhttp::Error::InvalidStatus)?;

        Ok(OhttpResponse {
            status,
            body: response_msg.content().to_vec(),
        })
    }

    /// Encapsulates `bhttp` for `key_config` and POSTs it to the relay.
    async fn send(
        &self,
        key_config: &[u8],
        bhttp: &[u8],
    ) -> Result<(reqwest::Response, ClientResponse), AuthenticatorError> {
        let (enc_request, ohttp_resp_ctx) =
            ClientRequest::from_encoded_config(key_config)?.encapsulate(bhttp)?;
        let resp = self
            .client
            .post(&self.relay_url)
            .timeout(REQUEST_TIMEOUT)
            .header("content-type", "message/ohttp-req")
            .body(enc_request)
            .send()
            .await?;
        Ok((resp, ohttp_resp_ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthenticatorError;
    use test_case::test_case;

    #[test]
    fn invalid_base64_key_config_returns_invalid_config() {
        let config = OhttpClientConfig::new(
            "http://localhost:1234".into(),
            "not valid base64 !!!".into(),
        );

        let result = OhttpClient::new(
            reqwest::Client::new(),
            "test_scope",
            "https://localhost:9999",
            config,
        );
        match result {
            Err(AuthenticatorError::InvalidConfig { attribute, reason }) => {
                assert_eq!(attribute, "test_scope.key_config_base64");
                assert!(
                    reason.contains("invalid base64"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected InvalidConfig, got: {other:?}"),
        }
    }

    #[test]
    fn invalid_ohttp_keys_payload_returns_invalid_config() {
        let config = OhttpClientConfig::new(
            "http://localhost:1234".into(),
            base64::engine::general_purpose::STANDARD
                .encode(b"definitely not an ohttp-keys payload"),
        );

        let result = OhttpClient::new(
            reqwest::Client::new(),
            "my_scope",
            "https://localhost:9999",
            config,
        );
        match result {
            Err(AuthenticatorError::InvalidConfig { attribute, reason }) => {
                assert_eq!(attribute, "my_scope.key_config_base64");
                assert!(
                    reason.contains("invalid application/ohttp-keys payload"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected InvalidConfig, got: {other:?}"),
        }
    }

    #[test]
    fn garbage_ohttp_keys_bytes_returns_invalid_config() {
        let config = OhttpClientConfig::new(
            "http://127.0.0.1:0/does-not-exist".into(),
            base64::engine::general_purpose::STANDARD.encode(b"not-a-valid-ohttp-keys"),
        );

        let result = OhttpClient::new(
            reqwest::Client::new(),
            "test",
            "http://localhost:1234",
            config,
        );
        assert!(
            matches!(result, Err(AuthenticatorError::InvalidConfig { .. })),
            "expected InvalidConfig for garbage key config, got: {result:?}"
        );
    }

    #[test]
    fn missing_scheme_in_target_url_returns_invalid_config() {
        let config = OhttpClientConfig::new(
            "http://localhost:1234".into(),
            base64::engine::general_purpose::STANDARD.encode(b"irrelevant"),
        );

        let result = OhttpClient::new(
            reqwest::Client::new(),
            "test_scope",
            "localhost:9999",
            config,
        );
        match result {
            Err(AuthenticatorError::InvalidConfig { attribute, reason }) => {
                assert_eq!(attribute, "test_scope.target_url");
                assert!(
                    reason.contains("expected scheme://authority"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected InvalidConfig, got: {other:?}"),
        }
    }

    #[test]
    fn empty_key_config_returns_invalid_config() {
        let config = OhttpClientConfig::new(
            "http://localhost:1234".into(),
            base64::engine::general_purpose::STANDARD.encode(b""),
        );

        let result = OhttpClient::new(
            reqwest::Client::new(),
            "test_scope",
            "https://localhost:9999",
            config,
        );
        assert!(
            matches!(result, Err(AuthenticatorError::InvalidConfig { .. })),
            "expected InvalidConfig for empty key config, got: {result:?}"
        );
    }

    #[test]
    fn ohttp_res_content_type_matches_loosely() {
        // Exact, parameterised, and differently-cased variants all match.
        assert!(is_ohttp_res_content_type("message/ohttp-res"));
        assert!(is_ohttp_res_content_type(
            "message/ohttp-res; charset=utf-8"
        ));
        assert!(is_ohttp_res_content_type("Message/OHTTP-Res"));
        assert!(is_ohttp_res_content_type("message/ohttp-res ; foo=bar"));

        // Anything else (including the request media type) is rejected.
        assert!(!is_ohttp_res_content_type("message/ohttp-req"));
        assert!(!is_ohttp_res_content_type("text/html"));
        assert!(!is_ohttp_res_content_type("application/json"));
        assert!(!is_ohttp_res_content_type(""));
    }

    fn key_config(key_id: u8, kem: ohttp::hpke::Kem) -> ohttp::KeyConfig {
        ohttp::init();
        ohttp::KeyConfig::new(
            key_id,
            kem,
            vec![ohttp::SymmetricSuite::new(
                ohttp::hpke::Kdf::HkdfSha256,
                ohttp::hpke::Aead::Aes128Gcm,
            )],
        )
        .expect("failed to build test key config")
    }

    fn selected_key_ids(
        configs: &[&ohttp::KeyConfig],
        kem: OhttpKem,
    ) -> Result<(u8, Option<u8>), String> {
        let list = ohttp::KeyConfig::encode_list(configs).unwrap();
        let (primary, fallback) = preferred_configs(&list, kem)?;
        Ok((primary[0], fallback.map(|config| config[0])))
    }

    #[test]
    fn prefers_xwing_and_falls_back_to_x25519_regardless_of_order() {
        let x25519 = key_config(128, ohttp::hpke::Kem::X25519Sha256);
        let xwing = key_config(64, ohttp::hpke::Kem::XWing);
        let auto = OhttpKem::Auto;
        // Rust gateway order, then Go v0.0.4 order.
        assert_eq!(
            selected_key_ids(&[&x25519, &xwing], auto),
            Ok((64, Some(128)))
        );
        assert_eq!(
            selected_key_ids(&[&xwing, &x25519], auto),
            Ok((64, Some(128)))
        );
        // With several generations, the last listed config of each KEM wins.
        let newer_xwing = key_config(65, ohttp::hpke::Kem::XWing);
        assert_eq!(
            selected_key_ids(&[&x25519, &xwing, &newer_xwing], auto),
            Ok((65, Some(128)))
        );
        // Without X-Wing, X25519 is used and there is nothing to fall back to.
        assert_eq!(selected_key_ids(&[&x25519], auto), Ok((128, None)));
    }

    #[test]
    fn explicit_kem_uses_only_that_key() {
        let x25519 = key_config(128, ohttp::hpke::Kem::X25519Sha256);
        let xwing = key_config(64, ohttp::hpke::Kem::XWing);
        assert_eq!(
            selected_key_ids(&[&x25519, &xwing], OhttpKem::X25519),
            Ok((128, None))
        );
        assert_eq!(
            selected_key_ids(&[&xwing, &x25519], OhttpKem::XWing),
            Ok((64, None))
        );
        assert!(selected_key_ids(&[&x25519], OhttpKem::XWing).is_err());
    }

    /// A client whose embedded payload lists X25519 (key 128) then X-Wing (key 64).
    fn dual_kem_client(relay_url: String) -> OhttpClient {
        let list = ohttp::KeyConfig::encode_list(&[
            key_config(128, ohttp::hpke::Kem::X25519Sha256),
            key_config(64, ohttp::hpke::Kem::XWing),
        ])
        .unwrap();
        OhttpClient::new(
            reqwest::Client::new(),
            "ohttp_gateway",
            "https://target.example",
            OhttpClientConfig::new(
                relay_url,
                base64::engine::general_purpose::STANDARD.encode(list),
            ),
        )
        .expect("failed to construct test OhttpClient")
    }

    /// Matches Encapsulated Requests whose header names `key_id`.
    fn for_key(key_id: u8) -> impl Fn(&mockito::Request) -> bool + Send + Sync + 'static {
        move |request| {
            request
                .body()
                .is_ok_and(|body| body.first() == Some(&key_id))
        }
    }

    #[test_case(400 ; "gateway rejects the key")]
    #[test_case(401 ; "go gateway does not know the key")]
    #[tokio::test]
    async fn key_rejection_retries_once_with_x25519(rejection: usize) {
        let mut server = mockito::Server::new_async().await;
        let xwing = server
            .mock("POST", "/")
            .match_request(for_key(64))
            .with_status(rejection)
            .expect(1)
            .create_async()
            .await;
        // A distinct status shows the reported result comes from the X25519 attempt.
        let x25519 = server
            .mock("POST", "/")
            .match_request(for_key(128))
            .with_status(503)
            .expect(1)
            .create_async()
            .await;

        let result = dual_kem_client(server.url()).get("/account").await;

        assert!(
            matches!(result, Err(AuthenticatorError::OhttpRelayError { status, .. }) if status == StatusCode::SERVICE_UNAVAILABLE),
            "unexpected result: {result:?}"
        );
        xwing.assert_async().await;
        x25519.assert_async().await;
    }

    #[tokio::test]
    async fn other_relay_errors_are_not_retried() {
        let mut server = mockito::Server::new_async().await;
        let xwing = server
            .mock("POST", "/")
            .match_request(for_key(64))
            .with_status(502)
            .expect(1)
            .create_async()
            .await;
        let x25519 = server
            .mock("POST", "/")
            .match_request(for_key(128))
            .expect(0)
            .create_async()
            .await;

        let result = dual_kem_client(server.url()).get("/account").await;

        assert!(
            matches!(result, Err(AuthenticatorError::OhttpRelayError { status, .. }) if status == StatusCode::BAD_GATEWAY),
            "unexpected result: {result:?}"
        );
        xwing.assert_async().await;
        x25519.assert_async().await;
    }

    /// Builds a valid base64 `application/ohttp-keys` config list so that
    /// [`OhttpClient::new`] succeeds and the request path can encapsulate.
    fn test_key_config_base64() -> String {
        ohttp::init();
        let config = ohttp::KeyConfig::new(
            1,
            ohttp::hpke::Kem::X25519Sha256,
            vec![ohttp::SymmetricSuite::new(
                ohttp::hpke::Kdf::HkdfSha256,
                ohttp::hpke::Aead::Aes128Gcm,
            )],
        )
        .expect("failed to build test key config");
        let encoded =
            ohttp::KeyConfig::encode_list(&[config]).expect("failed to encode test key config");
        base64::engine::general_purpose::STANDARD.encode(encoded)
    }

    fn test_client(relay_url: String) -> OhttpClient {
        OhttpClient::new(
            reqwest::Client::new(),
            "ohttp_gateway",
            "https://target.example",
            OhttpClientConfig::new(relay_url, test_key_config_base64()),
        )
        .expect("failed to construct test OhttpClient")
    }

    #[tokio::test]
    async fn relay_non_success_status_yields_relay_error_with_scope_and_url() {
        let mut server = mockito::Server::new_async().await;
        let relay_url = server.url();
        let mock = server
            .mock("POST", "/")
            .with_status(502)
            .with_body("upstream boom")
            .create_async()
            .await;

        let client = test_client(relay_url.clone());
        let result = client.get("/account").await;

        match result {
            Err(AuthenticatorError::OhttpRelayError {
                service,
                relay_url: err_relay_url,
                status,
                body,
            }) => {
                assert_eq!(service, "ohttp_gateway");
                assert_eq!(err_relay_url, relay_url);
                assert_eq!(status, StatusCode::BAD_GATEWAY);
                assert_eq!(body, "upstream boom");
            }
            other => panic!("expected OhttpRelayError, got: {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn relay_2xx_non_ohttp_content_type_yields_invalid_response() {
        let mut server = mockito::Server::new_async().await;
        let relay_url = server.url();
        // A captive portal / proxy intercepting the connection returns 200 HTML.
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "text/html")
            .with_body("<html>captive portal</html>")
            .create_async()
            .await;

        let client = test_client(relay_url.clone());
        let result = client.get("/account").await;

        match result {
            Err(AuthenticatorError::OhttpRelayInvalidResponse {
                service,
                relay_url: err_relay_url,
                content_type,
            }) => {
                assert_eq!(service, "ohttp_gateway");
                assert_eq!(err_relay_url, relay_url);
                assert_eq!(content_type.as_deref(), Some("text/html"));
            }
            other => panic!("expected OhttpRelayInvalidResponse, got: {other:?}"),
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn ohttp_res_with_undecryptable_body_yields_decapsulation_error() {
        let mut server = mockito::Server::new_async().await;
        let relay_url = server.url();
        // Correct content-type but a body that is not a valid encapsulated
        // response: this must surface as a *decapsulation* error, never as the
        // encapsulation error the two used to share.
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "message/ohttp-res")
            .with_body("not a valid encapsulated response")
            .create_async()
            .await;

        let client = test_client(relay_url);
        let result = client.get("/account").await;

        match result {
            Err(AuthenticatorError::OhttpDecapsulationError(_)) => {}
            other => panic!("expected OhttpDecapsulationError, got: {other:?}"),
        }
        mock.assert_async().await;
    }
}
