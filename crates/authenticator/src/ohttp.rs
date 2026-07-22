use base64::Engine as _;
use bhttp::{Message, Mode};
use ohttp::ClientRequest;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

use crate::AuthenticatorError;

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
}

impl OhttpClientConfig {
    pub fn new(relay_url: String, key_config_base64: String) -> Self {
        Self {
            relay_url,
            key_config_base64,
        }
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
    encoded_config_list: Vec<u8>,
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

        ClientRequest::from_encoded_config_list(&encoded_config_list).map_err(|err| {
            AuthenticatorError::InvalidConfig {
                attribute,
                reason: format!("invalid application/ohttp-keys payload: {err}"),
            }
        })?;

        Ok(Self {
            client,
            config_scope: config_scope.to_owned(),
            relay_url: config.relay_url,
            target_scheme,
            target_authority,
            encoded_config_list,
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

        let ohttp_req = ClientRequest::from_encoded_config_list(&self.encoded_config_list)?;
        let (enc_request, ohttp_resp_ctx) = ohttp_req.encapsulate(&bhttp_buf)?;

        let resp = self
            .client
            .post(&self.relay_url)
            .header("content-type", "message/ohttp-req")
            .body(enc_request)
            .send()
            .await?;

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthenticatorError;

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
                relay_url: err_relay_url,
                content_type,
            }) => {
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
