use base64::Engine as _;
use bhttp::{Message, Mode};
use ohttp::ClientRequest;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use world_id_primitives::PrimitiveError;

use crate::AuthenticatorError;

/// Configuration for routing requests through a single OHTTP relay endpoint.
///
/// Stores the relay URL, the authority header for inner BHTTP routing, and the
/// relay's `application/ohttp-keys` payload as a base64-encoded string.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OhttpClientConfig {
    /// URL of the OHTTP relay that receives encrypted requests.
    pub relay_url: String,
    /// The authority (Host header) placed in the inner BHTTP message,
    /// used by the relay to route decrypted traffic to the correct backend.
    pub authority: String,
    /// Base64-encoded `application/ohttp-keys` payload which contains a list of lengthy prefixed HPKE configs
    pub key_config_base64: String,
}

impl OhttpClientConfig {
    /// Creates a new OHTTP client configuration.
    pub fn new(relay_url: String, authority: String, key_config_base64: String) -> Self {
        Self {
            relay_url,
            authority,
            key_config_base64,
        }
    }

    /// Deserializes an OHTTP client configuration from a JSON string.
    ///
    /// # Errors
    /// Returns a [`PrimitiveError`] if the JSON is malformed.
    pub fn from_json(json_str: &str) -> Result<Self, PrimitiveError> {
        serde_json::from_str(json_str)
            .map_err(|e| PrimitiveError::Serialization(format!("failed to parse OHTTP config: {e}")))
    }
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
    relay_url: String,
    authority: String,
    encoded_config_list: Vec<u8>,
}

impl OhttpClient {
    /// Constructs a new OHTTP client from the given configuration.
    ///
    /// Decodes the base64 key config and validates it eagerly by
    /// parsing the `application/ohttp-keys` payload. Returns
    /// [`AuthenticatorError::InvalidConfig`] if the config is malformed.
    ///
    /// `config_scope` identifies which service this client is for
    /// (e.g. `"ohttp_indexer"` or `"ohttp_gateway"`), and is used to
    /// build fully qualified error attributes like
    /// `"ohttp_indexer.key_config_base64"`.
    pub fn new(
        client: Client,
        config_scope: &str,
        config: OhttpClientConfig,
    ) -> Result<Self, AuthenticatorError> {
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
            relay_url: config.relay_url,
            authority: config.authority,
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
        let body = serde_json::to_vec(body).expect("request types are infallibly serializable");
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
            b"https".to_vec(),
            self.authority.as_bytes().to_vec(),
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
                status: resp.status(),
                body: resp.text().await.unwrap_or_default(),
            });
        }

        let enc_response = resp.bytes().await?;
        let response_buf = ohttp_resp_ctx.decapsulate(&enc_response)?;

        let response_msg = Message::read_bhttp(&mut std::io::Cursor::new(&response_buf))?;
        let status_code = response_msg
            .control()
            .status()
            .map(|s| s.code())
            .ok_or_else(|| {
                AuthenticatorError::Generic(
                    "OHTTP response missing HTTP status line".into(),
                )
            })?;
        let status = StatusCode::from_u16(status_code).map_err(|_| bhttp::Error::InvalidStatus)?;

        Ok(OhttpResponse {
            status,
            body: response_msg.content().to_vec(),
        })
    }
}
