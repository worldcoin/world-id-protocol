use crate::{
    AuthenticatorError,
    ohttp::{OhttpClient, OhttpClientConfig},
};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;

#[derive(Clone, Copy, Debug)]
pub(crate) enum ServiceKind {
    Gateway,
    Indexer,
}

impl ServiceKind {
    pub fn ohttp_config_scope(&self) -> &str {
        match self {
            ServiceKind::Gateway => "ohttp_gateway",
            ServiceKind::Indexer => "ohttp_indexer",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ServiceClient {
    pub(crate) service_kind: ServiceKind,
    transport: HttpTransport,
}

#[derive(Clone, Debug)]
enum HttpTransport {
    Direct(reqwest::Client),
    Ohttp(OhttpClient),
}

#[derive(Debug)]
struct TransportResponse {
    status: StatusCode,
    body: Vec<u8>,
}

impl ServiceClient {
    /// Creates a new [`ServiceClient`] that routes through OHTTP when `ohttp_config` is
    /// `Some`, and falls back to direct HTTP otherwise.
    ///
    /// `target_url` is the origin of the upstream service (e.g. the gateway or
    /// indexer URL). It is forwarded into the encrypted BHTTP envelope when
    /// OHTTP is enabled.
    pub(crate) fn new(
        client: reqwest::Client,
        service_kind: ServiceKind,
        target_url: &str,
        ohttp_config: Option<OhttpClientConfig>,
    ) -> Result<Self, AuthenticatorError> {
        let transport = match ohttp_config {
            Some(config) => HttpTransport::Ohttp(OhttpClient::new(
                client,
                service_kind.ohttp_config_scope(),
                target_url,
                config,
            )?),
            None => HttpTransport::Direct(client),
        };

        Ok(Self {
            service_kind,
            transport,
        })
    }

    /// Reads the response body, falling back to an error description so the caller always retains the HTTP status code.
    async fn response_body_bytes_or_fallback(response: reqwest::Response) -> Vec<u8> {
        response
            .bytes()
            .await
            .map(|bytes| bytes.to_vec())
            .unwrap_or_else(|err| format!("Unable to read response body: {err}").into_bytes())
    }

    async fn success_or_fallback_body(
        response: reqwest::Response,
    ) -> Result<TransportResponse, AuthenticatorError> {
        let status = response.status();
        let body = if status.is_success() {
            response.bytes().await?.to_vec()
        } else {
            Self::response_body_bytes_or_fallback(response).await
        };

        Ok(TransportResponse { status, body })
    }

    fn error_from_response(&self, resp: &TransportResponse) -> AuthenticatorError {
        let body = String::from_utf8_lossy(&resp.body).into_owned();
        match self.service_kind {
            ServiceKind::Gateway => AuthenticatorError::GatewayError {
                status: resp.status,
                body,
            },
            ServiceKind::Indexer => AuthenticatorError::IndexerError {
                status: resp.status,
                body,
            },
        }
    }

    pub(crate) async fn post_json<Req, Res>(
        &self,
        base_url: &str,
        path: &str,
        body: &Req,
    ) -> Result<Res, AuthenticatorError>
    where
        Req: serde::Serialize,
        Res: DeserializeOwned,
    {
        let resp = match &self.transport {
            HttpTransport::Direct(client) => {
                let response = client
                    .post(format!("{base_url}{path}"))
                    .json(body)
                    .send()
                    .await?;
                Self::success_or_fallback_body(response).await?
            }
            HttpTransport::Ohttp(client) => {
                let resp = client.post_json(path, body).await?;
                TransportResponse {
                    status: resp.status,
                    body: resp.body,
                }
            }
        };

        if !resp.status.is_success() {
            return Err(self.error_from_response(&resp));
        }

        serde_json::from_slice(&resp.body).map_err(|err| {
            AuthenticatorError::InvalidServiceResponse(format!(
                "failed to decode successful {} response at {path}: {err}",
                match self.service_kind {
                    ServiceKind::Gateway => "gateway",
                    ServiceKind::Indexer => "indexer",
                }
            ))
        })
    }

    pub(crate) async fn get_json<Res>(
        &self,
        base_url: &str,
        path: &str,
    ) -> Result<Res, AuthenticatorError>
    where
        Res: DeserializeOwned,
    {
        let resp = match &self.transport {
            HttpTransport::Direct(client) => {
                let response = client.get(format!("{base_url}{path}")).send().await?;
                Self::success_or_fallback_body(response).await?
            }
            HttpTransport::Ohttp(client) => {
                let resp = client.get(path).await?;
                TransportResponse {
                    status: resp.status,
                    body: resp.body,
                }
            }
        };

        if !resp.status.is_success() {
            return Err(self.error_from_response(&resp));
        }

        serde_json::from_slice(&resp.body).map_err(|err| {
            AuthenticatorError::InvalidServiceResponse(format!(
                "failed to decode successful {} response at {path}: {err}",
                match self.service_kind {
                    ServiceKind::Gateway => "gateway",
                    ServiceKind::Indexer => "indexer",
                }
            ))
        })
    }
}
