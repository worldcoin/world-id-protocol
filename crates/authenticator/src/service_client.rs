use crate::{
    AuthenticatorError,
    ohttp::{OhttpClient, OhttpClientConfig},
};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use world_id_primitives::ServiceEndpoint;

/// Builds the HTTP client for the gateway, the indexer and the RPC.
///
/// A native client trusts only the bundled Mozilla roots: reqwest's default platform verifier
/// panics on Android unless it was initialized through JNI. A browser client uses the browser's
/// TLS.
///
/// # Errors
/// Returns [`AuthenticatorError::NetworkError`] if the TLS backend cannot be initialized.
pub(crate) fn default_http_client() -> Result<reqwest::Client, AuthenticatorError> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        http_client_trusting(webpki_root_certs::TLS_SERVER_ROOT_CERTS)
    }
    #[cfg(target_arch = "wasm32")]
    {
        Ok(reqwest::Client::builder().build()?)
    }
}

/// Builds a native HTTP client that trusts only `roots`.
#[cfg(not(target_arch = "wasm32"))]
fn http_client_trusting(
    roots: &[rustls::pki_types::CertificateDer<'_>],
) -> Result<reqwest::Client, AuthenticatorError> {
    let roots = roots
        .iter()
        .map(|cert| reqwest::Certificate::from_der(cert))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(reqwest::Client::builder().tls_certs_only(roots).build()?)
}

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
    /// Creates a new [`ServiceClient`] for the given endpoint.
    ///
    /// Routes through OHTTP for [`ServiceEndpoint::Ohttp`] and falls back to direct
    /// HTTP for [`ServiceEndpoint::Direct`].
    pub(crate) fn new(
        client: reqwest::Client,
        service_kind: ServiceKind,
        endpoint: &ServiceEndpoint,
    ) -> Result<Self, AuthenticatorError> {
        let transport = match endpoint {
            ServiceEndpoint::Direct { .. } => HttpTransport::Direct(client),
            ServiceEndpoint::Ohttp {
                url,
                relay_url,
                key_config_base64,
            } => HttpTransport::Ohttp(OhttpClient::new(
                client,
                service_kind.ohttp_config_scope(),
                url,
                OhttpClientConfig {
                    relay_url: relay_url.clone(),
                    key_config_base64: key_config_base64.clone(),
                },
            )?),
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
    use rustls::pki_types::CertificateDer;
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::TlsAcceptor;

    /// Serves HTTPS on `127.0.0.1` with a leaf certificate signed by a fresh CA, and returns
    /// the server URL and the CA certificate.
    async fn serve_tls() -> (String, CertificateDer<'static>) {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["127.0.0.1".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &ca)
            .unwrap();

        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], leaf_key.into())
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                // A rejected handshake only ends this connection.
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    continue;
                };
                let mut request = [0; 1024];
                let _ = stream.read(&mut request).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                    .await;
                let _ = stream.shutdown().await;
            }
        });

        (url, ca.der().clone())
    }

    #[tokio::test]
    async fn trusted_root_verifies_server() {
        let (url, ca) = serve_tls().await;

        let response = http_client_trusting(&[ca])
            .unwrap()
            .get(&url)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn default_client_rejects_root_outside_bundle() {
        let (url, _) = serve_tls().await;

        let err = default_http_client()
            .unwrap()
            .get(&url)
            .send()
            .await
            .unwrap_err();

        assert!(format!("{err:?}").contains("UnknownIssuer"), "{err:?}");
    }
}
