//! The on-chain registries a proof's `merkle_root` and `cred_pk` are checked against (WIP-202
//! §4.8 item 4).

use std::{cmp::Reverse, future::Future};

use alloy::{contract, primitives::Address, providers::DynProvider, sol};
use url::{Position, Url};
use world_id_primitives::{EdDSAPublicKey, FieldElement, POH_ISSUER_SCHEMA_ID};
use world_id_registries::world_id::WorldIdRegistry::{self, WorldIdRegistryInstance};
use world_id_services_common::{ProviderArgs, ProviderError, RetryConfig};

use self::CredentialSchemaIssuerRegistry::CredentialSchemaIssuerRegistryInstance;

// TODO: Move into `world-id-registries` next to `WorldIdRegistry`, as `services/relay` and
// `world-id-test-utils` declare the same binding.
sol! {
    /// The part of `CredentialSchemaIssuerRegistry` the sidecar reads.
    #[sol(rpc)]
    interface CredentialSchemaIssuerRegistry {
        struct Pubkey {
            uint256 x;
            uint256 y;
        }

        function issuerSchemaIdToPubkey(uint64 issuerSchemaId) external view returns (Pubkey memory);
    }
}

/// Answers whether a proof's root and Issuer key are trusted.
pub trait Registries: Send + Sync + 'static {
    /// Whether `root` is a valid, unexpired root of the `WorldIDRegistry` (WIP-202 §4.7 Root
    /// Freshness).
    ///
    /// # Errors
    /// The registry could not be read.
    fn is_valid_root(
        &self,
        root: FieldElement,
    ) -> impl Future<Output = Result<bool, RegistryError>> + Send;

    /// Whether `key` is the current key of the Proof of Human Issuer.
    ///
    /// # Errors
    /// The registry could not be read.
    fn is_trusted_issuer(
        &self,
        key: EdDSAPublicKey,
    ) -> impl Future<Output = Result<bool, RegistryError>> + Send;
}

/// A registry read that failed, e.g. because every RPC endpoint was unreachable.
#[derive(Debug, thiserror::Error)]
#[error("{call} failed: {detail}")]
pub struct RegistryError {
    call: &'static str,
    detail: String,
}

impl RegistryError {
    /// A failed `call`, described by `detail`, which must hold no secret such as an RPC URL.
    pub const fn new(call: &'static str, detail: String) -> Self {
        Self { call, detail }
    }
}

/// [`Registries`] that read the World Chain contracts on every check, so a revoked root or a
/// rotated Issuer key takes effect immediately.
pub struct OnchainRegistries {
    world_id_registry: WorldIdRegistryInstance<DynProvider>,
    issuer_registry: CredentialSchemaIssuerRegistryInstance<DynProvider>,
    /// Each part of an RPC URL that may carry an API key, longest first, and what errors show
    /// instead.
    redactions: Vec<(String, String)>,
}

impl OnchainRegistries {
    /// Reads the `WorldIDRegistry` and `CredentialSchemaIssuerRegistry` proxies at the given
    /// addresses through `rpc_urls`, retrying failed calls as `retry` says.
    ///
    /// # Errors
    /// `rpc_urls` is empty.
    pub async fn connect(
        rpc_urls: &[Url],
        retry: RetryConfig,
        world_id_registry: Address,
        credential_schema_issuer_registry: Address,
    ) -> Result<Self, ProviderError> {
        let provider = ProviderArgs {
            http: rpc_urls.to_vec(),
            retry,
            ..ProviderArgs::default()
        }
        .http()
        .await?;
        let mut redactions: Vec<_> = rpc_urls.iter().flat_map(redactions).collect();
        // Longest first, so that no secret is cut apart by a shorter one, e.g. the URL of another
        // endpoint on the same host.
        redactions.sort_by_key(|(secret, _)| Reverse(secret.len()));
        Ok(Self {
            world_id_registry: WorldIdRegistry::new(world_id_registry, provider.clone()),
            issuer_registry: CredentialSchemaIssuerRegistry::new(
                credential_schema_issuer_registry,
                provider,
            ),
            redactions,
        })
    }
}

impl Registries for OnchainRegistries {
    async fn is_valid_root(&self, root: FieldElement) -> Result<bool, RegistryError> {
        self.world_id_registry
            .isValidRoot(root.to_u256())
            .call()
            .await
            .map_err(|source| self.error("WorldIDRegistry.isValidRoot", &source))
    }

    async fn is_trusted_issuer(&self, key: EdDSAPublicKey) -> Result<bool, RegistryError> {
        let registered = self
            .issuer_registry
            .issuerSchemaIdToPubkey(POH_ISSUER_SCHEMA_ID)
            .call()
            .await
            .map_err(|source| {
                self.error(
                    "CredentialSchemaIssuerRegistry.issuerSchemaIdToPubkey",
                    &source,
                )
            })?;
        Ok(registered.x == FieldElement::from(key.pk.x).to_u256()
            && registered.y == FieldElement::from(key.pk.y).to_u256())
    }
}

/// How much of an RPC error a [`RegistryError`] keeps, e.g. of an HTML error page.
const MAX_DETAIL_CHARS: usize = 300;

impl OnchainRegistries {
    /// The error of a failed `call`, without the RPC URLs a transport error or an error page
    /// may show.
    fn error(&self, call: &'static str, source: &contract::Error) -> RegistryError {
        let redacted = self
            .redactions
            .iter()
            .fold(source.to_string(), |detail, (secret, shown)| {
                detail.replace(secret, shown)
            });
        let mut detail: String = redacted.chars().take(MAX_DETAIL_CHARS).collect();
        if detail.len() < redacted.len() {
            detail.push('…');
        }
        RegistryError::new(call, detail)
    }
}

/// The parts of `url` that may carry an API key, each with what errors show instead: the URL as
/// configured and as sent, since the HTTP client drops its user info, its password, and its
/// path and query, which error pages may echo.
fn redactions(url: &Url) -> Vec<(String, String)> {
    let host = format!("<{}>", url.host_str().unwrap_or("rpc"));
    let mut sent = url.clone();
    let _ = sent.set_username("");
    let _ = sent.set_password(None);
    let path_and_query = &url[Position::BeforePath..Position::AfterQuery];
    [
        Some((url.to_string(), host.clone())),
        Some((sent.to_string(), host)),
        url.password()
            .map(|password| (password.to_owned(), "<redacted>".to_owned())),
        (path_and_query != "/").then(|| (path_and_query.to_owned(), "/<redacted>".to_owned())),
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use alloy::sol_types::{SolCall as _, SolValue as _};
    use axum::{
        Json, Router,
        http::{StatusCode, Uri},
        routing::post,
    };
    use serde_json::{Value, json};
    use world_id_primitives::EdDSAPrivateKey;

    use super::*;

    const WORLD_ID_REGISTRY: Address = Address::repeat_byte(1);
    const ISSUER_REGISTRY: Address = Address::repeat_byte(2);

    /// A JSON-RPC endpoint that answers every `eth_call` with `result`, and keeps each call's
    /// target and calldata.
    async fn registries_answering(
        result: Result<Vec<u8>, &'static str>,
    ) -> (OnchainRegistries, Arc<Mutex<Vec<(Value, Value)>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&calls);
        let router = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| async move {
                let call = &request["params"][0];
                let input = call.get("input").or_else(|| call.get("data")).cloned();
                recorded
                    .lock()
                    .unwrap()
                    .push((call["to"].clone(), input.unwrap_or_default()));
                Json(match &result {
                    Ok(output) => json!({
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "result": format!("0x{}", hex::encode(output)),
                    }),
                    Err(message) => json!({
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "error": { "code": -32000, "message": message },
                    }),
                })
            }),
        );
        let url = serve(router).await;
        (registries_at(&[url], RetryConfig::default()).await, calls)
    }

    async fn serve(router: Router) -> Url {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        url.parse().unwrap()
    }

    async fn registries_at(urls: &[Url], retry: RetryConfig) -> OnchainRegistries {
        OnchainRegistries::connect(urls, retry, WORLD_ID_REGISTRY, ISSUER_REGISTRY)
            .await
            .unwrap()
    }

    fn eth_call(to: Address, calldata: &[u8]) -> (Value, Value) {
        (json!(to), json!(format!("0x{}", hex::encode(calldata))))
    }

    fn issuer_key_call() -> (Value, Value) {
        let calldata = CredentialSchemaIssuerRegistry::issuerSchemaIdToPubkeyCall {
            issuerSchemaId: POH_ISSUER_SCHEMA_ID,
        }
        .abi_encode();
        eth_call(ISSUER_REGISTRY, &calldata)
    }

    fn encoded_key(key: &EdDSAPublicKey) -> Vec<u8> {
        CredentialSchemaIssuerRegistry::Pubkey {
            x: FieldElement::from(key.pk.x).to_u256(),
            y: FieldElement::from(key.pk.y).to_u256(),
        }
        .abi_encode()
    }

    #[tokio::test]
    async fn roots_are_checked_with_is_valid_root() {
        let root = FieldElement::from(7u64);
        let (registries, calls) = registries_answering(Ok(true.abi_encode())).await;

        assert!(registries.is_valid_root(root).await.unwrap());
        let expected = WorldIdRegistry::isValidRootCall {
            root: root.to_u256(),
        }
        .abi_encode();
        assert_eq!(
            *calls.lock().unwrap(),
            [eth_call(WORLD_ID_REGISTRY, &expected)]
        );
    }

    #[tokio::test]
    async fn only_the_registered_poh_issuer_key_is_trusted() {
        let issuer = EdDSAPrivateKey::random(&mut rand::thread_rng()).public();
        let other = EdDSAPrivateKey::random(&mut rand::thread_rng()).public();
        let (registries, calls) = registries_answering(Ok(encoded_key(&issuer))).await;

        assert!(registries.is_trusted_issuer(issuer).await.unwrap());
        assert!(!registries.is_trusted_issuer(other).await.unwrap());
        assert_eq!(
            *calls.lock().unwrap(),
            [issuer_key_call(), issuer_key_call()]
        );
    }

    #[tokio::test]
    async fn rpc_errors_are_errors_not_untrusted() {
        let (registries, _) = registries_answering(Err("execution reverted")).await;

        let error = registries
            .is_valid_root(FieldElement::from(7u64))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("execution reverted"), "{error}");
    }

    #[tokio::test]
    async fn an_unreachable_endpoint_fails_after_bounded_retries_without_naming_its_url() {
        let url: Url = "http://user:PASSWORD@127.0.0.1:1/v2/SECRET"
            .parse()
            .unwrap();
        let retry = RetryConfig {
            max_retries: 2,
            initial_backoff_ms: 10,
            max_backoff_ms: 20,
            timeout_secs: 1,
        };
        let registries = registries_at(&[url], retry).await;

        let error = registries
            .is_valid_root(FieldElement::from(7u64))
            .await
            .unwrap_err()
            .to_string();

        assert!(
            error.starts_with("WorldIDRegistry.isValidRoot failed"),
            "{error}"
        );
        assert!(!error.contains("SECRET"), "{error}");
        assert!(!error.contains("PASSWORD"), "{error}");
    }

    #[tokio::test]
    async fn an_error_page_echoing_a_url_is_redacted_and_truncated_whatever_the_url_order() {
        let echo = Router::new().fallback(|uri: Uri| async move {
            let page = format!("Cannot POST {uri}{}", " ".repeat(10 * MAX_DETAIL_CHARS));
            (StatusCode::NOT_FOUND, page)
        });
        let origin = serve(echo).await;
        let keyed = origin.join("worldchain/SECRET").unwrap();
        let keyless = origin.join("worldchain").unwrap();
        let registries = registries_at(&[keyless, keyed], RetryConfig::default()).await;

        let error = registries
            .is_valid_root(FieldElement::from(7u64))
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("Cannot POST /<redacted>"), "{error}");
        assert!(!error.contains("SECRET"), "{error}");
        assert!(error.chars().count() < 2 * MAX_DETAIL_CHARS, "{error}");
    }
}
