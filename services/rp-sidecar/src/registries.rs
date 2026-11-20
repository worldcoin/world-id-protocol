//! The on-chain registries a proof's `merkle_root` and `cred_pk` are checked against (WIP-202
//! §4.8 item 4).

use std::future::Future;

use alloy::{contract, primitives::Address, providers::DynProvider, sol};
use world_id_primitives::{EdDSAPublicKey, FieldElement, POH_ISSUER_SCHEMA_ID};
use world_id_registries::world_id::WorldIdRegistry::{self, WorldIdRegistryInstance};

use self::CredentialSchemaIssuerRegistry::CredentialSchemaIssuerRegistryInstance;

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
#[error("{call} failed: {source}")]
pub struct RegistryError {
    call: &'static str,
    source: contract::Error,
}

/// [`Registries`] that read the World Chain contracts on every check, so a revoked root or a
/// rotated Issuer key takes effect immediately.
pub struct OnchainRegistries {
    world_id_registry: WorldIdRegistryInstance<DynProvider>,
    issuer_registry: CredentialSchemaIssuerRegistryInstance<DynProvider>,
}

impl OnchainRegistries {
    /// Reads the `WorldIDRegistry` and `CredentialSchemaIssuerRegistry` proxies at the given
    /// addresses through `provider`.
    #[must_use]
    pub fn new(
        provider: DynProvider,
        world_id_registry: Address,
        credential_schema_issuer_registry: Address,
    ) -> Self {
        Self {
            world_id_registry: WorldIdRegistry::new(world_id_registry, provider.clone()),
            issuer_registry: CredentialSchemaIssuerRegistry::new(
                credential_schema_issuer_registry,
                provider,
            ),
        }
    }
}

impl Registries for OnchainRegistries {
    async fn is_valid_root(&self, root: FieldElement) -> Result<bool, RegistryError> {
        self.world_id_registry
            .isValidRoot(root.to_u256())
            .call()
            .await
            .map_err(|source| RegistryError {
                call: "WorldIDRegistry.isValidRoot",
                source,
            })
    }

    async fn is_trusted_issuer(&self, key: EdDSAPublicKey) -> Result<bool, RegistryError> {
        let registered = self
            .issuer_registry
            .issuerSchemaIdToPubkey(POH_ISSUER_SCHEMA_ID)
            .call()
            .await
            .map_err(|source| RegistryError {
                call: "CredentialSchemaIssuerRegistry.issuerSchemaIdToPubkey",
                source,
            })?;
        Ok(registered.x == FieldElement::from(key.pk.x).to_u256()
            && registered.y == FieldElement::from(key.pk.y).to_u256())
    }
}

#[cfg(test)]
mod tests {
    use alloy::{
        primitives::U256,
        providers::{Provider as _, ProviderBuilder},
        sol_types::{SolCall as _, SolValue as _},
    };
    use axum::{Json, Router, routing::post};
    use serde_json::{Value, json};
    use world_id_primitives::EdDSAPrivateKey;

    use super::*;

    const WORLD_ID_REGISTRY: Address = Address::repeat_byte(1);
    const ISSUER_REGISTRY: Address = Address::repeat_byte(2);

    /// A JSON-RPC endpoint that answers one `eth_call`, checking its target and calldata.
    async fn registries_answering(
        to: Address,
        calldata: Vec<u8>,
        result: Result<Vec<u8>, &'static str>,
    ) -> OnchainRegistries {
        let router = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| async move {
                assert_eq!(request["method"], "eth_call");
                let call = &request["params"][0];
                assert_eq!(call["to"], json!(to));
                let input = call.get("input").or_else(|| call.get("data")).unwrap();
                assert_eq!(input, &json!(format!("0x{}", hex::encode(&calldata))));
                let outcome = match &result {
                    Ok(output) => json!({ "result": format!("0x{}", hex::encode(output)) }),
                    Err(message) => json!({ "error": { "code": -32000, "message": message } }),
                };
                let mut response = json!({ "jsonrpc": "2.0", "id": request["id"] });
                response
                    .as_object_mut()
                    .unwrap()
                    .extend(outcome.as_object().unwrap().clone());
                Json(response)
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let provider = ProviderBuilder::new()
            .connect_http(url.parse().unwrap())
            .erased();
        OnchainRegistries::new(provider, WORLD_ID_REGISTRY, ISSUER_REGISTRY)
    }

    fn issuer_key_call() -> Vec<u8> {
        CredentialSchemaIssuerRegistry::issuerSchemaIdToPubkeyCall {
            issuerSchemaId: POH_ISSUER_SCHEMA_ID,
        }
        .abi_encode()
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
        let calldata = WorldIdRegistry::isValidRootCall {
            root: root.to_u256(),
        }
        .abi_encode();
        let registries =
            registries_answering(WORLD_ID_REGISTRY, calldata, Ok(true.abi_encode())).await;

        assert!(registries.is_valid_root(root).await.unwrap());
    }

    #[tokio::test]
    async fn only_the_registered_poh_issuer_key_is_trusted() {
        let issuer = EdDSAPrivateKey::random(&mut rand::thread_rng()).public();
        let other = EdDSAPrivateKey::random(&mut rand::thread_rng()).public();
        let registries =
            registries_answering(ISSUER_REGISTRY, issuer_key_call(), Ok(encoded_key(&issuer)))
                .await;

        assert!(registries.is_trusted_issuer(issuer).await.unwrap());
        assert!(!registries.is_trusted_issuer(other).await.unwrap());
    }

    #[tokio::test]
    async fn an_unregistered_issuer_is_not_trusted() {
        let key = EdDSAPrivateKey::random(&mut rand::thread_rng()).public();
        let unregistered = CredentialSchemaIssuerRegistry::Pubkey {
            x: U256::ZERO,
            y: U256::ZERO,
        }
        .abi_encode();
        let registries =
            registries_answering(ISSUER_REGISTRY, issuer_key_call(), Ok(unregistered)).await;

        assert!(!registries.is_trusted_issuer(key).await.unwrap());
    }

    #[tokio::test]
    async fn rpc_failures_are_errors_not_untrusted() {
        let root = FieldElement::from(7u64);
        let calldata = WorldIdRegistry::isValidRootCall {
            root: root.to_u256(),
        }
        .abi_encode();
        let registries =
            registries_answering(WORLD_ID_REGISTRY, calldata, Err("node unavailable")).await;

        assert!(registries.is_valid_root(root).await.is_err());
    }
}
