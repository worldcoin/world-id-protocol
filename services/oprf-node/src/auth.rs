//! This module implements the authentication process for World ID.
//!
//! During the user's session initialization, the MPC nodes uses this authentication service to determine whether a user is eligible to compute a nullifier.
//!
//! Additionally, it defines two sub-modules necessary for the authentication process.
//!
//! - [`credential_blinding_factor`] – implements authentication for OPRF credential blinding factor generation.
//! - [`merkle_watcher`] – watches the blockchain for merkle-root update events.
//! - [`nullifier`] – implements authentication for OPRF nullifier generation.
//! - [`rp_registry_watcher`] – keeps track of registered RPs
//! - [`schema_issuer_registry_watcher`] – keeps track of registered Credential Schema Issuers
//! - [`signature_history`] – keeps track of nonce + time_stamp signatures to detect replays

use std::sync::Arc;

use ark_bn254::Bn254;
use axum::{http::StatusCode, response::IntoResponse};
use circom_types::groth16::VerificationKey;
use taceo_oprf::types::OprfKeyId;
use world_id_primitives::{TREE_DEPTH, oprf::OprfRequestErrorResponse};

use crate::auth::merkle_watcher::{MerkleWatcher, MerkleWatcherError};

/// The embedded Groth16 verification key for OPRF query proofs.
const QUERY_VERIFICATION_KEY: &str = include_str!("../../../circom/OPRFQuery.vk.json");

pub(crate) mod credential_blinding_factor;
pub(crate) mod merkle_watcher;
pub(crate) mod nullifier;
pub(crate) mod rp_registry_watcher;
pub(crate) mod schema_issuer_registry_watcher;
pub(crate) mod signature_history;

/// Common errors returned by the shared [`OprfRequestAuthenticator::verify`] method.
#[derive(Debug)]
pub(crate) enum OprfRequestAuthError {
    /// The client Groth16 proof did not verify.
    InvalidProof,
    /// The provided merkle root is not valid.
    InvalidMerkleRoot,
    /// An error returned from the merkle watcher service during merkle look-up.
    MerkleWatcherError(MerkleWatcherError),
}

impl OprfRequestAuthError {
    /// Lossy conversion to the compact wire-format error response.
    ///
    /// Internal details (e.g. the underlying [`MerkleWatcherError`]) are
    /// intentionally dropped — only a client-safe error code survives.
    pub(crate) fn to_oprf_response(&self) -> OprfRequestErrorResponse {
        match self {
            Self::InvalidProof => OprfRequestErrorResponse::InvalidProof,
            Self::InvalidMerkleRoot => OprfRequestErrorResponse::InvalidMerkleRoot,
            Self::MerkleWatcherError(_) => OprfRequestErrorResponse::ServiceUnavailable,
        }
    }
}

impl From<MerkleWatcherError> for OprfRequestAuthError {
    fn from(err: MerkleWatcherError) -> Self {
        Self::MerkleWatcherError(err)
    }
}

/// `taceo-oprf-service` calls `.to_string()` on auth errors to build the
/// WebSocket close frame reason, so `Display` must emit the structured JSON
/// that clients parse back into [`OprfRequestErrorResponse`].
impl std::fmt::Display for OprfRequestAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_oprf_response().to_json())
    }
}

impl std::error::Error for OprfRequestAuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MerkleWatcherError(e) => Some(e),
            _ => None,
        }
    }
}

impl IntoResponse for OprfRequestAuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            OprfRequestAuthError::InvalidProof => {
                (StatusCode::BAD_REQUEST, "invalid proof").into_response()
            }
            OprfRequestAuthError::MerkleWatcherError(err) => {
                tracing::error!("merkle watcher error: {err}");
                (StatusCode::SERVICE_UNAVAILABLE.into_response()).into_response()
            }
            OprfRequestAuthError::InvalidMerkleRoot => {
                (StatusCode::BAD_REQUEST, "invalid merkle root").into_response()
            }
        }
    }
}

/// Common authentication for [`NullifierOprfRequestAuthenticator`] and [`CredentialBlindingFactorOprfRequestAuthenticator`].
pub(crate) struct OprfRequestAuthenticator {
    merkle_watcher: MerkleWatcher,
    vk: Arc<ark_groth16::PreparedVerifyingKey<Bn254>>,
}

impl OprfRequestAuthenticator {
    pub(crate) fn init(merkle_watcher: MerkleWatcher) -> Self {
        let vk: VerificationKey<Bn254> =
            serde_json::from_str(QUERY_VERIFICATION_KEY).expect("can deserialize embedded vk");
        Self {
            merkle_watcher,
            vk: Arc::new(ark_groth16::prepare_verifying_key(&vk.into())),
        }
    }

    pub(crate) async fn verify(
        &self,
        proof: &ark_groth16::Proof<Bn254>,
        blinded_query: ark_babyjubjub::EdwardsAffine,
        merkle_root: ark_babyjubjub::Fq,
        oprf_key_id: OprfKeyId,
        action: ark_babyjubjub::Fq,
        nonce: ark_babyjubjub::Fq,
    ) -> Result<(), OprfRequestAuthError> {
        tracing::trace!("checking if merkle root is valid...");
        let valid = self
            .merkle_watcher
            .is_root_valid(merkle_root.into())
            .await?;
        if !valid {
            tracing::trace!("merkle root INVALID");
            return Err(OprfRequestAuthError::InvalidMerkleRoot);
        }

        tracing::trace!("verifying user proof...");
        let public = [
            blinded_query.x,
            blinded_query.y,
            merkle_root,
            ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
            oprf_key_id.into(),
            action,
            nonce,
        ];
        let valid = ark_groth16::Groth16::<Bn254>::verify_proof(&self.vk, proof, &public)
            .expect("We expect that we loaded the correct key");
        if valid {
            tracing::trace!("proof valid");
            Ok(())
        } else {
            tracing::trace!("proof INVALID");
            Err(OprfRequestAuthError::InvalidProof)
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::{
        primitives::{Address, U256},
        signers::local::LocalSigner,
    };
    use ark_serialize::CanonicalSerialize;
    use rand::Rng;
    use world_id_core::{EdDSAPrivateKey, Signer};
    use world_id_primitives::{
        TREE_DEPTH, authenticator::AuthenticatorPublicKeySet, merkle::MerkleInclusionProof,
    };
    use world_id_test_utils::{
        anvil::TestAnvil,
        fixtures::{RegistryTestContext, RpFixture, generate_rp_fixture},
        merkle::first_leaf_merkle_path,
    };

    pub(crate) struct OprfRequestAuthTestSetup {
        pub(crate) anvil: TestAnvil,
        pub(crate) world_id_registry: Address,
        pub(crate) rp_registry: Address,
        pub(crate) credential_schema_issuer_registry: Address,
        pub(crate) issuer_schema_id: u64,
        pub(crate) rp_fixture: RpFixture,
        pub(crate) merkle_inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
        pub(crate) key_index: u64,
        pub(crate) key_set: AuthenticatorPublicKeySet,
        pub(crate) signer: Signer,
    }

    impl OprfRequestAuthTestSetup {
        pub(crate) async fn new() -> eyre::Result<Self> {
            let mut rng = rand::thread_rng();
            let RegistryTestContext {
                anvil,
                world_id_registry,
                rp_registry,
                credential_registry: credential_schema_issuer_registry,
                ..
            } = RegistryTestContext::new_with_mock_oprf_key_registry().await?;

            let deployer = anvil.signer(0)?;

            let rp_fixture = generate_rp_fixture();

            // Register the RP which also triggers a OPRF key-gen.
            let rp_signer = LocalSigner::from_signing_key(rp_fixture.signing_key.clone());
            anvil
                .register_rp(
                    rp_registry,
                    deployer.clone(),
                    rp_fixture.world_rp_id,
                    rp_signer.address(),
                    rp_signer.address(),
                    "taceo.oprf".to_string(),
                )
                .await?;

            // Register an issuer which also triggers a OPRF key-gen.
            let issuer_schema_id = rng.r#gen::<u64>();
            let issuer_sk = EdDSAPrivateKey::random(&mut rng);
            let issuer_pk = issuer_sk.public();
            anvil
                .register_issuer(
                    credential_schema_issuer_registry,
                    deployer.clone(),
                    issuer_schema_id,
                    issuer_pk.clone(),
                )
                .await?;

            let signer = Signer::from_seed_bytes(&rng.r#gen::<[u8; 32]>()).unwrap();

            let mut key_set = AuthenticatorPublicKeySet::default();
            key_set.try_push(signer.offchain_signer_pubkey())?;
            let leaf_hash = key_set.leaf_hash();

            let offchain_pubkey_compressed = {
                let pk = signer.offchain_signer_pubkey().pk;
                let mut compressed_bytes = Vec::new();
                pk.serialize_compressed(&mut compressed_bytes)
                    .expect("serialization to succeed");
                U256::from_le_slice(&compressed_bytes)
            };

            let leaf_index = 1;
            let (siblings, root) = first_leaf_merkle_path(leaf_hash);
            let key_index = key_set
                .iter()
                .position(|pk| {
                    pk.as_ref()
                        .is_some_and(|pk| pk.pk == signer.offchain_signer_pubkey().pk)
                })
                .expect("key set contains signer key") as u64;

            anvil
                .create_account(
                    world_id_registry,
                    deployer.clone(),
                    signer.onchain_signer_address(),
                    offchain_pubkey_compressed,
                    leaf_hash.into(),
                )
                .await;

            Ok(Self {
                anvil,
                world_id_registry,
                rp_registry,
                credential_schema_issuer_registry,
                issuer_schema_id,
                rp_fixture,
                merkle_inclusion_proof: MerkleInclusionProof {
                    root,
                    leaf_index,
                    siblings,
                },
                key_index,
                key_set,
                signer,
            })
        }
    }

    #[test]
    fn common_auth_error_display_is_valid_json_within_budget() {
        use super::OprfRequestAuthError;
        use world_id_primitives::oprf::{MAX_CLOSE_REASON_BYTES, OprfRequestErrorResponse};

        let errors: Vec<OprfRequestAuthError> = vec![
            OprfRequestAuthError::InvalidProof,
            OprfRequestAuthError::InvalidMerkleRoot,
        ];

        for err in errors {
            let display = format!("{err}");
            let parsed: OprfRequestErrorResponse =
                serde_json::from_str(&display).unwrap_or_else(|e| {
                    panic!("Display for {err:?} is not valid JSON: {display} ({e})")
                });
            assert!(
                display.len() <= MAX_CLOSE_REASON_BYTES,
                "{parsed:?} Display is {} bytes, exceeds {MAX_CLOSE_REASON_BYTES}: {display}",
                display.len()
            );
        }
    }
}
