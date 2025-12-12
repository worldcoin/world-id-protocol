//! This module implements the authentication process for World ID.
//!
//! During the user's session initialization, the MPC nodes uses this authentication service to determine whether a user is eligible to compute a nullifier.
//!
//! Additionally, it defines two sub-modules necessary for the authentication process.
//!
//! - [`merkle_watcher`] – watches the blockchain for merkle-root update events.
//! - [`signature_history`] – keeps track of nonce + time_stamp signatures to detect replays
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use crate::auth::{
    errors::OprfRequestAuthError, issuer_schema_watcher::IssuerSchemaWatcher,
    merkle_watcher::MerkleWatcher, signature_history::SignatureHistory,
};
use alloy::primitives::U256;
use ark_bn254::Bn254;
use async_trait::async_trait;
use oprf_service::OprfRequestAuthenticator;
use oprf_types::api::v1::OprfRequest;
use tracing::instrument;
use world_id_primitives::{oprf::OprfRequestAuthV1, TREE_DEPTH};

pub(crate) mod errors;
pub(crate) mod issuer_schema_watcher;
pub(crate) mod merkle_watcher;
pub(crate) mod signature_history;

pub(crate) struct WorldOprfRequestAuthenticator {
    merkle_watcher: MerkleWatcher,
    issuer_schema_watcher: IssuerSchemaWatcher,
    signature_history: SignatureHistory,
    vk: Arc<ark_groth16::PreparedVerifyingKey<Bn254>>,
    current_time_stamp_max_difference: Duration,
}

impl WorldOprfRequestAuthenticator {
    pub(crate) fn init(
        merkle_watcher: MerkleWatcher,
        issuer_schema_watcher: IssuerSchemaWatcher,
        vk: ark_groth16::VerifyingKey<Bn254>,
        current_time_stamp_max_difference: Duration,
        signature_history_cleanup_interval: Duration,
    ) -> Self {
        Self {
            signature_history: SignatureHistory::init(
                current_time_stamp_max_difference * 2,
                signature_history_cleanup_interval,
            ),
            merkle_watcher,
            issuer_schema_watcher,
            vk: Arc::new(ark_groth16::prepare_verifying_key(&vk)),
            current_time_stamp_max_difference,
        }
    }
}

#[async_trait]
impl OprfRequestAuthenticator for WorldOprfRequestAuthenticator {
    type RequestAuth = OprfRequestAuthV1;
    type RequestAuthError = OprfRequestAuthError;

    #[instrument(level = "debug", skip_all)]
    async fn verify(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<(), Self::RequestAuthError> {
        // check the time stamp against system time +/- difference
        let req_time_stamp = Duration::from_secs(request.auth.current_time_stamp);
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time is after unix epoch");
        if current_time.abs_diff(req_time_stamp) > self.current_time_stamp_max_difference {
            return Err(OprfRequestAuthError::TimeStampDifference);
        }
        tracing::debug!("timestamp difference check success");

        // TODO check the RP nonce signature

        // add signature to history to check if the nonces where only used once
        self.signature_history
            .add_signature(request.auth.signature.to_vec(), req_time_stamp)?;

        tracing::debug!("checking root and issuer schema...");
        // check if the merkle root is valid and get issuer pk
        let (root_valid, issuer_pk) = tokio::join!(
            self.merkle_watcher
                .is_root_valid(request.auth.merkle_root.into()),
            self.issuer_schema_watcher
                .get_pubkey(U256::from(request.auth.cred_type_id))
        );

        root_valid?;
        let cred_pk = issuer_pk?;
        // verify the user proof
        let public = [
            request.blinded_query.x,
            request.blinded_query.y,
            request.auth.cred_type_id.into(),
            cred_pk.x,
            cred_pk.y,
            request.auth.current_time_stamp.into(),
            request.auth.merkle_root,
            ark_babyjubjub::Fq::from(TREE_DEPTH as u64),
            request.share_identifier.oprf_key_id.into(),
            request.auth.action,
            request.auth.nonce,
        ];

        tracing::debug!("verifying user proof...");
        let valid = ark_groth16::Groth16::<Bn254>::verify_proof(
            &self.vk,
            &request.auth.proof.clone().into(),
            &public,
        )
        .map_err(|err| eyre::eyre!(err))?;
        if valid {
            tracing::debug!("proof valid");
            Ok(())
        } else {
            tracing::debug!("proof INVALID");
            Err(OprfRequestAuthError::InvalidProof)
        }
    }
}
