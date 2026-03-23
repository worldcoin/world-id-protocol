use crate::auth::{
    self, merkle_watcher::MerkleWatcher, nonce_history::NonceHistory,
    rp_registry_watcher::RpRegistryWatcher,
};
use async_trait::async_trait;
use std::time::Duration;
use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
};
use tracing::instrument;
use world_id_core::FieldElement;
use world_id_primitives::SessionFeType;
use world_id_primitives::{
    SessionFieldElement,
    oprf::{NullifierOprfRequestAuthV1, WorldIdRequestAuthError},
};

pub(crate) struct SessionOprfRequestAuthenticator(auth::OprfRequestAuthWithRpSignature);

impl SessionOprfRequestAuthenticator {
    pub(crate) fn init(
        merkle_watcher: MerkleWatcher,
        rp_registry_watcher: RpRegistryWatcher,
        nonce_history: NonceHistory,
        current_time_stamp_max_difference: Duration,
    ) -> Self {
        Self(crate::auth::OprfRequestAuthWithRpSignature::init(
            merkle_watcher,
            rp_registry_watcher,
            nonce_history,
            current_time_stamp_max_difference,
        ))
    }

    async fn authenticate_inner(
        &self,
        request: &OprfRequest<NullifierOprfRequestAuthV1>,
    ) -> Result<OprfKeyId, WorldIdRequestAuthError> {
        // check action prefix is set to 0x01 or 0x02
        let action = FieldElement::from(request.auth.action);
        if !action.is_valid_for_session(SessionFeType::OprfSeed)
            && !action.is_valid_for_session(SessionFeType::Action)
        {
            return Err(WorldIdRequestAuthError::InvalidActionSession);
        }

        // check the RP nonce signature
        let msg = world_id_primitives::rp::compute_rp_signature_msg(
            request.auth.nonce,
            request.auth.current_time_stamp,
            request.auth.expiration_timestamp,
            // Note that for this nullifier route, the requested action is NEVER signed
            None,
        );

        self.0.verify(&msg, request).await
    }
}

#[async_trait]
impl OprfRequestAuthenticator for SessionOprfRequestAuthenticator {
    type RequestAuth = NullifierOprfRequestAuthV1;

    #[instrument(level = "debug", skip_all)]
    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, OprfRequestAuthenticatorError> {
        Ok(self.authenticate_inner(request).await?)
    }
}
