use std::time::Duration;

use alloy::{
    network::TransactionBuilder as _,
    primitives::{Address, Bytes, U256},
    providers::Provider as _,
    rpc::types::TransactionRequest,
    sol_types::SolCall as _,
};
use taceo_nodes_common::web3::{self, erc165::ERC165ConfirmError};
use tracing::instrument;
use world_id_primitives::{
    FieldElement,
    oprf::{NullifierOprfRequestAuthV1, WorldIdRequestAuthError},
    rp::{IWIP101, RpRequestAuthorization},
};

use crate::auth::rp_module::{RelyingParty, RpAccountType};

#[cfg(test)]
pub(crate) mod tests;

/// WIP101-specific authentication failures.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Wip101Error {
    #[error("Auxiliary data must be empty with EOA backed signer")]
    AuxDataOnEoa,
    #[error("Auxiliary data for WIP101 contract too large")]
    AuxDataTooLarge,
    #[error("RP signer is a contract but does not conform to WIP101")]
    IncompatibleRpSigner,
    #[error("Ran into timeout while verifying RP signature")]
    VerificationTimeout,
    #[error("RP signer contract reverted with custom error")]
    CustomRevert,
    #[error("RP signer contract reverts with code: {0:?}")]
    VerificationFailed(Option<U256>),
    #[error(transparent)]
    Internal(#[from] eyre::Report),
}

impl From<&Wip101Error> for WorldIdRequestAuthError {
    fn from(value: &Wip101Error) -> Self {
        match value {
            Wip101Error::AuxDataOnEoa => Self::Wip101AuxDataOnEoa,
            Wip101Error::AuxDataTooLarge => Self::Wip101AuxDataTooLarge,
            Wip101Error::IncompatibleRpSigner => Self::Wip101IncompatibleRpSigner,
            Wip101Error::VerificationTimeout => Self::Wip101VerificationTimeout,
            Wip101Error::CustomRevert => Self::Wip101CustomRevert,
            Wip101Error::VerificationFailed(code) => Self::Wip101VerificationFailed(*code),
            Wip101Error::Internal(_) => Self::Internal,
        }
    }
}

impl From<Wip101Error> for WorldIdRequestAuthError {
    fn from(value: Wip101Error) -> Self {
        Self::from(&value)
    }
}

/// Max size of the auxiliary data according to WIP101.
const MAX_AUX_DATA_SIZE: usize = 1024;

impl RelyingParty {
    pub(crate) async fn verify_wip101(
        &self,
        oprf_action: ark_babyjubjub::Fq,
        authorization: &RpRequestAuthorization,
        auth: &NullifierOprfRequestAuthV1,
        rpc_provider: &web3::HttpRpcProvider,
        timeout: Duration,
    ) -> Result<(), Wip101Error> {
        tracing::trace!("RP signer is WIP101");
        // The intent is the signed authorization payload itself, so a contract-backed RP cannot be
        // handed a different request than an EOA-backed RP signs.
        let call = IWIP101::verifyRpRequestCall {
            intent: authorization.typed_data(),
            oprfAction: FieldElement::from(oprf_action).into(),
            data: auxiliary_data(auth)?,
        };
        let request = TransactionRequest::default()
            .with_to(self.signer)
            .with_input(call.abi_encode());

        let verification = async {
            let returned = rpc_provider
                .inner()
                .call(request)
                .await
                .map_err(alloy::contract::Error::from)?;
            if returned.is_empty() {
                return Ok(None);
            }
            IWIP101::verifyRpRequestCall::abi_decode_returns(&returned)
                .map(Some)
                .map_err(alloy::contract::Error::from)
        };

        match tokio::time::timeout(timeout, verification)
            .await
            .map_err(|_| Wip101Error::VerificationTimeout)?
        {
            Ok(Some(x)) if x == IWIP101::verifyRpRequestCall::SELECTOR => Ok(()),
            Ok(Some(_)) => Err(Wip101Error::VerificationFailed(None)),
            Ok(None) => Err(Wip101Error::IncompatibleRpSigner),
            Err(err) => {
                if let Some(IWIP101::RpInvalidRequest { code }) =
                    err.as_decoded_error::<IWIP101::RpInvalidRequest>()
                {
                    Err(Wip101Error::VerificationFailed(Some(code)))
                } else if let Some(data) = err.as_revert_data() {
                    if data.is_empty() {
                        Err(Wip101Error::IncompatibleRpSigner)
                    } else {
                        Err(Wip101Error::CustomRevert)
                    }
                } else {
                    Err(Wip101Error::Internal(eyre::Report::from(err)))
                }
            }
        }
    }
}

fn auxiliary_data(auth: &NullifierOprfRequestAuthV1) -> Result<Bytes, Wip101Error> {
    if auth
        .wip101_data
        .as_ref()
        .is_some_and(|bytes| bytes.len() > MAX_AUX_DATA_SIZE)
    {
        return Err(Wip101Error::AuxDataTooLarge);
    }
    Ok(auth
        .wip101_data
        .clone()
        .map(Bytes::from)
        .unwrap_or_default())
}

#[instrument(level = "debug", skip_all, fields(signer=%signer))]
pub(crate) async fn account_check(
    signer: Address,
    rpc_provider: &web3::HttpRpcProvider,
) -> eyre::Result<RpAccountType> {
    tracing::trace!("performing wip101 check on {signer}");
    let interface_check = rpc_provider
        .erc165_supports_interface(signer, [IWIP101::verifyRpRequestCall::SELECTOR])
        .await;
    match interface_check {
        Ok(()) => Ok(RpAccountType::Contract),
        Err(ERC165ConfirmError::Unsupported) => Ok(RpAccountType::IncompatibleWip101),
        Err(ERC165ConfirmError::NotAContract) => Ok(RpAccountType::Eoa),
        Err(err) => Err(eyre::Report::from(err)),
    }
}
