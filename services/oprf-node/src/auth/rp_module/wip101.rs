use std::time::Duration;

use alloy::{
    primitives::{Address, Bytes, U256},
    sol_types::SolCall as _,
};
use taceo_nodes_common::web3::{self, erc165::ERC165ConfirmError};
use tracing::instrument;
use world_id_primitives::{
    FieldElement, RequestVersion,
    oprf::{NullifierOprfRequestAuthV1, WorldIdRequestAuthError},
    rp::RpRequestAuthorizationV2,
};

use crate::auth::rp_module::{RelyingParty, RpAccountType, wip101::IWIP101::IWIP101Instance};

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
    #[error("RP signer does not support WIP101 for request version {0:?}")]
    UnsupportedVersion(RequestVersion),
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
            Wip101Error::IncompatibleRpSigner | Wip101Error::UnsupportedVersion(_) => {
                Self::Wip101IncompatibleRpSigner
            }
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

#[allow(
    clippy::unreadable_literal,
    reason = "actually easier to read like this"
)]
const SUCCESS_MAGIC_VALUE: [u8; 4] = 0x35dbc8deu32.to_be_bytes();

alloy::sol!(
   #[sol(rpc)]
  interface IWIP101 is IERC165 {

      error RpInvalidRequest(uint256 code);

      function verifyRpRequest(
          uint8 version,
          uint256 nonce,
          uint64 createdAt,
          uint64 expiresAt,
          uint256 action,
          bytes calldata data
      ) external view returns (bytes4 magicValue);
  }

  struct RpRequestIntentV2 {
      uint8 requestVersion;
      uint64 rpId;
      uint160 oprfKeyId;
      uint256 nonce;
      uint64 createdAt;
      uint64 expiresAt;
      uint8 proofType;
      uint8 sessionMode;
      uint8 actionKind;
      uint256 action;
      bytes32 existingSessionSeedAuthorization;
      bytes32 detailsHash;
  }

  #[sol(rpc)]
  interface IWIP101V2 is IERC165 {
      function verifyRpRequestV2(
          RpRequestIntentV2 calldata intent,
          uint256 oprfAction,
          bytes calldata data
      ) external view returns (bytes4 magicValue);
  }
);

impl RelyingParty {
    pub(crate) async fn verify_wip101(
        &self,
        action: ark_babyjubjub::Fq,
        auth: &NullifierOprfRequestAuthV1,
        rpc_provider: &web3::HttpRpcProvider,
        timeout: Duration,
    ) -> Result<(), Wip101Error> {
        tracing::trace!("RP signer is WIP101");
        let iwip101 = IWIP101Instance::new(self.signer, rpc_provider.inner());

        if auth
            .wip101_data
            .as_ref()
            .is_some_and(|bytes| bytes.len() > MAX_AUX_DATA_SIZE)
        {
            return Err(Wip101Error::AuxDataTooLarge);
        }
        // cloning here is not a problem as we only allow up to 1kb anyways
        let auxiliary_data = auth
            .wip101_data
            .clone()
            .map(Bytes::from)
            .unwrap_or_default();
        let wip101_call = iwip101.verifyRpRequest(
            RequestVersion::V1 as u8,
            auth.nonce.into(),
            auth.created_at,
            auth.expires_at,
            action.into(),
            auxiliary_data,
        );

        match tokio::time::timeout(timeout, wip101_call.call())
            .await
            .map_err(|_| Wip101Error::VerificationTimeout)?
        {
            Ok(x) if x == SUCCESS_MAGIC_VALUE => Ok(()),
            Ok(_) => Err(Wip101Error::VerificationFailed(None)),
            Err(
                alloy::contract::Error::UnknownFunction(_)
                | alloy::contract::Error::UnknownSelector(_),
            ) => Err(Wip101Error::IncompatibleRpSigner),
            Err(err) => {
                if let Some(IWIP101::RpInvalidRequest { code }) =
                    err.as_decoded_error::<IWIP101::RpInvalidRequest>()
                {
                    Err(Wip101Error::VerificationFailed(Some(code)))
                } else if let Some(x) = err.as_revert_data() {
                    if x.is_empty() {
                        // empty revert reason - most likely this contract reported it supports WIP101 without actually supporting it
                        Err(Wip101Error::IncompatibleRpSigner)
                    } else {
                        // most likely we got some specific revert reason that was not the agreed RpInvalidRequest
                        Err(Wip101Error::CustomRevert)
                    }
                } else {
                    Err(Wip101Error::Internal(eyre::Report::from(err)))
                }
            }
        }
    }

    pub(crate) async fn verify_wip101_v2(
        &self,
        oprf_action: ark_babyjubjub::Fq,
        authorization: &RpRequestAuthorizationV2,
        auth: &NullifierOprfRequestAuthV1,
        rpc_provider: &web3::HttpRpcProvider,
        timeout: Duration,
    ) -> Result<(), Wip101Error> {
        tracing::trace!("RP signer is WIP101 V2");
        let iwip101 = IWIP101V2::IWIP101V2Instance::new(self.signer, rpc_provider.inner());
        let auxiliary_data = auxiliary_data(auth)?;
        let typed_data = authorization.typed_data();
        let intent = RpRequestIntentV2 {
            requestVersion: typed_data.requestVersion,
            rpId: typed_data.rpId,
            oprfKeyId: typed_data.oprfKeyId,
            nonce: typed_data.nonce,
            createdAt: typed_data.createdAt,
            expiresAt: typed_data.expiresAt,
            proofType: typed_data.proofType,
            sessionMode: typed_data.sessionMode,
            actionKind: typed_data.actionKind,
            action: typed_data.action,
            existingSessionSeedAuthorization: typed_data.existingSessionSeedAuthorization,
            detailsHash: typed_data.detailsHash,
        };
        let call = iwip101.verifyRpRequestV2(
            intent,
            field_element_to_u256(FieldElement::from(oprf_action)),
            auxiliary_data,
        );

        match tokio::time::timeout(timeout, call.call())
            .await
            .map_err(|_| Wip101Error::VerificationTimeout)?
        {
            Ok(x) if x == IWIP101V2::verifyRpRequestV2Call::SELECTOR => Ok(()),
            Ok(_) => Err(Wip101Error::VerificationFailed(None)),
            Err(
                alloy::contract::Error::UnknownFunction(_)
                | alloy::contract::Error::UnknownSelector(_),
            ) => Err(Wip101Error::IncompatibleRpSigner),
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

fn field_element_to_u256(value: FieldElement) -> U256 {
    U256::from_be_bytes(value.to_be_bytes())
}

#[instrument(level = "debug", skip_all, fields(signer=%signer))]
pub(crate) async fn account_check(
    signer: Address,
    rpc_provider: &web3::HttpRpcProvider,
) -> eyre::Result<RpAccountType> {
    tracing::trace!("performing wip101 check on {signer}");
    let v2_check = rpc_provider
        .erc165_supports_interface(signer, [IWIP101V2::verifyRpRequestV2Call::SELECTOR])
        .await;
    if matches!(v2_check, Err(ERC165ConfirmError::NotAContract)) {
        return Ok(RpAccountType::Eoa);
    }
    let supports_v2 = match v2_check {
        Ok(()) => true,
        Err(ERC165ConfirmError::Unsupported) => false,
        Err(ERC165ConfirmError::NotAContract) => unreachable!("handled above"),
        Err(err) => return Err(eyre::Report::from(err)),
    };

    let v1_check = rpc_provider
        .erc165_supports_interface(signer, [IWIP101::verifyRpRequestCall::SELECTOR])
        .await;
    let supports_v1 = match v1_check {
        Ok(()) => true,
        Err(ERC165ConfirmError::Unsupported) => false,
        Err(ERC165ConfirmError::NotAContract) => return Ok(RpAccountType::Eoa),
        Err(err) => return Err(eyre::Report::from(err)),
    };

    if supports_v1 || supports_v2 {
        Ok(RpAccountType::Contract {
            supports_v1,
            supports_v2,
        })
    } else {
        Ok(RpAccountType::IncompatibleWip101)
    }
}
