use alloy::{
    primitives::{Address, Bytes},
    sol_types::SolCall as _,
};
use taceo_nodes_common::web3::{self, erc165::ERC165ConfirmError};
use tracing::instrument;
use world_id_primitives::{RequestVersion, oprf::NullifierOprfRequestAuthV1};

use crate::auth::{
    rp_module::{RelyingParty, RpAccountType, RpModuleError},
    wip101::IWIP101::IWIP101Instance,
};

#[cfg(test)]
pub(crate) mod tests;

const SESSION_EFFIGY: ark_babyjubjub::Fq =
    ark_ff::MontFp!("904625697166532776746648320380374280103671755200316906558262375061821325312");

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
);

impl RelyingParty {
    pub(crate) async fn verify_wip101(
        &self,
        action: Option<ark_babyjubjub::Fq>,
        auth: &NullifierOprfRequestAuthV1,
        rpc_provider: &web3::RpcProvider,
    ) -> Result<(), RpModuleError> {
        let iwip101 = IWIP101Instance::new(self.signer, rpc_provider.http());

        // To not transmit the action to the verifier contract, we build an effigy that highlights that this is a session action
        let action = action.unwrap_or(SESSION_EFFIGY);
        let result = iwip101
            .verifyRpRequest(
                RequestVersion::V1 as u8,
                auth.nonce.into(),
                auth.current_time_stamp,
                auth.expiration_timestamp,
                action.into(),
                Bytes::new(),
            )
            .call()
            .await;
        match result {
            Ok(x) if x == SUCCESS_MAGIC_VALUE => Ok(()),
            Ok(_) => Err(RpModuleError::WIP101VerificationFailed(None)),
            Err(alloy::contract::Error::UnknownFunction(_))
            | Err(alloy::contract::Error::UnknownSelector(_)) => {
                Err(RpModuleError::Wip101IncompatibleRpSigner)
            }
            Err(err) => {
                if let Some(IWIP101::RpInvalidRequest { code }) =
                    err.as_decoded_error::<IWIP101::RpInvalidRequest>()
                {
                    Err(RpModuleError::WIP101VerificationFailed(Some(code)))
                } else if let Some(x) = err.as_revert_data() {
                    if x.is_empty() {
                        // empty revert reason - most likely this contract reported it supports WIP101 without actually supporting it
                        Err(RpModuleError::Wip101IncompatibleRpSigner)
                    } else {
                        // most likely we got some specific revert reason that was not the agreed RpInvalidRequest
                        Err(RpModuleError::Wip101CustomRevert)
                    }
                } else {
                    Err(RpModuleError::Internal(eyre::eyre!(
                        "Error during WIP101 verification: {err},{err:?}"
                    )))
                }
            }
        }
    }
}

#[instrument(level = "debug", skip_all, fields(signer=%signer))]
pub(crate) async fn account_check(
    signer: Address,
    rpc_provider: &web3::RpcProvider,
) -> eyre::Result<RpAccountType> {
    tracing::trace!("performing wip101 check on {signer}");
    let erc165_check = rpc_provider
        .erc165_supports_interface(signer, [IWIP101::verifyRpRequestCall::SELECTOR])
        .await;
    match erc165_check {
        Ok(_) => Ok(RpAccountType::Contract),
        Err(ERC165ConfirmError::NotAContract) => Ok(RpAccountType::Eoa),
        Err(ERC165ConfirmError::Unsupported) => Ok(RpAccountType::IncompatibleWip101),
        Err(err) => eyre::bail!(err),
    }
}
