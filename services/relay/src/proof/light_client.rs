use std::time::Duration;

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, B256, Bytes, U256},
    providers::DynProvider,
    sol_types::SolValue,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use url::Url;

use crate::{
    contracts::{self, ILightClientGateway},
    error::RelayError,
    proof::{ChainCommitment, mpt},
};

/// Request body sent to the Helios SP1 prover service.
#[derive(Debug, Serialize)]
struct ProverRequest {
    prev_head: u64,
    prev_header: B256,
    target_block: u64,
}

/// Response from the Helios SP1 prover service.
#[derive(Debug, Deserialize)]
struct ProverResponse {
    status: ProverStatus,
    #[serde(default)]
    result: Option<ProverResult>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ProverStatus {
    Pending,
    Complete,
    Failed,
}

#[derive(Debug, Deserialize)]
struct ProverResult {
    proof: Bytes,
    new_head: u64,
    new_header: B256,
    execution_state_root: B256,
    execution_block_number: u64,
    sync_committee_hash: B256,
    next_sync_committee_hash: B256,
}

/// Request ID returned when submitting a proof request.
#[derive(Debug, Deserialize)]
struct ProverSubmitResponse {
    request_id: String,
}

/// Builds the LightClient (Helios/SP1) proof attributes for relaying to a destination gateway.
///
/// Two-hop proof: the SP1 proof verifies L1 consensus, then MPT proves the L1
/// bridge's chain head against the verified L1 state root.
pub async fn build_light_client_proof_attributes(
    l1_provider: &DynProvider,
    dest_provider: &DynProvider,
    l1_bridge_address: Address,
    gateway_address: Address,
    helios_prover_url: &Url,
    commitment: &ChainCommitment,
) -> Result<(Bytes, Bytes), RelayError> {
    // Step 1: Read current on-chain state from the LightClient gateway
    let gateway = ILightClientGateway::new(gateway_address, dest_provider);

    let current_head: u64 = gateway.head().call().await?.to::<u64>();

    let current_header: B256 = gateway.headers(U256::from(current_head)).call().await?;

    info!(
        current_head,
        current_header = %current_header,
        "read LightClient gateway state"
    );

    // Step 2: Request SP1 proof from external prover
    let prover_result = request_sp1_proof(
        helios_prover_url,
        current_head,
        current_header,
        commitment.block_number,
    )
    .await?;

    info!(
        new_head = prover_result.new_head,
        execution_block = prover_result.execution_block_number,
        "SP1 proof generated"
    );

    // Step 3: Fetch L1 MPT proof for the L1 bridge's keccak chain head
    let l1_mpt_proof = mpt::fetch_storage_proof(
        l1_provider,
        l1_bridge_address,
        contracts::STATE_BRIDGE_STORAGE_SLOT,
        BlockNumberOrTag::Number(prover_result.execution_block_number),
    )
    .await?;

    // Step 4: ABI-encode the attribute
    // Use abi_encode_params() (not abi_encode()) so the tuple components are encoded
    // as separate ABI parameters — matching Solidity's abi.decode(proof, (...)).
    let attribute_data = (
        prover_result.proof.clone(),
        U256::from(prover_result.new_head),
        prover_result.new_header,
        prover_result.execution_state_root,
        U256::from(prover_result.execution_block_number),
        prover_result.sync_committee_hash,
        prover_result.next_sync_committee_hash,
        l1_mpt_proof.account_proof.clone(),
        l1_mpt_proof.storage_proof.clone(),
    )
        .abi_encode_params();

    // Prepend selector
    let selector = alloy_primitives::keccak256(
        b"zkProofGatewayAttributes(bytes,uint256,bytes32,bytes32,uint256,bytes32,bytes32,bytes[],bytes[])",
    );
    let mut attribute = selector[..4].to_vec();
    attribute.extend_from_slice(&attribute_data);

    let payload = commitment.commitment_payload.clone();

    Ok((Bytes::from(attribute), payload))
}

/// Submits a proof request to the Helios prover and polls until completion.
async fn request_sp1_proof(
    prover_url: &Url,
    prev_head: u64,
    prev_header: B256,
    target_block: u64,
) -> Result<ProverResult, RelayError> {
    let client = reqwest::Client::new();

    let submit_url = prover_url
        .join("prove")
        .map_err(|e| RelayError::Prover(format!("invalid prover URL: {e}")))?;

    let request = ProverRequest {
        prev_head,
        prev_header,
        target_block,
    };

    let submit_response: ProverSubmitResponse = client
        .post(submit_url)
        .json(&request)
        .send()
        .await
        .map_err(|e| RelayError::Prover(format!("prover submit failed: {e}")))?
        .error_for_status()
        .map_err(|e| RelayError::Prover(format!("prover returned error: {e}")))?
        .json()
        .await
        .map_err(|e| RelayError::Prover(format!("prover response decode failed: {e}")))?;

    debug!(request_id = %submit_response.request_id, "SP1 proof request submitted");

    // Poll for completion
    let status_url = prover_url
        .join(&format!("status/{}", submit_response.request_id))
        .map_err(|e| RelayError::Prover(format!("invalid prover URL: {e}")))?;

    let poll_interval = Duration::from_secs(30);
    let timeout = Duration::from_secs(3600);
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(RelayError::ProverTimeout(timeout));
        }

        tokio::time::sleep(poll_interval).await;

        let response: ProverResponse = client
            .get(status_url.clone())
            .send()
            .await
            .map_err(|e| RelayError::Prover(format!("prover poll failed: {e}")))?
            .error_for_status()
            .map_err(|e| RelayError::Prover(format!("prover returned error: {e}")))?
            .json()
            .await
            .map_err(|e| RelayError::Prover(format!("prover response decode failed: {e}")))?;

        match response.status {
            ProverStatus::Complete => {
                return response.result.ok_or_else(|| {
                    RelayError::Prover("prover returned complete but no result".into())
                });
            }
            ProverStatus::Failed => {
                return Err(RelayError::Prover("SP1 proof generation failed".into()));
            }
            ProverStatus::Pending => {
                debug!(
                    request_id = %submit_response.request_id,
                    "SP1 proof still pending"
                );
            }
        }
    }
}
