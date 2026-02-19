use std::time::Duration;

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, B256, Bytes, U256, keccak256},
    providers::{DynProvider, Provider},
    sol_types::SolValue,
};
use tracing::{debug, info, warn};

use crate::{
    contracts::{self, IDisputeGame, IDisputeGameFactory, L2_TO_L1_MESSAGE_PASSER},
    error::RelayError,
    proof::{ChainCommitment, mpt},
};

/// Game status constants from OP Stack.
const _GAME_STATUS_IN_PROGRESS: u8 = 0;
const GAME_STATUS_CHALLENGER_WINS: u8 = 1;
const GAME_STATUS_DEFENDER_WINS: u8 = 2;

/// Result of finding a suitable dispute game.
#[derive(Debug)]
struct DisputeGameInfo {
    proxy: Address,
    extra_data: Bytes,
    root_claim: B256,
    l2_block_number: u64,
}

/// Builds the EthereumMPT proof attributes for relaying to the L1 gateway.
///
/// This is the most complex proof path: it waits for an OP Stack dispute game
/// covering the target WC block, then constructs MPT proofs against the
/// game's proven state root.
#[allow(clippy::too_many_arguments)]
pub async fn build_l1_proof_attributes(
    wc_provider: &DynProvider,
    l1_provider: &DynProvider,
    wc_source_address: Address,
    dispute_game_factory: Address,
    game_type: u32,
    require_finalized: bool,
    commitment: &ChainCommitment,
    poll_interval: Duration,
    timeout: Duration,
) -> Result<(Bytes, Bytes), RelayError> {
    // Step 1: Find a dispute game covering the target WC block
    let game = wait_for_dispute_game(
        l1_provider,
        dispute_game_factory,
        game_type,
        require_finalized,
        commitment.block_number,
        poll_interval,
        timeout,
    )
    .await?;

    info!(
        l2_block = game.l2_block_number,
        game_proxy = %game.proxy,
        "found suitable dispute game"
    );

    // Step 2: Get WC block at the game's L2 block number
    let wc_block = wc_provider
        .get_block_by_number(BlockNumberOrTag::Number(game.l2_block_number))
        .await
        .map_err(RelayError::Rpc)?
        .ok_or_else(|| {
            RelayError::Other(eyre::eyre!("WC block {} not found", game.l2_block_number))
        })?;

    let wc_state_root = wc_block.header.state_root;
    let wc_block_hash = wc_block.header.hash;

    // Step 3: Get L2ToL1MessagePasser storage root at the game's block
    let msg_passer_storage_root = mpt::fetch_storage_root(
        wc_provider,
        L2_TO_L1_MESSAGE_PASSER,
        BlockNumberOrTag::Number(game.l2_block_number),
    )
    .await?;

    // Step 4: Reconstruct and verify output root
    let output_root_preimage: [B256; 4] = [
        B256::ZERO,              // version
        wc_state_root,           // stateRoot
        msg_passer_storage_root, // messagePasserStorageRoot
        wc_block_hash,           // latestBlockHash
    ];

    let computed_output_root = keccak256(
        [
            output_root_preimage[0].as_slice(),
            output_root_preimage[1].as_slice(),
            output_root_preimage[2].as_slice(),
            output_root_preimage[3].as_slice(),
        ]
        .concat(),
    );

    if computed_output_root != game.root_claim {
        return Err(RelayError::OutputRootMismatch {
            expected: game.root_claim,
            actual: computed_output_root,
        });
    }

    debug!("output root verified: {}", computed_output_root);

    // Step 5: Fetch MPT proof for WorldIDSource keccak chain head
    let mpt_proof = mpt::fetch_storage_proof(
        wc_provider,
        wc_source_address,
        contracts::STATE_BRIDGE_STORAGE_SLOT,
        BlockNumberOrTag::Number(game.l2_block_number),
    )
    .await?;

    // Step 6: ABI-encode the attribute
    let attribute_data = (
        game_type,
        game.extra_data.clone(),
        output_root_preimage,
        mpt_proof.account_proof.clone(),
        mpt_proof.storage_proof.clone(),
    )
        .abi_encode();

    // Prepend the attribute selector
    let selector =
        alloy_primitives::keccak256(b"l1ProofAttributes(uint32,bytes,bytes32[4],bytes[],bytes[])");
    let mut attribute = selector[..4].to_vec();
    attribute.extend_from_slice(&attribute_data);

    let payload = commitment.commitment_payload.clone();

    Ok((Bytes::from(attribute), payload))
}

/// Polls the DisputeGameFactory until a game is found that covers the target WC block.
async fn wait_for_dispute_game(
    l1_provider: &DynProvider,
    factory_address: Address,
    target_game_type: u32,
    require_finalized: bool,
    target_wc_block: u64,
    poll_interval: Duration,
    timeout: Duration,
) -> Result<DisputeGameInfo, RelayError> {
    let deadline = tokio::time::Instant::now() + timeout;
    let factory = IDisputeGameFactory::new(factory_address, l1_provider);

    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(RelayError::DisputeGameTimeout(target_wc_block));
        }

        match find_dispute_game(
            &factory,
            l1_provider,
            target_game_type,
            require_finalized,
            target_wc_block,
        )
        .await
        {
            Ok(Some(game)) => return Ok(game),
            Ok(None) => {
                debug!(
                    target_block = target_wc_block,
                    "no suitable dispute game yet, polling again in {:?}", poll_interval
                );
                tokio::time::sleep(poll_interval).await;
            }
            Err(e) => {
                warn!(error = %e, "error scanning dispute games, retrying");
                tokio::time::sleep(poll_interval).await;
            }
        }
    }
}

/// Scans the DisputeGameFactory backwards for a game covering the target block.
async fn find_dispute_game(
    factory: &IDisputeGameFactory::IDisputeGameFactoryInstance<&DynProvider>,
    l1_provider: &DynProvider,
    target_game_type: u32,
    require_finalized: bool,
    target_wc_block: u64,
) -> Result<Option<DisputeGameInfo>, RelayError> {
    let game_count: u64 = factory.gameCount().call().await?.to::<u64>();

    if game_count == 0 {
        return Ok(None);
    }

    // Scan backwards from most recent game (max 50 games per scan to bound work)
    let scan_start = game_count.saturating_sub(1);
    let scan_end = game_count.saturating_sub(50);

    for i in (scan_end..=scan_start).rev() {
        let game_info = factory.gameAtIndex(U256::from(i)).call().await?;

        // Filter by game type
        if game_info.gameType != target_game_type {
            continue;
        }

        let game = IDisputeGame::new(game_info.proxy, l1_provider);

        // Check L2 block number
        let l2_block: u64 = game.l2BlockNumber().call().await?.to::<u64>();

        if l2_block < target_wc_block {
            break;
        }

        // Check game status
        let status: u8 = game.status().call().await?;

        if status == GAME_STATUS_CHALLENGER_WINS {
            continue;
        }

        if require_finalized && status != GAME_STATUS_DEFENDER_WINS {
            continue;
        }

        let root_claim: B256 = game.rootClaim().call().await?;
        let extra_data: Bytes = game.extraData().call().await?;

        return Ok(Some(DisputeGameInfo {
            proxy: game_info.proxy,
            extra_data,
            root_claim,
            l2_block_number: l2_block,
        }));
    }

    Ok(None)
}
