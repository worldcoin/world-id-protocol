//! E2E tests for the Solana permissioned gateway relay path.
//!
//! Uses LiteSVM as an in-process local Solana network, mirroring the way the
//! EVM relay tests spin up Anvil. The gateway signer is a funded LiteSVM test
//! account, so local tests do not depend on operator key material.

use std::path::PathBuf;

use alloy::{
    primitives::{B256, U256},
    sol_types::{SolCall, SolValue},
};
use anchor_client::anchor_lang::{InstructionData, ToAccountMetas, system_program};
use anchor_litesvm::AnchorLiteSVM;
use eyre::Result;
use solana_keypair::Signer;
use world_id_relay::{
    bindings::{ICommitment, IWorldIDSource},
    primitives::{ChainCommitment, KeccakChain, U160},
    satellite::permissioned::solana::SolanaPermissionedSatellite,
};
use world_id_solana_satellite as satellite_program;

const TEST_LAMPORTS: u64 = 10_000_000_000;

fn svm_result<T>(result: Result<T, Box<dyn std::error::Error>>) -> Result<T> {
    result.map_err(|e| eyre::eyre!("{e}"))
}

fn satellite_program_so() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/deploy/world_id_solana_satellite.so")
}

fn anchor_instruction(
    accounts: impl ToAccountMetas,
    args: impl InstructionData,
) -> anchor_client::Instruction {
    anchor_client::Instruction {
        program_id: satellite_program::ID,
        accounts: accounts.to_account_metas(None),
        data: args.data(),
    }
}

fn encode_update_root(root: U256, timestamp: u64, proof_id: B256) -> IWorldIDSource::Commitment {
    IWorldIDSource::Commitment {
        blockHash: B256::from([1u8; 32]),
        data: ICommitment::updateRootCall {
            _0: root,
            _1: U256::from(timestamp),
            _2: proof_id,
        }
        .abi_encode()
        .into(),
    }
}

fn encode_issuer(
    issuer_schema_id: u64,
    x: U256,
    y: U256,
    proof_id: B256,
) -> IWorldIDSource::Commitment {
    IWorldIDSource::Commitment {
        blockHash: B256::from([2u8; 32]),
        data: ICommitment::setIssuerPubkeyCall {
            _0: issuer_schema_id,
            _1: x,
            _2: y,
            _3: proof_id,
        }
        .abi_encode()
        .into(),
    }
}

fn encode_oprf(oprf_key_id: u64, x: U256, y: U256, proof_id: B256) -> IWorldIDSource::Commitment {
    IWorldIDSource::Commitment {
        blockHash: B256::from([3u8; 32]),
        data: ICommitment::setOprfPubkeyCall {
            _0: U160::from(oprf_key_id),
            _1: x,
            _2: y,
            _3: proof_id,
        }
        .abi_encode()
        .into(),
    }
}

fn make_commitment(commits: Vec<IWorldIDSource::Commitment>) -> ChainCommitment {
    let mut chain = KeccakChain::new(B256::ZERO, 0);
    let chain_head = chain.hash_chained(&commits);
    chain.commit_chained(&commits);
    ChainCommitment {
        chain_head,
        block_number: 1,
        chain_id: 480,
        commitment_payload: commits.abi_encode_params().into(),
        timestamp: 1234,
    }
}

#[test]
fn e2e_solana_permissioned_replays_commitment_on_local_svm() -> Result<()> {
    let program_so = satellite_program_so();
    if !program_so.exists() {
        eprintln!(
            "skipping Solana LiteSVM E2E; build {} first with `cargo build-sbf --manifest-path crates/solana-satellite/Cargo.toml --sbf-out-dir target/deploy`",
            program_so.display()
        );
        return Ok(());
    }

    let program_bytes = std::fs::read(program_so)?;
    let mut ctx = AnchorLiteSVM::build_with_program(satellite_program::ID, &program_bytes);
    let owner = svm_result(ctx.create_funded_account(TEST_LAMPORTS))?;
    let gateway = svm_result(ctx.create_funded_account(TEST_LAMPORTS))?;

    let (config, _) = anchor_client::anchor_lang::prelude::Pubkey::find_program_address(
        &[b"config"],
        &satellite_program::ID,
    );

    let init_ix = anchor_instruction(
        satellite_program::accounts::Initialize {
            config,
            payer: gateway.pubkey(),
            system_program: system_program::ID,
        },
        satellite_program::instruction::Initialize {
            owner: owner.pubkey(),
            gateway: gateway.pubkey(),
            root_validity_window: 3600,
            tree_depth: 30,
            min_expiration_threshold: 60,
        },
    );
    svm_result(ctx.execute_instruction(init_ix, &[&gateway]))?.assert_success();

    let root = U256::from(42u64);
    let issuer_x = U256::from(11u64);
    let issuer_y = U256::from(12u64);
    let oprf_x = U256::from(21u64);
    let oprf_y = U256::from(22u64);
    let proof_id = B256::from([0xAB; 32]);
    let commitment = make_commitment(vec![
        encode_update_root(root, 1234, proof_id),
        encode_issuer(7, issuer_x, issuer_y, proof_id),
        encode_oprf(9, oprf_x, oprf_y, proof_id),
    ]);

    let satellite = SolanaPermissionedSatellite::new(
        "SOLANA_LOCALNET",
        1337,
        "http://127.0.0.1:8899",
        satellite_program::ID,
        gateway.insecure_clone(),
    )?;
    let instructions = satellite.decode_instructions(&commitment)?;
    svm_result(ctx.execute_instructions(instructions, &[&gateway]))?.assert_success();

    let config_state: satellite_program::Config = ctx.get_account(&config)?;
    assert_eq!(config_state.latest_root, root.to_be_bytes::<32>());
    assert_eq!(config_state.latest_chain_head, *commitment.chain_head);

    let (root_state, _) = anchor_client::anchor_lang::prelude::Pubkey::find_program_address(
        &[b"root", &root.to_be_bytes::<32>()],
        &satellite_program::ID,
    );
    let root_state: satellite_program::RootState = ctx.get_account(&root_state)?;
    assert_eq!(root_state.root, root.to_be_bytes::<32>());
    assert_eq!(root_state.timestamp, 1234);
    assert_eq!(root_state.proof_id, *proof_id);

    let (issuer_state, _) = anchor_client::anchor_lang::prelude::Pubkey::find_program_address(
        &[b"issuer", &7u64.to_le_bytes()],
        &satellite_program::ID,
    );
    let issuer_state: satellite_program::PubkeyState = ctx.get_account(&issuer_state)?;
    assert_eq!(issuer_state.key, 7);
    assert_eq!(issuer_state.x, issuer_x.to_be_bytes::<32>());
    assert_eq!(issuer_state.y, issuer_y.to_be_bytes::<32>());

    let (oprf_state, _) = anchor_client::anchor_lang::prelude::Pubkey::find_program_address(
        &[b"oprf", &9u64.to_le_bytes()],
        &satellite_program::ID,
    );
    let oprf_state: satellite_program::PubkeyState = ctx.get_account(&oprf_state)?;
    assert_eq!(oprf_state.key, 9);
    assert_eq!(oprf_state.x, oprf_x.to_be_bytes::<32>());
    assert_eq!(oprf_state.y, oprf_y.to_be_bytes::<32>());

    Ok(())
}
