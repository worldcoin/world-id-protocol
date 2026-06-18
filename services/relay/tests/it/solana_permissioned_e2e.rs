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
use world_id_solana_verifier::{hex_word, solidity_to_solana_compressed_proof};

const TEST_LAMPORTS: u64 = 10_000_000_000;
const ROOT_VALIDITY_WINDOW: i64 = 3600;
const MIN_EXPIRATION_THRESHOLD: i64 = 1_000_000_000;

// Ported from `contracts/test/core/Verifier.t.sol::testVerifyNullifier`.
const ROOT_CORRECT: &str = "af727d9412a9d5c73b685fd09dc39e727064e65b8269b233009edfc105f9853";
const NULLIFIER_PROOF: [&str; 4] = [
    "4906f4e17b969ef2cfc44bd96520f01a3f5c32972bca2e10b70e05e03e3d9f13",
    "d6d9a3456e9af7d8f6f78eb3380deb8c93505c062f62fa18b8ef8a2ccb55db8",
    "a92a48edeb327b190048648788de9a8eff0abed5dc93bee8881387da40571278",
    "38f52985c393efb732be8f54b5f00f7f25370ac5945de84e0d8d2f2d298866b8",
];

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

fn verifier_t_sol_nullifier_inputs() -> [[u8; 32]; 15] {
    [
        hex_word("1bae01b23e5f0ee96151331fffb0550351c52e5ee0ced452c762e120723ae702").unwrap(),
        hex_word("1").unwrap(),
        hex_word("252c8234509649bb469ecb7a7e758f306b41415f2d80d4d67967902d6f589a81").unwrap(),
        hex_word("230e4f93a5f1187639314dd25e595db06dc18de219cfaeb8cfdf81d4afe910d5").unwrap(),
        hex_word("699cfa47").unwrap(),
        hex_word("0").unwrap(),
        hex_word(ROOT_CORRECT).unwrap(),
        hex_word("1e").unwrap(),
        hex_word("1a6ccf8f70e5de68").unwrap(),
        hex_word("15d4b66e5417cb9875f6a2b5be9814dca80651d7c74b3b21685fdd494566e79f").unwrap(),
        hex_word("ac79da013272129ddceae6d20c0f579abd04b0a00160ed2be2151bf4014e8d").unwrap(),
        hex_word("187ce5ac507fe0760e95d1893cc6ebf3a115eb9adeaa355c14cc52722a2275be").unwrap(),
        hex_word("1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f").unwrap(),
        hex_word("18e3ab3d5fedc6eaa5e0d06a3a6f3dd5e0bf2d17b18b797a1cc6ff4706169d1e").unwrap(),
        hex_word("0").unwrap(),
    ]
}

fn word_to_u64(word: [u8; 32]) -> u64 {
    u64::from_be_bytes(word[24..].try_into().unwrap())
}

// Solidity source: `contracts/test/core/Verifier.t.sol::testVerifyNullifier`.
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
            root_validity_window: ROOT_VALIDITY_WINDOW,
            tree_depth: 30,
            min_expiration_threshold: MIN_EXPIRATION_THRESHOLD,
        },
    );
    svm_result(ctx.execute_instruction(init_ix, &[&gateway]))?.assert_success();

    let public_inputs = verifier_t_sol_nullifier_inputs();
    let root = U256::from_be_bytes(public_inputs[6]);
    let issuer_schema_id = word_to_u64(public_inputs[1]);
    let issuer_x = U256::from_be_bytes(public_inputs[2]);
    let issuer_y = U256::from_be_bytes(public_inputs[3]);
    let expires_at_min = word_to_u64(public_inputs[4]) as i64;
    let tree_depth = word_to_u64(public_inputs[7]);
    let rp_id = word_to_u64(public_inputs[8]);
    let oprf_x = U256::from_be_bytes(public_inputs[10]);
    let oprf_y = U256::from_be_bytes(public_inputs[11]);
    let proof_id = B256::from([0xAB; 32]);
    let commitment = make_commitment(vec![
        encode_update_root(root, 1234, proof_id),
        encode_issuer(issuer_schema_id, issuer_x, issuer_y, proof_id),
        encode_oprf(rp_id, oprf_x, oprf_y, proof_id),
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
    assert_eq!(config_state.root_validity_window, ROOT_VALIDITY_WINDOW);
    assert_eq!(config_state.tree_depth, tree_depth);

    let (root_state, _) = anchor_client::anchor_lang::prelude::Pubkey::find_program_address(
        &[b"root", &root.to_be_bytes::<32>()],
        &satellite_program::ID,
    );
    let root_account: satellite_program::RootState = ctx.get_account(&root_state)?;
    assert_eq!(root_account.root, root.to_be_bytes::<32>());
    assert_eq!(root_account.timestamp, 1234);
    assert_eq!(root_account.proof_id, *proof_id);

    let (issuer_state, _) = anchor_client::anchor_lang::prelude::Pubkey::find_program_address(
        &[b"issuer", &issuer_schema_id.to_le_bytes()],
        &satellite_program::ID,
    );
    let issuer_account: satellite_program::PubkeyState = ctx.get_account(&issuer_state)?;
    assert_eq!(issuer_account.key, issuer_schema_id);
    assert_eq!(issuer_account.x, issuer_x.to_be_bytes::<32>());
    assert_eq!(issuer_account.y, issuer_y.to_be_bytes::<32>());

    let (oprf_state, _) = anchor_client::anchor_lang::prelude::Pubkey::find_program_address(
        &[b"oprf", &rp_id.to_le_bytes()],
        &satellite_program::ID,
    );
    let oprf_account: satellite_program::PubkeyState = ctx.get_account(&oprf_state)?;
    assert_eq!(oprf_account.key, rp_id);
    assert_eq!(oprf_account.x, oprf_x.to_be_bytes::<32>());
    assert_eq!(oprf_account.y, oprf_y.to_be_bytes::<32>());

    let solana_proof = solidity_to_solana_compressed_proof(
        &NULLIFIER_PROOF.map(|value| hex_word(value).unwrap()),
    )?;
    let verify_ix = anchor_instruction(
        satellite_program::accounts::Verify {
            config,
            root_state,
            issuer_state,
            oprf_state,
        },
        satellite_program::instruction::Verify {
            args: satellite_program::VerifyArgs {
                nullifier: public_inputs[0],
                action: public_inputs[9],
                rp_id,
                nonce: public_inputs[13],
                signal_hash: public_inputs[12],
                expires_at_min,
                issuer_schema_id,
                credential_genesis_issued_at_min: public_inputs[5],
                session_id: public_inputs[14],
                proof: satellite_program::ProofExt {
                    proof_a: solana_proof.proof_a,
                    proof_b: solana_proof.proof_b,
                    proof_c: solana_proof.proof_c,
                    root: public_inputs[6],
                },
            },
        },
    );
    svm_result(ctx.execute_instruction(verify_ix, &[&gateway]))?.assert_success();

    Ok(())
}
