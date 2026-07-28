use std::{future::Future, pin::Pin, str::FromStr, sync::Arc};

use alloy::{
    primitives::{B256, Bytes, U256, hex, keccak256},
    sol_types::{SolCall, SolValue},
};
use anchor_client::{
    Client, ClientError, Cluster, Instruction, Program,
    anchor_lang::{InstructionData, ToAccountMetas, prelude::Pubkey, system_program},
};
use eyre::Result;
use solana_keypair::{Keypair, Signer};
use world_id_solana as satellite_program;

use crate::{
    bindings::{ICommitment, IWorldIDSource},
    primitives::{ChainCommitment, U160},
    satellite::Satellite,
};

const CONFIG_SEED: &[u8] = b"config";
const ROOT_SEED: &[u8] = b"root";
const ISSUER_SEED: &[u8] = b"issuer";
const OPRF_SEED: &[u8] = b"oprf";
const GATEWAY_SEED: &[u8] = b"gateway";

/// A permissioned Solana satellite backed by the Anchor World ID program.
///
/// The relay operator signs as an authorized gateway. Each World Chain
/// `ChainCommitted` payload is decoded client-side and mapped into the
/// equivalent Solana state update instructions; each instruction folds its
/// own commitment (including the World Chain block hash it was proven
/// against) into the satellite's on-chain keccak chain head itself, so there
/// is no separate "assert the chain head" instruction to build here.
pub struct SolanaPermissionedSatellite {
    name: String,
    chain_id: u64,
    program: Program<Arc<Keypair>>,
    gateway: Pubkey,
    program_id: Pubkey,
    config: Pubkey,
    gateway_authorization: Pubkey,
}

impl SolanaPermissionedSatellite {
    /// Creates a new Solana permissioned satellite.
    pub fn new(
        name: impl Into<String>,
        destination_chain_id: u64,
        rpc_url: &str,
        program_id: Pubkey,
        gateway_keypair: Keypair,
    ) -> Result<Self> {
        let gateway = gateway_keypair.pubkey();
        let cluster = Cluster::from_str(rpc_url)
            .map_err(|e| eyre::eyre!("failed to parse Solana RPC URL: {e}"))?;
        let client = Client::new(cluster, Arc::new(gateway_keypair));
        let program = client.program(program_id)?;
        let (config, _) = Pubkey::find_program_address(&[CONFIG_SEED], &program_id);
        let (gateway_authorization, _) =
            Pubkey::find_program_address(&[GATEWAY_SEED, gateway.as_ref()], &program_id);

        Ok(Self {
            name: name.into(),
            chain_id: destination_chain_id,
            program,
            gateway,
            program_id,
            config,
            gateway_authorization,
        })
    }

    /// Decodes a World Chain commitment into Solana satellite instructions.
    pub fn decode_instructions(&self, commitment: &ChainCommitment) -> Result<Vec<Instruction>> {
        let commits = Vec::<IWorldIDSource::Commitment>::abi_decode_params(
            commitment.commitment_payload.as_ref(),
        )?;
        let mut instructions = Vec::with_capacity(commits.len());

        for commit in commits {
            instructions.push(self.decode_commitment_data(commit.blockHash, commit.data.as_ref())?);
        }

        Ok(instructions)
    }

    fn decode_commitment_data(&self, block_hash: B256, data: &[u8]) -> Result<Instruction> {
        let selector: [u8; 4] = data
            .get(..4)
            .ok_or_else(|| eyre::eyre!("empty commitment payload"))?
            .try_into()
            .expect("selector slice length is fixed");
        let block_hash = b256_word(block_hash);

        match selector {
            ICommitment::updateRootCall::SELECTOR => {
                let call = ICommitment::updateRootCall::abi_decode(data)?;
                let root = u256_word(call._0);
                let timestamp = u256_to_i64(call._1)?;
                let proof_id = b256_word(call._2);
                Ok(self.update_root_instruction(root, timestamp, proof_id, block_hash))
            }
            ICommitment::setIssuerPubkeyCall::SELECTOR => {
                let call = ICommitment::setIssuerPubkeyCall::abi_decode(data)?;
                Ok(self.set_issuer_pubkey_instruction(
                    call._0,
                    u256_word(call._1),
                    u256_word(call._2),
                    b256_word(call._3),
                    block_hash,
                ))
            }
            ICommitment::setOprfKeyCall::SELECTOR => {
                let call = ICommitment::setOprfKeyCall::abi_decode(data)?;
                Ok(self.set_oprf_key_instruction(
                    u160_word20(call._0),
                    u256_word(call._1),
                    u256_word(call._2),
                    b256_word(call._3),
                    block_hash,
                ))
            }
            _ => Err(eyre::eyre!(
                "unsupported Solana satellite commitment selector 0x{}",
                hex::encode(selector)
            )),
        }
    }

    fn update_root_instruction(
        &self,
        root: [u8; 32],
        timestamp: i64,
        proof_id: [u8; 32],
        block_hash: [u8; 32],
    ) -> Instruction {
        let (root_state, _) = Pubkey::find_program_address(&[ROOT_SEED, &root], &self.program_id);
        anchor_instruction(
            self.program_id,
            satellite_program::accounts::GatewayUpdateRoot {
                config: self.config,
                gateway: self.gateway,
                gateway_authorization: self.gateway_authorization,
                root_state,
                system_program: system_program::ID,
            },
            satellite_program::instruction::UpdateRoot {
                root,
                timestamp,
                proof_id,
                block_hash,
            },
        )
    }

    fn set_issuer_pubkey_instruction(
        &self,
        issuer_schema_id: u64,
        x: [u8; 32],
        y: [u8; 32],
        proof_id: [u8; 32],
        block_hash: [u8; 32],
    ) -> Instruction {
        let seed = key20_from_u64(issuer_schema_id);
        let (issuer_state, _) =
            Pubkey::find_program_address(&[ISSUER_SEED, &seed], &self.program_id);
        anchor_instruction(
            self.program_id,
            satellite_program::accounts::GatewaySetIssuerPubkey {
                config: self.config,
                gateway: self.gateway,
                gateway_authorization: self.gateway_authorization,
                issuer_state,
                system_program: system_program::ID,
            },
            satellite_program::instruction::SetIssuerPubkey {
                issuer_schema_id,
                x,
                y,
                proof_id,
                block_hash,
            },
        )
    }

    fn set_oprf_key_instruction(
        &self,
        rp_id: [u8; 20],
        x: [u8; 32],
        y: [u8; 32],
        proof_id: [u8; 32],
        block_hash: [u8; 32],
    ) -> Instruction {
        let (oprf_state, _) = Pubkey::find_program_address(&[OPRF_SEED, &rp_id], &self.program_id);
        anchor_instruction(
            self.program_id,
            satellite_program::accounts::GatewaySetOprfKey {
                config: self.config,
                gateway: self.gateway,
                gateway_authorization: self.gateway_authorization,
                oprf_state,
                system_program: system_program::ID,
            },
            satellite_program::instruction::SetOprfKey {
                rp_id,
                x,
                y,
                proof_id,
                block_hash,
            },
        )
    }
}

impl Satellite for SolanaPermissionedSatellite {
    fn name(&self) -> &str {
        &self.name
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// This bounds how many *World Chain events* get merged into one
    /// `ChainCommitment` before `relay()` decodes and submits it -- not the
    /// Solana transaction size limit directly. `relay()` submits one Solana
    /// instruction per transaction regardless of how many are decoded from a
    /// single commitment, so this is just an efficiency knob for the merge
    /// step, not a correctness one. See `relay()`'s doc comment for why the
    /// actual size limit has to be enforced post-decode, on instruction
    /// count, not here on event count.
    fn max_commitments_per_relay(&self) -> usize {
        20
    }

    fn remote_chain_head<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<B256>> + Send + 'a>> {
        Box::pin(async move {
            match self
                .program
                .account::<satellite_program::Config>(self.config)
                .await
            {
                Ok(config) => Ok(B256::from(config.latest_chain_head)),
                Err(ClientError::AccountNotFound) => Ok(B256::ZERO),
                Err(error) => Err(error.into()),
            }
        })
    }

    fn build_proof<'a>(
        &'a self,
        commitment: &'a ChainCommitment,
    ) -> Pin<Box<dyn Future<Output = Result<(Bytes, Bytes)>> + Send + 'a>> {
        Box::pin(async move { Ok((Bytes::new(), commitment.commitment_payload.clone())) })
    }

    fn relay<'a>(
        &'a self,
        commitment: &'a ChainCommitment,
    ) -> Pin<Box<dyn Future<Output = Result<B256>> + Send + 'a>> {
        Box::pin(async move {
            let instructions = self.decode_instructions(commitment)?;

            // `max_commitments_per_relay` bounds how many *World Chain
            // events* get merged into one `commitment` -- but a single event
            // can itself bundle multiple individual commits (root + issuer +
            // oprf), each becoming its own Solana instruction here. So the
            // real per-transaction size limit has to be enforced on the
            // decoded instruction count, not the merged-event count above
            // this call. One instruction per transaction is the safe,
            // unconditionally-correct choice: even a single bare instruction
            // plus anchor_client's real (larger than our own instructions
            // alone) versioned-transaction framing has landed reliably
            // against live devnet, whereas batches of 3-4 have intermittently
            // overflowed Solana's 1232-byte limit depending on which commit
            // kinds happened to be bundled together.
            let mut last_signature = None;
            for instruction in instructions {
                let signature = self
                    .program
                    .request()
                    .instruction(instruction)
                    .send()
                    .await?;
                tracing::info!(%signature, "submitted Solana satellite transaction");
                last_signature = Some(signature);
            }

            let signature =
                last_signature.ok_or_else(|| eyre::eyre!("no instructions to relay"))?;
            Ok(keccak256(signature.to_string().as_bytes()))
        })
    }
}

fn anchor_instruction(
    program_id: Pubkey,
    accounts: impl ToAccountMetas,
    args: impl InstructionData,
) -> Instruction {
    Instruction {
        program_id,
        accounts: accounts.to_account_metas(None),
        data: args.data(),
    }
}

fn b256_word(value: B256) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(value.as_slice());
    out
}

fn u256_word(value: U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

fn u256_to_i64(value: U256) -> Result<i64> {
    let limbs = value.as_limbs();
    eyre::ensure!(
        limbs[1..].iter().all(|limb| *limb == 0),
        "timestamp does not fit in u64"
    );
    eyre::ensure!(limbs[0] <= i64::MAX as u64, "timestamp does not fit in i64");
    Ok(limbs[0] as i64)
}

/// Zero-extends a `u64` into a big-endian 20-byte (160-bit) key, matching
/// `world-id-solana`'s `key20_from_u64` (used for the issuer PDA seed).
fn key20_from_u64(value: u64) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[12..].copy_from_slice(&value.to_be_bytes());
    out
}

/// Converts a full 160-bit OPRF key id into its big-endian byte
/// representation, matching `world-id-solana`'s `set_oprf_key` seed/key
/// encoding. Unlike the previous u64-only satellite schema, this accepts the
/// full `StateBridge.oprfKeyIdToPubkeyAndProofId` keyspace.
fn u160_word20(value: U160) -> [u8; 20] {
    value.to_be_bytes::<20>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::sol_types::SolCall;

    fn test_satellite() -> SolanaPermissionedSatellite {
        SolanaPermissionedSatellite::new(
            "SOLANA_LOCALNET",
            1337,
            "http://127.0.0.1:8899",
            satellite_program::ID,
            Keypair::new(),
        )
        .unwrap()
    }

    #[test]
    fn decodes_update_root_commitment() {
        let satellite = test_satellite();
        let root = U256::from(42u64);
        let proof_id = B256::from([0xAB; 32]);
        let block_hash = B256::from([0x11; 32]);
        let data = ICommitment::updateRootCall {
            _0: root,
            _1: U256::from(1234u64),
            _2: proof_id,
        }
        .abi_encode();

        let instruction = satellite.decode_commitment_data(block_hash, &data).unwrap();
        let expected_root_state = Pubkey::find_program_address(
            &[ROOT_SEED, &root.to_be_bytes::<32>()],
            &satellite_program::ID,
        )
        .0;

        assert_eq!(instruction.program_id, satellite_program::ID);
        assert_eq!(instruction.accounts[3].pubkey, expected_root_state);
        assert_eq!(
            instruction.data,
            satellite_program::instruction::UpdateRoot {
                root: root.to_be_bytes::<32>(),
                timestamp: 1234,
                proof_id: b256_word(proof_id),
                block_hash: b256_word(block_hash),
            }
            .data()
        );
    }

    #[test]
    fn decodes_issuer_pubkey_commitment() {
        let satellite = test_satellite();
        let proof_id = B256::from([0xCD; 32]);
        let block_hash = B256::from([0x22; 32]);
        let data = ICommitment::setIssuerPubkeyCall {
            _0: 7,
            _1: U256::from(11u64),
            _2: U256::from(12u64),
            _3: proof_id,
        }
        .abi_encode();

        let instruction = satellite.decode_commitment_data(block_hash, &data).unwrap();
        assert_eq!(
            instruction.data,
            satellite_program::instruction::SetIssuerPubkey {
                issuer_schema_id: 7,
                x: U256::from(11u64).to_be_bytes::<32>(),
                y: U256::from(12u64).to_be_bytes::<32>(),
                proof_id: b256_word(proof_id),
                block_hash: b256_word(block_hash),
            }
            .data()
        );
    }

    #[test]
    fn decodes_oprf_pubkey_commitment() {
        let satellite = test_satellite();
        let proof_id = B256::from([0xEF; 32]);
        let block_hash = B256::from([0x33; 32]);
        let data = ICommitment::setOprfKeyCall {
            _0: U160::from(9u64),
            _1: U256::from(21u64),
            _2: U256::from(22u64),
            _3: proof_id,
        }
        .abi_encode();

        let instruction = satellite.decode_commitment_data(block_hash, &data).unwrap();
        assert_eq!(
            instruction.data,
            satellite_program::instruction::SetOprfKey {
                rp_id: u160_word20(U160::from(9u64)),
                x: U256::from(21u64).to_be_bytes::<32>(),
                y: U256::from(22u64).to_be_bytes::<32>(),
                proof_id: b256_word(proof_id),
                block_hash: b256_word(block_hash),
            }
            .data()
        );
    }

    #[test]
    fn wide_oprf_ids_are_no_longer_rejected() {
        // Unlike the previous u64-only satellite schema, set_oprf_key now
        // accepts the full 160-bit StateBridge.oprfKeyIdToPubkeyAndProofId
        // keyspace, so ids above u64::MAX round-trip rather than erroring.
        let wide = U160::from(1u128 << 80);
        let key = u160_word20(wide);

        assert_eq!(key, wide.to_be_bytes::<20>());
    }

    /// Solana's wire-format transaction size limit (1232 raw bytes) is far
    /// smaller than what EVM chains allow, so `max_commitments_per_relay`'s
    /// generic default (64, tuned for EVM) massively overflows it here. This
    /// builds real mixed-entry transactions (matching what `relay()` actually
    /// submits) and measures their serialized size directly, rather than
    /// estimating, to pick a safe cutoff empirically.
    #[test]
    fn measures_max_commitments_that_fit_in_one_solana_transaction() {
        use solana_message::Message;
        use solana_transaction::Transaction;

        let satellite = test_satellite();
        const RAW_TX_SIZE_LIMIT: usize = 1232;

        // Cycle through the three instruction kinds to model a realistic
        // mixed batch (root updates, issuer keys, OPRF keys all bridging in
        // the same window), not a best-case single-kind batch.
        let make_ix = |i: u64| match i % 3 {
            0 => satellite.update_root_instruction(
                U256::from(i + 1).to_be_bytes::<32>(),
                1234,
                [0xAB; 32],
                [0x11; 32],
            ),
            1 => satellite.set_issuer_pubkey_instruction(
                i,
                U256::from(i).to_be_bytes::<32>(),
                U256::from(i).to_be_bytes::<32>(),
                [0xCD; 32],
                [0x22; 32],
            ),
            _ => satellite.set_oprf_key_instruction(
                u160_word20(U160::from(i)),
                U256::from(i).to_be_bytes::<32>(),
                U256::from(i).to_be_bytes::<32>(),
                [0xEF; 32],
                [0x33; 32],
            ),
        };

        let payer = satellite.gateway;
        let mut max_that_fits = 0;
        for n in 1..=20u64 {
            let instructions: Vec<_> = (0..n).map(make_ix).collect();
            let message = Message::new(&instructions, Some(&payer));
            let tx = Transaction::new_unsigned(message);
            let size = bincode::serialize(&tx).unwrap().len();

            println!("n={n} raw_bytes={size} limit={RAW_TX_SIZE_LIMIT}");
            if size <= RAW_TX_SIZE_LIMIT {
                max_that_fits = n;
            }
        }

        println!("max_commitments_per_relay that fits in one Solana transaction: {max_that_fits}");
        assert!(
            max_that_fits > 0,
            "even a single commitment instruction should fit in one transaction"
        );
    }
}
