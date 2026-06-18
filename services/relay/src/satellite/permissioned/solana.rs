use std::{future::Future, pin::Pin, str::FromStr, sync::Arc};

use alloy::{
    primitives::{B256, Bytes, U256, hex, keccak256},
    sol_types::{SolCall, SolValue},
};
use anchor_client::{
    Client, ClientError, Cluster, Instruction, Program,
    anchor_lang::{InstructionData, ToAccountMetas, prelude::Pubkey, system_program},
};
use eyre::{Result, ensure};
use solana_keypair::{Keypair, Signer};
use world_id_solana_satellite as satellite_program;

use crate::{
    bindings::{ICommitment, IWorldIDSource},
    primitives::{ChainCommitment, U160},
    satellite::Satellite,
};

const CONFIG_SEED: &[u8] = b"config";
const ROOT_SEED: &[u8] = b"root";
const ISSUER_SEED: &[u8] = b"issuer";
const OPRF_SEED: &[u8] = b"oprf";

/// A permissioned Solana satellite backed by the Anchor World ID program.
///
/// The relay operator signs as the configured gateway. Each World Chain
/// `ChainCommitted` payload is decoded client-side and mapped into the
/// equivalent Solana state update instructions.
pub struct SolanaPermissionedSatellite {
    name: String,
    chain_id: u64,
    program: Program<Arc<Keypair>>,
    gateway: Pubkey,
    program_id: Pubkey,
    config: Pubkey,
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

        Ok(Self {
            name: name.into(),
            chain_id: destination_chain_id,
            program,
            gateway,
            program_id,
            config,
        })
    }

    /// Decodes a World Chain commitment into Solana satellite instructions.
    pub fn decode_instructions(&self, commitment: &ChainCommitment) -> Result<Vec<Instruction>> {
        let commits = Vec::<IWorldIDSource::Commitment>::abi_decode_params(
            commitment.commitment_payload.as_ref(),
        )?;
        let mut instructions = Vec::with_capacity(commits.len() + 1);

        for commit in commits {
            instructions.push(self.decode_commitment_data(commit.data.as_ref())?);
        }

        instructions.push(self.set_chain_head_instruction(commitment.chain_head));
        Ok(instructions)
    }

    fn decode_commitment_data(&self, data: &[u8]) -> Result<Instruction> {
        let selector: [u8; 4] = data
            .get(..4)
            .ok_or_else(|| eyre::eyre!("empty commitment payload"))?
            .try_into()
            .expect("selector slice length is fixed");

        match selector {
            ICommitment::updateRootCall::SELECTOR => {
                let call = ICommitment::updateRootCall::abi_decode(data)?;
                let root = u256_word(call._0);
                let timestamp = u256_to_i64(call._1)?;
                let proof_id = b256_word(call._2);
                Ok(self.update_root_instruction(root, timestamp, proof_id))
            }
            ICommitment::setIssuerPubkeyCall::SELECTOR => {
                let call = ICommitment::setIssuerPubkeyCall::abi_decode(data)?;
                Ok(self.set_issuer_pubkey_instruction(
                    call._0,
                    u256_word(call._1),
                    u256_word(call._2),
                    b256_word(call._3),
                ))
            }
            ICommitment::setOprfPubkeyCall::SELECTOR => {
                let call = ICommitment::setOprfPubkeyCall::abi_decode(data)?;
                let oprf_key_id = u160_to_u64(call._0)?;
                Ok(self.set_oprf_key_instruction(
                    oprf_key_id,
                    u256_word(call._1),
                    u256_word(call._2),
                    b256_word(call._3),
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
    ) -> Instruction {
        let (root_state, _) = Pubkey::find_program_address(&[ROOT_SEED, &root], &self.program_id);
        anchor_instruction(
            self.program_id,
            satellite_program::accounts::GatewayUpdateRoot {
                config: self.config,
                gateway: self.gateway,
                root_state,
                system_program: system_program::ID,
            },
            satellite_program::instruction::UpdateRoot {
                root,
                timestamp,
                proof_id,
            },
        )
    }

    fn set_chain_head_instruction(&self, chain_head: B256) -> Instruction {
        anchor_instruction(
            self.program_id,
            satellite_program::accounts::GatewaySetChainHead {
                config: self.config,
                gateway: self.gateway,
            },
            satellite_program::instruction::SetChainHead {
                chain_head: b256_word(chain_head),
            },
        )
    }

    fn set_issuer_pubkey_instruction(
        &self,
        issuer_schema_id: u64,
        x: [u8; 32],
        y: [u8; 32],
        proof_id: [u8; 32],
    ) -> Instruction {
        let seed = issuer_schema_id.to_le_bytes();
        let (issuer_state, _) =
            Pubkey::find_program_address(&[ISSUER_SEED, &seed], &self.program_id);
        anchor_instruction(
            self.program_id,
            satellite_program::accounts::GatewaySetIssuerPubkey {
                config: self.config,
                gateway: self.gateway,
                issuer_state,
                system_program: system_program::ID,
            },
            satellite_program::instruction::SetIssuerPubkey {
                issuer_schema_id,
                x,
                y,
                proof_id,
            },
        )
    }

    fn set_oprf_key_instruction(
        &self,
        oprf_key_id: u64,
        x: [u8; 32],
        y: [u8; 32],
        proof_id: [u8; 32],
    ) -> Instruction {
        let seed = oprf_key_id.to_le_bytes();
        let (oprf_state, _) = Pubkey::find_program_address(&[OPRF_SEED, &seed], &self.program_id);
        anchor_instruction(
            self.program_id,
            satellite_program::accounts::GatewaySetOprfKey {
                config: self.config,
                gateway: self.gateway,
                oprf_state,
                system_program: system_program::ID,
            },
            satellite_program::instruction::SetOprfKey {
                rp_id: oprf_key_id,
                x,
                y,
                proof_id,
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
            let mut request = self.program.request();
            for instruction in instructions {
                request = request.instruction(instruction);
            }

            let signature = request.send().await?;
            tracing::info!(%signature, "submitted Solana satellite transaction");
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
    ensure!(
        limbs[1..].iter().all(|limb| *limb == 0),
        "timestamp does not fit in u64"
    );
    ensure!(limbs[0] <= i64::MAX as u64, "timestamp does not fit in i64");
    Ok(limbs[0] as i64)
}

fn u160_to_u64(value: U160) -> Result<u64> {
    let limbs = value.as_limbs();
    ensure!(
        limbs[1..].iter().all(|limb| *limb == 0),
        "Solana satellite currently supports only u64 OPRF key ids"
    );
    Ok(limbs[0])
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
        let data = ICommitment::updateRootCall {
            _0: root,
            _1: U256::from(1234u64),
            _2: proof_id,
        }
        .abi_encode();

        let instruction = satellite.decode_commitment_data(&data).unwrap();
        let expected_root_state = Pubkey::find_program_address(
            &[ROOT_SEED, &root.to_be_bytes::<32>()],
            &satellite_program::ID,
        )
        .0;

        assert_eq!(instruction.program_id, satellite_program::ID);
        assert_eq!(instruction.accounts[2].pubkey, expected_root_state);
        assert_eq!(
            instruction.data,
            satellite_program::instruction::UpdateRoot {
                root: root.to_be_bytes::<32>(),
                timestamp: 1234,
                proof_id: b256_word(proof_id),
            }
            .data()
        );
    }

    #[test]
    fn decodes_issuer_pubkey_commitment() {
        let satellite = test_satellite();
        let proof_id = B256::from([0xCD; 32]);
        let data = ICommitment::setIssuerPubkeyCall {
            _0: 7,
            _1: U256::from(11u64),
            _2: U256::from(12u64),
            _3: proof_id,
        }
        .abi_encode();

        let instruction = satellite.decode_commitment_data(&data).unwrap();
        assert_eq!(
            instruction.data,
            satellite_program::instruction::SetIssuerPubkey {
                issuer_schema_id: 7,
                x: U256::from(11u64).to_be_bytes::<32>(),
                y: U256::from(12u64).to_be_bytes::<32>(),
                proof_id: b256_word(proof_id),
            }
            .data()
        );
    }

    #[test]
    fn decodes_oprf_pubkey_commitment() {
        let satellite = test_satellite();
        let proof_id = B256::from([0xEF; 32]);
        let data = ICommitment::setOprfPubkeyCall {
            _0: U160::from(9u64),
            _1: U256::from(21u64),
            _2: U256::from(22u64),
            _3: proof_id,
        }
        .abi_encode();

        let instruction = satellite.decode_commitment_data(&data).unwrap();
        assert_eq!(
            instruction.data,
            satellite_program::instruction::SetOprfKey {
                rp_id: 9,
                x: U256::from(21u64).to_be_bytes::<32>(),
                y: U256::from(22u64).to_be_bytes::<32>(),
                proof_id: b256_word(proof_id),
            }
            .data()
        );
    }

    #[test]
    fn rejects_wide_oprf_ids_for_current_satellite_schema() {
        let too_wide = U160::from(1u128 << 80);
        let error = u160_to_u64(too_wide).unwrap_err().to_string();

        assert!(error.contains("u64 OPRF key ids"));
    }
}
