#![allow(unexpected_cfgs)]

//! Minimal Anchor-based Solana satellite for World ID.
//!
//! The program trusts a configured gateway signer to bridge World ID state into
//! Solana accounts. Proof verification uses Solana BN254 compressed proof bytes
//! and delegates Groth16 verification to `world-id-solana-verifier`.

use anchor_lang::prelude::*;
use world_id_solana_verifier::{SolanaCompressedProof, verify_solana_compressed_proof};

declare_id!("BxHvVSWUkStm7RsKySrzyGWV85PNF8TsGTsPEQ3PsVfK");

const CONFIG_SEED: &[u8] = b"config";
const ROOT_SEED: &[u8] = b"root";
const ISSUER_SEED: &[u8] = b"issuer";
const OPRF_SEED: &[u8] = b"oprf";

/// World ID Solana satellite program.
#[program]
pub mod world_id_solana_satellite {
    use super::*;

    /// Initializes satellite configuration.
    pub fn initialize(
        ctx: Context<Initialize>,
        owner: Pubkey,
        gateway: Pubkey,
        root_validity_window: i64,
        tree_depth: u64,
        min_expiration_threshold: i64,
    ) -> Result<()> {
        require!(owner != Pubkey::default(), SatelliteError::ZeroPubkey);
        require!(gateway != Pubkey::default(), SatelliteError::ZeroPubkey);
        require!(
            root_validity_window > 0,
            SatelliteError::InvalidRootValidityWindow
        );
        require!(tree_depth > 0, SatelliteError::InvalidTreeDepth);
        require!(
            min_expiration_threshold > 0,
            SatelliteError::InvalidMinExpirationThreshold
        );

        let config = &mut ctx.accounts.config;
        config.owner = owner;
        config.gateway = gateway;
        config.root_validity_window = root_validity_window;
        config.tree_depth = tree_depth;
        config.min_expiration_threshold = min_expiration_threshold;
        config.latest_root = [0u8; 32];
        config.latest_chain_head = [0u8; 32];
        config.bump = ctx.bumps.config;

        Ok(())
    }

    /// Updates the permissioned gateway signer.
    pub fn set_gateway(ctx: Context<SetGateway>, gateway: Pubkey) -> Result<()> {
        require!(gateway != Pubkey::default(), SatelliteError::ZeroPubkey);
        ctx.accounts.config.gateway = gateway;
        Ok(())
    }

    /// Records the latest bridged World Chain keccak head.
    pub fn set_chain_head(ctx: Context<GatewaySetChainHead>, chain_head: [u8; 32]) -> Result<()> {
        require!(chain_head != [0u8; 32], SatelliteError::InvalidChainHead);
        ctx.accounts.config.latest_chain_head = chain_head;
        Ok(())
    }

    /// Records a bridged World ID Merkle root.
    pub fn update_root(
        ctx: Context<GatewayUpdateRoot>,
        root: [u8; 32],
        timestamp: i64,
        proof_id: [u8; 32],
    ) -> Result<()> {
        require!(root != [0u8; 32], SatelliteError::InvalidRoot);
        require!(timestamp > 0, SatelliteError::InvalidTimestamp);

        ctx.accounts.config.latest_root = root;

        let state = &mut ctx.accounts.root_state;
        state.config = ctx.accounts.config.key();
        state.root = root;
        state.timestamp = timestamp;
        state.proof_id = proof_id;
        state.bump = ctx.bumps.root_state;

        Ok(())
    }

    /// Records a bridged credential issuer public key.
    pub fn set_issuer_pubkey(
        ctx: Context<GatewaySetIssuerPubkey>,
        issuer_schema_id: u64,
        x: [u8; 32],
        y: [u8; 32],
        proof_id: [u8; 32],
    ) -> Result<()> {
        require!(
            !is_zero_point(&x, &y),
            SatelliteError::UnregisteredIssuerSchemaId
        );

        let state = &mut ctx.accounts.issuer_state;
        state.config = ctx.accounts.config.key();
        state.key = issuer_schema_id;
        state.x = x;
        state.y = y;
        state.proof_id = proof_id;
        state.bump = ctx.bumps.issuer_state;

        Ok(())
    }

    /// Records a bridged OPRF public key.
    pub fn set_oprf_key(
        ctx: Context<GatewaySetOprfKey>,
        rp_id: u64,
        x: [u8; 32],
        y: [u8; 32],
        proof_id: [u8; 32],
    ) -> Result<()> {
        require!(
            !is_zero_point(&x, &y),
            SatelliteError::UnregisteredOprfKeyId
        );

        let state = &mut ctx.accounts.oprf_state;
        state.config = ctx.accounts.config.key();
        state.key = rp_id;
        state.x = x;
        state.y = y;
        state.proof_id = proof_id;
        state.bump = ctx.bumps.oprf_state;

        Ok(())
    }

    /// Verifies a uniqueness proof against bridged satellite state.
    pub fn verify(ctx: Context<Verify>, args: VerifyArgs) -> Result<()> {
        verify_proof_and_signals(&ctx.accounts, args)
    }

    /// Verifies a session proof against bridged satellite state.
    pub fn verify_session(ctx: Context<Verify>, args: VerifySessionArgs) -> Result<()> {
        verify_proof_and_signals(
            &ctx.accounts,
            VerifyArgs {
                nullifier: args.session_nullifier[0],
                action: args.session_nullifier[1],
                rp_id: args.rp_id,
                nonce: args.nonce,
                signal_hash: args.signal_hash,
                expires_at_min: args.expires_at_min,
                issuer_schema_id: args.issuer_schema_id,
                credential_genesis_issued_at_min: args.credential_genesis_issued_at_min,
                session_id: args.session_id,
                proof: args.proof,
            },
        )
    }
}

fn verify_proof_and_signals(accounts: &Verify<'_>, args: VerifyArgs) -> Result<()> {
    require_root_account(
        &accounts.root_state,
        &args.proof.root,
        accounts.config.key(),
    )?;
    require_key_account(
        &accounts.issuer_state,
        args.issuer_schema_id,
        ISSUER_SEED,
        accounts.config.key(),
    )?;
    require_key_account(
        &accounts.oprf_state,
        args.rp_id,
        OPRF_SEED,
        accounts.config.key(),
    )?;

    require!(
        accounts.root_state.root == args.proof.root,
        SatelliteError::InvalidMerkleRoot
    );
    require!(
        is_valid_root(&accounts.config, &accounts.root_state)?,
        SatelliteError::InvalidMerkleRoot
    );
    require!(
        !is_zero_point(&accounts.issuer_state.x, &accounts.issuer_state.y),
        SatelliteError::UnregisteredIssuerSchemaId
    );
    require!(
        !is_zero_point(&accounts.oprf_state.x, &accounts.oprf_state.y),
        SatelliteError::UnregisteredOprfKeyId
    );

    let now = Clock::get()?.unix_timestamp;
    require!(
        args.expires_at_min >= now - accounts.config.min_expiration_threshold,
        SatelliteError::ExpirationTooOld
    );

    let public_inputs = [
        args.nullifier,
        u64_word(args.issuer_schema_id),
        accounts.issuer_state.x,
        accounts.issuer_state.y,
        i64_word(args.expires_at_min)?,
        args.credential_genesis_issued_at_min,
        args.proof.root,
        u64_word(accounts.config.tree_depth),
        u64_word(args.rp_id),
        args.action,
        accounts.oprf_state.x,
        accounts.oprf_state.y,
        args.signal_hash,
        args.nonce,
        args.session_id,
    ];

    verify_solana_compressed_proof(&args.proof.into(), &public_inputs)
        .map_err(|_| error!(SatelliteError::ProofInvalid))
}

fn is_valid_root(config: &Config, root_state: &RootState) -> Result<bool> {
    if root_state.timestamp == 0 {
        return Ok(false);
    }
    if root_state.root == config.latest_root {
        return Ok(true);
    }

    let now = Clock::get()?.unix_timestamp;
    let expires_at = root_state
        .timestamp
        .checked_add(config.root_validity_window)
        .ok_or_else(|| error!(SatelliteError::InvalidTimestamp))?;
    Ok(now <= expires_at)
}

fn is_zero_point(x: &[u8; 32], y: &[u8; 32]) -> bool {
    *x == [0u8; 32] && *y == [0u8; 32]
}

fn require_root_account(
    root_state: &Account<'_, RootState>,
    root: &[u8; 32],
    config: Pubkey,
) -> Result<()> {
    let (expected, _) = Pubkey::find_program_address(&[ROOT_SEED, root], &crate::ID);
    require_keys_eq!(
        root_state.key(),
        expected,
        SatelliteError::InvalidStateAccount
    );
    require_keys_eq!(
        root_state.config,
        config,
        SatelliteError::InvalidStateAccount
    );
    Ok(())
}

fn require_key_account(
    key_state: &Account<'_, PubkeyState>,
    key: u64,
    seed: &[u8],
    config: Pubkey,
) -> Result<()> {
    let key_bytes = key.to_le_bytes();
    let (expected, _) = Pubkey::find_program_address(&[seed, &key_bytes], &crate::ID);
    require_keys_eq!(
        key_state.key(),
        expected,
        SatelliteError::InvalidStateAccount
    );
    require_keys_eq!(
        key_state.config,
        config,
        SatelliteError::InvalidStateAccount
    );
    require!(key_state.key == key, SatelliteError::InvalidStateAccount);
    Ok(())
}

fn u64_word(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn i64_word(value: i64) -> Result<[u8; 32]> {
    require!(value >= 0, SatelliteError::InvalidTimestamp);
    Ok(u64_word(value as u64))
}

/// Initialize accounts.
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// Satellite configuration PDA.
    #[account(init, payer = payer, space = Config::SPACE, seeds = [CONFIG_SEED], bump)]
    pub config: Account<'info, Config>,
    /// Account funding initialization.
    #[account(mut)]
    pub payer: Signer<'info>,
    /// System program.
    pub system_program: Program<'info, System>,
}

/// Gateway update accounts.
#[derive(Accounts)]
pub struct SetGateway<'info> {
    /// Satellite configuration PDA.
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = owner)]
    pub config: Account<'info, Config>,
    /// Satellite owner.
    pub owner: Signer<'info>,
}

/// Gateway root update accounts.
#[derive(Accounts)]
#[instruction(root: [u8; 32])]
pub struct GatewayUpdateRoot<'info> {
    /// Satellite configuration PDA.
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = gateway)]
    pub config: Account<'info, Config>,
    /// Permissioned gateway signer.
    #[account(mut)]
    pub gateway: Signer<'info>,
    /// Root state PDA.
    #[account(
        init_if_needed,
        payer = gateway,
        space = RootState::SPACE,
        seeds = [ROOT_SEED, root.as_ref()],
        bump
    )]
    pub root_state: Account<'info, RootState>,
    /// System program.
    pub system_program: Program<'info, System>,
}

/// Gateway chain-head update accounts.
#[derive(Accounts)]
pub struct GatewaySetChainHead<'info> {
    /// Satellite configuration PDA.
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump, has_one = gateway)]
    pub config: Account<'info, Config>,
    /// Permissioned gateway signer.
    pub gateway: Signer<'info>,
}

/// Gateway issuer key update accounts.
#[derive(Accounts)]
#[instruction(issuer_schema_id: u64)]
pub struct GatewaySetIssuerPubkey<'info> {
    /// Satellite configuration PDA.
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = gateway)]
    pub config: Account<'info, Config>,
    /// Permissioned gateway signer.
    #[account(mut)]
    pub gateway: Signer<'info>,
    /// Issuer public key state PDA.
    #[account(
        init_if_needed,
        payer = gateway,
        space = PubkeyState::SPACE,
        seeds = [ISSUER_SEED, &issuer_schema_id.to_le_bytes()],
        bump
    )]
    pub issuer_state: Account<'info, PubkeyState>,
    /// System program.
    pub system_program: Program<'info, System>,
}

/// Gateway OPRF key update accounts.
#[derive(Accounts)]
#[instruction(rp_id: u64)]
pub struct GatewaySetOprfKey<'info> {
    /// Satellite configuration PDA.
    #[account(seeds = [CONFIG_SEED], bump = config.bump, has_one = gateway)]
    pub config: Account<'info, Config>,
    /// Permissioned gateway signer.
    #[account(mut)]
    pub gateway: Signer<'info>,
    /// OPRF public key state PDA.
    #[account(
        init_if_needed,
        payer = gateway,
        space = PubkeyState::SPACE,
        seeds = [OPRF_SEED, &rp_id.to_le_bytes()],
        bump
    )]
    pub oprf_state: Account<'info, PubkeyState>,
    /// System program.
    pub system_program: Program<'info, System>,
}

/// Verification accounts.
#[derive(Accounts)]
pub struct Verify<'info> {
    /// Satellite configuration PDA.
    #[account(seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// Root state account for the proof root.
    pub root_state: Account<'info, RootState>,
    /// Issuer public key state account.
    pub issuer_state: Account<'info, PubkeyState>,
    /// OPRF public key state account.
    pub oprf_state: Account<'info, PubkeyState>,
}

/// Satellite configuration.
#[account]
pub struct Config {
    /// Satellite owner.
    pub owner: Pubkey,
    /// Permissioned gateway signer.
    pub gateway: Pubkey,
    /// Historic root validity window in seconds.
    pub root_validity_window: i64,
    /// World ID tree depth.
    pub tree_depth: u64,
    /// Minimum acceptable expiration age in seconds.
    pub min_expiration_threshold: i64,
    /// Latest bridged root.
    pub latest_root: [u8; 32],
    /// Latest bridged World Chain keccak head.
    pub latest_chain_head: [u8; 32],
    /// Config PDA bump.
    pub bump: u8,
}

impl Config {
    /// Serialized account size.
    pub const SPACE: usize = 8 + 32 + 32 + 8 + 8 + 8 + 32 + 32 + 1;
}

/// Bridged root metadata.
#[account]
pub struct RootState {
    /// Config account this state belongs to.
    pub config: Pubkey,
    /// Bridged Merkle root.
    pub root: [u8; 32],
    /// Proven timestamp.
    pub timestamp: i64,
    /// Opaque gateway proof id.
    pub proof_id: [u8; 32],
    /// Root PDA bump.
    pub bump: u8,
}

impl RootState {
    /// Serialized account size.
    pub const SPACE: usize = 8 + 32 + 32 + 8 + 32 + 1;
}

/// Bridged BabyJubJub public key metadata.
#[account]
pub struct PubkeyState {
    /// Config account this state belongs to.
    pub config: Pubkey,
    /// Issuer schema id or RP id.
    pub key: u64,
    /// Public key x-coordinate.
    pub x: [u8; 32],
    /// Public key y-coordinate.
    pub y: [u8; 32],
    /// Opaque gateway proof id.
    pub proof_id: [u8; 32],
    /// Public key PDA bump.
    pub bump: u8,
}

impl PubkeyState {
    /// Serialized account size.
    pub const SPACE: usize = 8 + 32 + 8 + 32 + 32 + 32 + 1;
}

/// Solana-compressed World ID proof plus bundled Merkle root.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofExt {
    /// Compressed G1 `A` point.
    pub proof_a: [u8; 32],
    /// Compressed G2 `B` point.
    pub proof_b: [u8; 64],
    /// Compressed G1 `C` point.
    pub proof_c: [u8; 32],
    /// Merkle root public input.
    pub root: [u8; 32],
}

impl From<ProofExt> for SolanaCompressedProof {
    fn from(value: ProofExt) -> Self {
        Self {
            proof_a: value.proof_a,
            proof_b: value.proof_b,
            proof_c: value.proof_c,
        }
    }
}

/// Uniqueness proof verification arguments.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyArgs {
    /// Nullifier public output.
    pub nullifier: [u8; 32],
    /// Action public input.
    pub action: [u8; 32],
    /// RP id.
    pub rp_id: u64,
    /// Nonce public input.
    pub nonce: [u8; 32],
    /// Signal hash public input.
    pub signal_hash: [u8; 32],
    /// Minimum credential expiration timestamp.
    pub expires_at_min: i64,
    /// Credential issuer schema id.
    pub issuer_schema_id: u64,
    /// Minimum credential genesis issuance timestamp.
    pub credential_genesis_issued_at_min: [u8; 32],
    /// Session id, zero for uniqueness proofs.
    pub session_id: [u8; 32],
    /// Solana-compressed proof plus root.
    pub proof: ProofExt,
}

/// Session proof verification arguments.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifySessionArgs {
    /// RP id.
    pub rp_id: u64,
    /// Nonce public input.
    pub nonce: [u8; 32],
    /// Signal hash public input.
    pub signal_hash: [u8; 32],
    /// Minimum credential expiration timestamp.
    pub expires_at_min: i64,
    /// Credential issuer schema id.
    pub issuer_schema_id: u64,
    /// Minimum credential genesis issuance timestamp.
    pub credential_genesis_issued_at_min: [u8; 32],
    /// Session id.
    pub session_id: [u8; 32],
    /// Session nullifier tuple `[nullifier, action]`.
    pub session_nullifier: [[u8; 32]; 2],
    /// Solana-compressed proof plus root.
    pub proof: ProofExt,
}

/// Satellite errors.
#[error_code]
pub enum SatelliteError {
    /// A required public key was zero.
    #[msg("zero public key")]
    ZeroPubkey,
    /// Root validity window must be positive.
    #[msg("invalid root validity window")]
    InvalidRootValidityWindow,
    /// Tree depth must be positive.
    #[msg("invalid tree depth")]
    InvalidTreeDepth,
    /// Minimum expiration threshold must be positive.
    #[msg("invalid minimum expiration threshold")]
    InvalidMinExpirationThreshold,
    /// Root cannot be zero.
    #[msg("invalid root")]
    InvalidRoot,
    /// Root is not valid.
    #[msg("invalid merkle root")]
    InvalidMerkleRoot,
    /// Expiration is too old.
    #[msg("expiration too old")]
    ExpirationTooOld,
    /// Issuer schema id has no bridged public key.
    #[msg("unregistered issuer schema id")]
    UnregisteredIssuerSchemaId,
    /// OPRF key id has no bridged public key.
    #[msg("unregistered oprf key id")]
    UnregisteredOprfKeyId,
    /// The Groth16 proof is invalid.
    #[msg("proof invalid")]
    ProofInvalid,
    /// Timestamp must be non-negative.
    #[msg("invalid timestamp")]
    InvalidTimestamp,
    /// State account does not match the expected PDA or config.
    #[msg("invalid state account")]
    InvalidStateAccount,
    /// Chain head cannot be zero.
    #[msg("invalid chain head")]
    InvalidChainHead,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u64_word_is_big_endian_field_word() {
        let word = u64_word(0x1a6ccf8f70e5de68);

        assert_eq!(&word[..24], &[0u8; 24]);
        assert_eq!(&word[24..], &0x1a6ccf8f70e5de68u64.to_be_bytes());
    }

    #[test]
    fn zero_point_requires_both_coordinates_zero() {
        assert!(is_zero_point(&[0u8; 32], &[0u8; 32]));
        assert!(!is_zero_point(&[1u8; 32], &[0u8; 32]));
        assert!(!is_zero_point(&[0u8; 32], &[1u8; 32]));
    }
}
