//! Creates a new World ID account directly on the WorldIDRegistry contract.
//!
//! Generates a random authenticator seed, derives on-chain (SECP256K1) and
//! off-chain (EdDSA) key pairs, computes the Poseidon2 leaf hash commitment,
//! and submits a `createAccount` transaction.
//!
//! If the registry has a registration fee configured, the script will
//! automatically approve the fee token and pay the fee.
//!
//! # Usage
//!
//! ```bash
//! cd services/relay
//! cargo run --example create_account
//! ```
//!
//! Reads from the `.env` file:
//! - `WALLET_PRIVATE_KEY` — key that sends the transaction (must be funded)
//! - `WORLDCHAIN_RPC_URL` — RPC endpoint for World Chain
//! - `RELAY_CONFIG` — relay config JSON (uses `source.world_id_registry`)

use std::sync::Arc;

use alloy::{
    primitives::{Address, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolEvent as _,
};
use ark_ff::{BigInteger as _, PrimeField as _};
use ark_serialize::CanonicalSerialize as _;
use eyre::Result;
use world_id_primitives::{Signer, authenticator::AuthenticatorPublicKeySet};

sol! {
    #[sol(rpc)]
    interface IWorldIDRegistry {
        function createAccount(
            address recoveryAddress,
            address[] calldata authenticatorAddresses,
            uint256[] calldata authenticatorPubkeys,
            uint256 offchainSignerCommitment
        ) external;

        function getRegistrationFee() external view returns (uint256 fee);
        function getFeeToken() external view returns (address token);

        event RootRecorded(uint256 indexed root, uint256 timestamp);
    }

    #[sol(rpc)]
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256 remaining);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    // --- Read env ---
    let wallet_key =
        std::env::var("WALLET_PRIVATE_KEY").expect("WALLET_PRIVATE_KEY must be set in .env");
    let rpc_url =
        std::env::var("WORLDCHAIN_RPC_URL").expect("WORLDCHAIN_RPC_URL must be set in .env");
    let relay_config_str =
        std::env::var("RELAY_CONFIG").expect("RELAY_CONFIG must be set in .env");

    // Parse registry address from RELAY_CONFIG
    let relay_config: serde_json::Value = serde_json::from_str(&relay_config_str)?;
    let registry_address: Address = relay_config["source"]["world_id_registry"]
        .as_str()
        .expect("source.world_id_registry missing in RELAY_CONFIG")
        .parse()?;

    // --- Build provider with signer ---
    let signer: PrivateKeySigner = wallet_key.parse()?;
    let sender = signer.address();
    let provider = Arc::new(
        ProviderBuilder::new()
            .wallet(signer)
            .connect_http(rpc_url.parse()?),
    );

    let registry = IWorldIDRegistry::new(registry_address, provider.clone());

    // --- Handle fee approval if needed ---
    let fee = registry.getRegistrationFee().call().await?;
    if fee > U256::ZERO {
        let fee_token_addr = registry.getFeeToken().call().await?;
        let fee_token = IERC20::new(fee_token_addr, provider.clone());

        let current_allowance = fee_token
            .allowance(sender, registry_address)
            .call()
            .await?;

        if current_allowance < fee {
            println!("Fee token:   {fee_token_addr}");
            println!("Fee amount:  {fee}");
            println!("Approving max allowance for fee token...");

            let approve_receipt = fee_token
                .approve(registry_address, U256::MAX)
                .send()
                .await?
                .get_receipt()
                .await?;
            println!(
                "Approval confirmed in block {} (status: {})",
                approve_receipt.block_number.unwrap_or_default(),
                if approve_receipt.status() {
                    "success"
                } else {
                    "reverted"
                }
            );
        }
    }

    // --- Generate authenticator keys ---
    let seed: [u8; 32] = rand::random();
    let authenticator_signer = Signer::from_seed_bytes(&seed)?;

    let onchain_address = authenticator_signer.onchain_signer_address();
    let offchain_pubkey = authenticator_signer.offchain_signer_pubkey();

    // Compress EdDSA pubkey to U256 (little-endian)
    let mut compressed = Vec::new();
    offchain_pubkey
        .pk
        .serialize_compressed(&mut compressed)
        .expect("pubkey serialization should not fail");
    let pubkey_u256 = U256::from_le_slice(&compressed);

    // Compute Poseidon2 leaf hash commitment
    let mut key_set = AuthenticatorPublicKeySet::default();
    key_set.try_push(offchain_pubkey)?;
    let leaf_hash = key_set.leaf_hash();
    let le_bytes: [u8; 32] = leaf_hash.into_bigint().to_bytes_le().try_into().unwrap();
    let commitment = U256::from_le_bytes(le_bytes);

    println!("Registry:              {registry_address}");
    println!("Authenticator seed:    0x{}", hex::encode(seed));
    println!("On-chain address:      {onchain_address}");
    println!("Off-chain pubkey:      {pubkey_u256}");
    println!("Leaf hash commitment:  {commitment}");
    println!();

    // --- Send transaction ---
    println!("Sending createAccount transaction...");
    let pending = registry
        .createAccount(
            Address::ZERO, // no recovery address
            vec![onchain_address],
            vec![pubkey_u256],
            commitment,
        )
        .send()
        .await?;
    let tx_hash = *pending.tx_hash();
    let receipt = pending.get_receipt().await?;
    println!("Transaction hash:  {tx_hash}");
    println!(
        "Confirmed in block {} (status: {})",
        receipt.block_number.unwrap_or_default(),
        if receipt.status() {
            "success"
        } else {
            "reverted"
        }
    );

    // --- Extract RootRecorded event ---
    let mut root = U256::ZERO;
    for log in receipt.inner.logs() {
        if let Ok(event) = IWorldIDRegistry::RootRecorded::decode_log(&log.inner) {
            root = event.root;
            println!();
            println!("RootRecorded event:");
            println!("  root:      {}", event.root);
            println!("  timestamp: {}", event.timestamp);
        }
    }

    println!();
    println!("=== Verify on satellite chains ===");
    println!("The relay should bridge this root via propagateState() -> updateRoot.");
    if root > U256::ZERO {
        println!("Query on satellite: getLatestRoot() should return {root}");
    }

    Ok(())
}
