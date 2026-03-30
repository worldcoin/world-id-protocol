//! Registers a new issuer schema on the CredentialSchemaIssuerRegistry contract.
//!
//! Generates a random issuer schema ID, derives an EdDSA key pair for the
//! issuer's off-chain public key, and submits a `register` transaction.
//!
//! If the registry has a registration fee configured, the script will
//! automatically approve the fee token and pay the fee.
//!
//! # Usage
//!
//! ```bash
//! cd services/relay
//! cargo run --example register_issuer_schema
//! ```
//!
//! Reads from the `.env` file:
//! - `WALLET_PRIVATE_KEY` — key that sends the transaction (must be funded)
//! - `WORLDCHAIN_RPC_URL` — RPC endpoint for World Chain
//! - `RELAY_CONFIG` — relay config JSON (uses `source.issuer_schema_registry`)

use std::sync::Arc;

use alloy::{
    primitives::{Address, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolEvent as _,
};
use eyre::Result;
use world_id_primitives::Signer;

sol! {
    #[sol(rpc)]
    interface ICredentialSchemaIssuerRegistry {
        struct Pubkey {
            uint256 x;
            uint256 y;
        }

        function register(
            uint64 issuerSchemaId,
            Pubkey memory pubkey,
            address signer
        ) external returns (uint256);

        function getRegistrationFee() external view returns (uint256);
        function getFeeToken() external view returns (address);

        event IssuerSchemaRegistered(
            uint64 indexed issuerSchemaId,
            Pubkey pubkey,
            address signer,
            uint160 oprfKeyId
        );
    }

    #[sol(rpc)]
    interface IERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
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
    let relay_config_str = std::env::var("RELAY_CONFIG").expect("RELAY_CONFIG must be set in .env");

    // Parse registry address from RELAY_CONFIG
    let relay_config: serde_json::Value = serde_json::from_str(&relay_config_str)?;
    let registry_address: Address = relay_config["source"]["issuer_schema_registry"]
        .as_str()
        .expect("source.issuer_schema_registry missing in RELAY_CONFIG")
        .parse()?;

    // --- Build provider with signer ---
    let signer: PrivateKeySigner = wallet_key.parse()?;
    let sender = signer.address();
    let provider = Arc::new(
        ProviderBuilder::new()
            .wallet(signer)
            .connect_http(rpc_url.parse()?),
    );

    let registry = ICredentialSchemaIssuerRegistry::new(registry_address, provider.clone());

    // --- Handle fee approval if needed ---
    let fee = registry.getRegistrationFee().call().await?;
    if fee > U256::ZERO {
        let fee_token_addr = registry.getFeeToken().call().await?;
        let fee_token = IERC20::new(fee_token_addr, provider.clone());

        let current_allowance = fee_token.allowance(sender, registry_address).call().await?;

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

    // --- Generate issuer schema ID and key pair ---
    let issuer_schema_id: u64 = rand::random();
    let seed: [u8; 32] = rand::random();
    let issuer_signer = Signer::from_seed_bytes(&seed)?;

    let onchain_address = issuer_signer.onchain_signer_address();
    let offchain_pubkey = issuer_signer.offchain_signer_pubkey();

    // The pubkey is a BN254 affine point (x, y)
    let pubkey_x = U256::from_limbs(offchain_pubkey.pk.x.0.0);
    let pubkey_y = U256::from_limbs(offchain_pubkey.pk.y.0.0);
    let pubkey = ICredentialSchemaIssuerRegistry::Pubkey {
        x: pubkey_x,
        y: pubkey_y,
    };

    println!("Registry:              {registry_address}");
    println!("Issuer schema ID:      {issuer_schema_id}");
    println!("Issuer seed:           0x{}", hex::encode(seed));
    println!("On-chain signer:       {onchain_address}");
    println!("Pubkey x:              {pubkey_x}");
    println!("Pubkey y:              {pubkey_y}");
    println!();

    // --- Send transaction ---
    println!("Sending register transaction...");
    let pending = registry
        .register(issuer_schema_id, pubkey, onchain_address)
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

    // --- Extract events ---
    for log in receipt.inner.logs() {
        if let Ok(event) =
            ICredentialSchemaIssuerRegistry::IssuerSchemaRegistered::decode_log(&log.inner)
        {
            println!();
            println!("IssuerSchemaRegistered event:");
            println!("  issuerSchemaId: {}", event.issuerSchemaId);
            println!("  pubkey.x:       {}", event.pubkey.x);
            println!("  pubkey.y:       {}", event.pubkey.y);
            println!("  signer:         {}", event.signer);
            println!("  oprfKeyId:      {}", event.oprfKeyId);
        }
    }

    println!();
    println!("=== Verify on satellite chains ===");
    println!("The relay should bridge the following via propagateState():");
    println!(
        "  - setIssuerPubkey(issuerSchemaId={issuer_schema_id}, pubkey=({pubkey_x}, {pubkey_y}))"
    );
    println!("  - setOprfPubkey(oprfKeyId={issuer_schema_id}, ...) once OPRF key gen finalizes");
    println!();
    println!("Query on satellite: issuerSchemaIdToPubkey({issuer_schema_id})");

    Ok(())
}
