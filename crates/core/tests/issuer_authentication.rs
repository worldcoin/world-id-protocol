#![cfg(all(feature = "authenticator", feature = "issuer"))]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use ark_ff::PrimeField as _;
use eyre::{eyre, Result, WrapErr as _};
use k256::ecdsa::SigningKey;
use rand::thread_rng;
use world_id_core::primitives::Config;
use world_id_core::requests::{IssuerAuthRequest, IssuerAuthSignature, IssuerAuthVersion};
use world_id_core::{proof, Authenticator, EdDSAPrivateKey, FieldElement, HashableCredential, IssuerAuthReplayProtection, IssuerAuthVerificationContext, IssuerAuthVerifier, OnchainKeyRepresentable};
use world_id_primitives::authenticator::AuthenticatorPublicKeySet;
use world_id_primitives::merkle::AccountInclusionProof;
use world_id_primitives::TREE_DEPTH;

use test_utils::{
    fixtures::{build_base_credential, single_leaf_merkle_fixture, RegistryTestContext},
    stubs::spawn_indexer_stub,
};

use alloy::primitives::keccak256;

use test_utils::anvil::WorldIDRegistry;

fn address_from_signing_key(signing_key: &SigningKey) -> Address {
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let pubkey_bytes = encoded.as_bytes();
    let hash = keccak256(&pubkey_bytes[1..]);
    Address::from_slice(&hash.0[12..])
}

#[tokio::test]
async fn issuer_auth_request_roundtrip() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");

    let RegistryTestContext {
        anvil,
        world_id_registry,
        credential_registry,
        issuer_private_key,
        issuer_public_key,
        issuer_schema_id,
    } = RegistryTestContext::new().await?;

    let issuer_schema_id_u64 = issuer_schema_id
        .try_into()
        .map_err(|_| eyre!("issuer schema id exceeded u64 range"))?;

    // Prepare authenticator key material.
    let seed = [7u8; 32];
    let onchain_signer = PrivateKeySigner::from_bytes(&seed.into())
        .map_err(|e| eyre!("failed to init signer: {e}"))?;
    let offchain_sk = EdDSAPrivateKey::from_bytes(seed);
    let offchain_pk = offchain_sk.public();
    let key_set = AuthenticatorPublicKeySet::new(Some(vec![offchain_pk.clone()]))?;
    let leaf_commitment_fq = Authenticator::leaf_hash(&key_set);
    let leaf_commitment = U256::from_limbs(leaf_commitment_fq.into_bigint().0);
    let offchain_pubkey = offchain_pk.to_ethereum_representation()?;

    // Create account on-chain.
    let deployer = anvil
        .signer(0)
        .wrap_err("failed to fetch deployer signer")?;
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(deployer.clone()))
        .connect_http(anvil.endpoint().parse().wrap_err("invalid anvil endpoint URL")?);
    let registry = WorldIDRegistry::new(world_id_registry, provider);
    let receipt = registry
        .createAccount(
            deployer.address(),
            vec![onchain_signer.address()],
            vec![offchain_pubkey],
            leaf_commitment,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    if !receipt.status() {
        eyre::bail!("createAccount transaction reverted");
    }

    let account_created = receipt
        .logs()
        .iter()
        .find_map(|log| WorldIDRegistry::AccountCreated::decode_log(log.inner.as_ref()).ok())
        .ok_or_else(|| eyre!("AccountCreated event not emitted"))?;
    let leaf_index: u64 = account_created
        .leafIndex
        .try_into()
        .map_err(|_| eyre!("leaf index exceeded u64 range"))?;

    // Build inclusion proof and indexer stub.
    let merkle_fixture = single_leaf_merkle_fixture(vec![offchain_pk.clone()], leaf_index)?;
    let inclusion_proof = AccountInclusionProof::<{ TREE_DEPTH }>::new(
        merkle_fixture.inclusion_proof.clone(),
        merkle_fixture.key_set.clone(),
    )?;
    let (indexer_url, indexer_handle) =
        spawn_indexer_stub(leaf_index, inclusion_proof).await?;

    // Build authenticator config.
    let config = Config::new(
        Some(anvil.endpoint().to_string()),
        anvil.instance.chain_id(),
        world_id_registry,
        indexer_url,
        "http://127.0.0.1:0".to_string(),
        Vec::new(),
        1,
    )?;
    let authenticator = Authenticator::init(&seed, config).await?;

    // Prepare credential.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs();
    let credential = build_base_credential(
        issuer_schema_id_u64,
        leaf_index,
        now,
        now + 3600,
    )
    .sign(&issuer_private_key)
    .wrap_err("failed to sign credential")?;

    // Build issuer auth request with a random signer.
    let issuer_signing_key = SigningKey::random(&mut thread_rng());
    let issuer_signer = address_from_signing_key(&issuer_signing_key);
    let action = FieldElement::from_arbitrary_raw_bytes(b"credential.refresh");
    let nonce = FieldElement::from(42u64);

    let mut request = IssuerAuthRequest {
        id: "issuer_auth_req_1".to_string(),
        version: IssuerAuthVersion::V1,
        created_at: now,
        expires_at: now + 60,
        issuer_schema_id: issuer_schema_id_u64,
        issuer_registry_address: credential_registry,
        issuer_signer,
        action,
        nonce,
        signature: IssuerAuthSignature::from_bytes([0u8; 65]),
    };

    let digest = request.signing_hash(anvil.instance.chain_id());
    let (signature, recovery_id) = issuer_signing_key
        .sign_prehash_recoverable(&digest)
        .map_err(|e| eyre!("failed to sign issuer auth request: {e}"))?;
    let mut sig_bytes = [0u8; 65];
    sig_bytes[..64].copy_from_slice(&signature.to_bytes());
    sig_bytes[64] = recovery_id.to_byte();
    request.signature = IssuerAuthSignature::from_bytes(sig_bytes);

    // Generate auth proof.
    let response = authenticator
        .generate_authentication_proof(request.clone(), credential)
        .await
        .wrap_err("failed to generate issuer auth proof")?;

    // Verify auth proof.
    let vk_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../circom/OPRFQuery.vk.json");
    let vk = proof::load_query_verification_key_from_path(vk_path)?;
    let replay = IssuerAuthReplayProtection::new(
        std::time::Duration::from_secs(120),
        std::time::Duration::from_secs(30),
    );
    let verifier = IssuerAuthVerifier::new(vk, replay);
    let context = IssuerAuthVerificationContext {
        expected_schema_id: issuer_schema_id_u64,
        expected_signer: issuer_signer,
        issuer_pubkey: &issuer_public_key,
        chain_id: anvil.instance.chain_id(),
    };
    verifier.verify_with_root(
        &request,
        &response,
        context,
        true,
    )?;

    indexer_handle.abort();
    Ok(())
}
