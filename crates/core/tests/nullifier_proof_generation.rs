#![cfg(all(feature = "authenticator", feature = "issuer"))]

use std::convert::TryInto;

use alloy::{network::EthereumWallet, providers::ProviderBuilder, sol_types::SolEvent};
use ark_babyjubjub::Fq;
use ark_ec::CurveGroup;
use ark_ff::{AdditiveGroup, PrimeField};
use eddsa_babyjubjub::EdDSAPrivateKey;
use eyre::{eyre, WrapErr as _};
use oprf_core::dlog_equality::DLogEqualityProof;
use rand::thread_rng;
use ruint::aliases::U256;
use test_utils::{
    anvil::{AccountRegistry, CredentialSchemaIssuerRegistry},
    fixtures::{build_base_credential, generate_rp_fixture, RegistryTestContext},
    merkle::first_leaf_merkle_path,
};
use uuid::Uuid;

use world_id_core::{oprf, proof, Authenticator, HashableCredential, OnchainKeyRepresentable};
use world_id_primitives::{
    authenticator::AuthenticatorPublicKeySet, circuit_inputs::NullifierProofCircuitInput,
    merkle::MerkleInclusionProof, proof::SingleProofInput, rp::RpNullifierKey, TREE_DEPTH,
};

/// Tests and verifies a Nullifier Proof with locally deployed contracts on Anvil and
/// a simulated local vOPRF service.
#[tokio::test]
async fn test_nullifier_proof_generation() -> eyre::Result<()> {
    let query_material = proof::load_embedded_query_material();
    let nullifier_material = proof::load_embedded_nullifier_material();

    let RegistryTestContext {
        anvil,
        account_registry,
        credential_registry: issuer_registry,
        issuer_private_key: issuer_sk,
        issuer_public_key: issuer_pk,
        issuer_schema_id,
    } = RegistryTestContext::new().await?;

    let mut rng = thread_rng();

    let signer = anvil
        .signer(0)
        .wrap_err("failed to fetch default anvil signer")?;

    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer.clone()))
        .connect_http(
            anvil
                .endpoint()
                .parse()
                .wrap_err("invalid anvil endpoint URL")?,
        );

    let registry_contract = CredentialSchemaIssuerRegistry::new(issuer_registry, provider);

    // Register the Issuer and extract issuerSchemaId from the emitted event
    // Verify on‑chain issuer pubkey matches the local EdDSA pubkey
    let onchain_pubkey = registry_contract
        .issuerSchemaIdToPubkey(issuer_schema_id)
        .call()
        .await
        .wrap_err("failed to fetch issuer pubkey from chain")?;

    let expected_pubkey = CredentialSchemaIssuerRegistry::Pubkey {
        x: U256::from_limbs(issuer_pk.pk.x.into_bigint().0),
        y: U256::from_limbs(issuer_pk.pk.y.into_bigint().0),
    };

    assert_eq!(onchain_pubkey.x, expected_pubkey.x);
    assert_eq!(onchain_pubkey.y, expected_pubkey.y);

    // Prepare recovery and authenticator signers for account creation
    let recovery_signer = anvil
        .signer(1)
        .wrap_err("failed to fetch recovery anvil signer")?;
    let authenticator_signer = anvil
        .signer(2)
        .wrap_err("failed to fetch authenticator anvil signer")?;

    // Use authenticator signer to interact with the AccountRegistry
    let account_provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(authenticator_signer.clone()))
        .connect_http(
            anvil
                .endpoint()
                .parse()
                .wrap_err("invalid anvil endpoint URL")?,
        );
    let account_contract = AccountRegistry::new(account_registry, account_provider);

    // Create user's off‑chain BabyJubJub key batch and compute leaf commitment
    let user_sk = EdDSAPrivateKey::random(&mut rng);
    let key_set = AuthenticatorPublicKeySet::new(Some(vec![user_sk.public().clone()]))?;
    let leaf_commitment_fq = Authenticator::leaf_hash(&key_set);
    let leaf_commitment = U256::from_limbs(leaf_commitment_fq.into_bigint().0);
    let (merkle_siblings, expected_root_fq) = first_leaf_merkle_path(leaf_commitment_fq);
    let expected_root_u256 = U256::from_limbs(expected_root_fq.into_bigint().0);

    // Prepare inputs for on‑chain createAccount call
    let offchain_pubkey = key_set[0].to_ethereum_representation()?;

    // Create account on‑chain and ensure transaction success
    let account_receipt = account_contract
        .createAccount(
            recovery_signer.address(),
            vec![authenticator_signer.address()],
            vec![offchain_pubkey],
            leaf_commitment,
        )
        .send()
        .await
        .wrap_err("failed to submit createAccount transaction")?
        .get_receipt()
        .await
        .wrap_err("failed to fetch createAccount receipt")?;

    if !account_receipt.status() {
        eyre::bail!("createAccount transaction reverted");
    }

    // Verify on‑chain Merkle root equals the locally recomputed root
    let onchain_root = account_contract
        .currentRoot()
        .call()
        .await
        .wrap_err("failed to fetch account registry root from chain")?;

    assert_eq!(
        onchain_root, expected_root_u256,
        "on-chain root mismatch with locally computed root"
    );

    // Read emitted account index and derive the raw Merkle index (0‑based)
    let account_created = account_receipt
        .logs()
        .iter()
        .find_map(|log| AccountRegistry::AccountCreated::decode_log(log.inner.as_ref()).ok())
        .ok_or_else(|| eyre!("AccountCreated event not emitted"))?;

    let account_index: u64 = account_created
        .accountIndex
        .try_into()
        .map_err(|_| eyre!("account index exceeded u64 range"))?;
    // Convert issuerSchemaId to field‑friendly u64 for circuits
    let issuer_schema_id_u64: u64 = issuer_schema_id
        .try_into()
        .map_err(|_| eyre!("issuer schema id exceeded u64 range"))?;

    // Construct a minimal credential (bound to issuerSchemaId and account)
    let genesis_issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_at = genesis_issued_at + 86_400;

    let credential = build_base_credential(
        issuer_schema_id_u64,
        account_index,
        genesis_issued_at,
        expires_at,
    )
    .sign(&issuer_sk)
    .wrap_err("failed to sign credential with issuer key")?;

    // Prepare Merkle membership witness for πR (query proof)
    let rp_fixture = generate_rp_fixture();
    let inclusion_proof = MerkleInclusionProof {
        root: expected_root_fq,
        account_id: account_index,
        siblings: merkle_siblings,
    };

    // Build OPRF query context (RP id, action, nonce, timestamp)
    let rp_nullifier_key = RpNullifierKey::new(rp_fixture.rp_nullifier_point);

    let proof_args = SingleProofInput::<TREE_DEPTH> {
        credential,
        inclusion_proof,
        key_set,
        key_index: 0,
        rp_session_id_r_seed: rp_fixture.rp_session_id_r_seed,
        rp_id: rp_fixture.world_rp_id,
        share_epoch: rp_fixture.share_epoch.into_inner(),
        action: rp_fixture.action.into(),
        nonce: rp_fixture.nonce.into(),
        current_timestamp: rp_fixture.current_timestamp,
        rp_signature: rp_fixture.signature,
        rp_nullifier_key,
        signal_hash: rp_fixture.signal_hash,
    };

    // Produce πR (signed OPRF query) — blinded request + query inputs
    let request_id = Uuid::new_v4();
    let signed_query =
        oprf::sign_oprf_query(&proof_args, &query_material, &user_sk, request_id, &mut rng)
            .wrap_err("failed to sign oprf query")?;

    let oprf_request = signed_query.get_request();

    // Derive blinded response C = x * B, where B is the blinded query
    let blinded_query = oprf_request.blinded_query;
    let blinded_response = (blinded_query * rp_fixture.rp_secret).into_affine();

    // Create and check Chaum‑Pedersen DLog equality proof for (K, C)
    let dlog_proof = DLogEqualityProof::proof(blinded_query, rp_fixture.rp_secret, &mut rng);

    // Build nullifier proof input (π2 witness payload)
    let nullifier_input = NullifierProofCircuitInput::<TREE_DEPTH>::new(
        signed_query.query_input().clone(),
        &dlog_proof,
        rp_nullifier_key.into_inner(),
        blinded_response,
        *rp_fixture.signal_hash,
        *rp_fixture.rp_session_id_r_seed,
        signed_query.blinding_factor().clone(),
    );

    // Generate witness JSON and create the Groth16 proof offline
    let (proof, public) = nullifier_material.generate_proof(&nullifier_input, &mut rng)?;

    // Verify the Groth16 proof offline
    nullifier_material
        .verify_proof(&proof, &public)
        .wrap_err("failed to verify nullifier proof offline")?;

    // 2 outputs, 0 is id_commitment, 1 is nullifier
    let id_commitment = public[0];
    let nullifier = public[1];

    // Basic checks on public outputs
    assert_ne!(id_commitment, Fq::ZERO);
    assert_ne!(nullifier, Fq::ZERO);

    Ok(())
}
