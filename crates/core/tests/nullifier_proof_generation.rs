#![cfg(all(feature = "authenticator", feature = "issuer"))]

use std::convert::TryInto;

use alloy::{network::EthereumWallet, providers::ProviderBuilder, sol_types::SolEvent};
use ark_babyjubjub::Fq;
use ark_ec::CurveGroup;
use ark_ff::{AdditiveGroup, PrimeField};
use eddsa_babyjubjub::EdDSAPrivateKey;
use eyre::{WrapErr as _, eyre};
use rand::thread_rng;
use ruint::aliases::U256;
use taceo_oprf_client::BlindingFactor;
use taceo_oprf_core::{dlog_equality::DLogEqualityProof, oprf::BlindedOprfResponse};
use taceo_oprf_types::crypto::OprfPublicKey;
use test_utils::{
    anvil::{CredentialSchemaIssuerRegistry, WorldIDRegistry},
    fixtures::{RegistryTestContext, build_base_credential, generate_rp_fixture},
    merkle::first_leaf_merkle_path,
};

use world_id_core::{FieldElement, HashableCredential, OnchainKeyRepresentable, proof};
use world_id_primitives::{
    TREE_DEPTH, authenticator::AuthenticatorPublicKeySet,
    circuit_inputs::NullifierProofCircuitInput, merkle::MerkleInclusionProof,
    proof::SingleProofInput,
};

/// Tests and verifies a Nullifier Proof with locally deployed contracts on Anvil and
/// a simulated local vOPRF service.
#[tokio::test]
async fn test_nullifier_proof_generation() -> eyre::Result<()> {
    let query_material = proof::load_embedded_query_material(Option::<std::path::PathBuf>::None)?;
    let nullifier_material =
        proof::load_embedded_nullifier_material(Option::<std::path::PathBuf>::None)?;

    let RegistryTestContext {
        anvil,
        world_id_registry,
        oprf_key_registry: _,
        credential_registry: issuer_registry,
        issuer_private_key: issuer_sk,
        issuer_public_key: issuer_pk,
        issuer_schema_id,
        ..
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

    // Use authenticator signer to interact with the `WorldIDRegistry`
    let account_provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(authenticator_signer.clone()))
        .connect_http(
            anvil
                .endpoint()
                .parse()
                .wrap_err("invalid anvil endpoint URL")?,
        );
    let account_contract = WorldIDRegistry::new(world_id_registry, account_provider);

    // Create user's off‑chain BabyJubJub key batch and compute leaf commitment
    let user_sk = EdDSAPrivateKey::random(&mut rng);
    let key_set = AuthenticatorPublicKeySet::new(Some(vec![user_sk.public().clone()]))?;
    let leaf_commitment_fq = key_set.leaf_hash();
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
        .wrap_err("failed to fetch world id registry root from chain")?;

    assert_eq!(
        onchain_root, expected_root_u256,
        "on-chain root mismatch with locally computed root"
    );

    // Read emitted leaf index and derive the raw Merkle index (0‑based)
    let account_created = account_receipt
        .logs()
        .iter()
        .find_map(|log| WorldIDRegistry::AccountCreated::decode_log(log.inner.as_ref()).ok())
        .ok_or_else(|| eyre!("AccountCreated event not emitted"))?;

    let leaf_index: u64 = account_created
        .leafIndex
        .try_into()
        .map_err(|_| eyre!("leaf index exceeded u64 range"))?;

    // Construct a minimal credential (bound to issuerSchemaId and leaf index)
    let genesis_issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_at = genesis_issued_at + 86_400;

    let (credential, credential_sub_blinding_factor) =
        build_base_credential(issuer_schema_id, leaf_index, genesis_issued_at, expires_at);

    let credential = credential
        .sign(&issuer_sk)
        .wrap_err("failed to sign credential with issuer key")?;

    // Prepare Merkle membership witness for πR (query proof)
    let rp_fixture = generate_rp_fixture();
    let inclusion_proof = MerkleInclusionProof {
        root: expected_root_fq,
        leaf_index,
        siblings: merkle_siblings,
    };

    let signal_hash = FieldElement::from_arbitrary_raw_bytes(b"hello world!");

    // Build OPRF query context (RP id, action, nonce, timestamp)
    let oprf_public_key = OprfPublicKey::new(rp_fixture.rp_nullifier_point);

    let args = SingleProofInput::<TREE_DEPTH> {
        credential,
        inclusion_proof,
        key_set,
        key_index: 0,
        credential_sub_blinding_factor,
        rp_id: rp_fixture.world_rp_id,
        oprf_key_id: rp_fixture.oprf_key_id,
        share_epoch: rp_fixture.share_epoch.into_inner(),
        action: rp_fixture.action.into(),
        nonce: rp_fixture.nonce.into(),
        current_timestamp: rp_fixture.current_timestamp,
        expiration_timestamp: rp_fixture.expiration_timestamp,
        rp_signature: rp_fixture.signature,
        signal_hash,
        session_id_r_seed: rp_fixture.rp_session_id_r_seed,
        session_id: FieldElement::ZERO,
        genesis_issued_at_min: 0,
    };

    // Produce πR (signed OPRF query) — blinded request + query inputs
    let query_hash =
        world_id_core::proof::query_hash(args.inclusion_proof.leaf_index, args.rp_id, args.action);
    let blinding_factor = BlindingFactor::rand(&mut rng);
    let (_, query_input) = proof::oprf_request_auth(
        &args,
        &query_material,
        &user_sk,
        query_hash,
        &blinding_factor,
        &mut rng,
    )?;

    let blinded_request =
        taceo_oprf_core::oprf::client::blind_query(query_hash, blinding_factor.clone());

    // Derive blinded response C = x * B, where B is the blinded query
    let blinded_query = blinded_request.blinded_query();
    let blinded_response = (blinded_query * rp_fixture.rp_secret).into_affine();

    // Create unblinded OPRF response from blinded response and blinding factor
    let blinding_factor_prepared = blinding_factor.prepare();
    let oprf_blinded_response = BlindedOprfResponse::new(blinded_response);
    let unblinded_response = oprf_blinded_response.unblind_response(&blinding_factor_prepared);

    // Create and check Chaum‑Pedersen DLog equality proof for (K, C)
    let dlog_proof = DLogEqualityProof::proof(blinded_query, rp_fixture.rp_secret, &mut rng);

    let cred_signature = args
        .credential
        .signature
        .clone()
        .ok_or_else(|| eyre::eyre!("Credential not signed"))?;

    // Build nullifier proof input (π2 witness payload)
    let nullifier_input = NullifierProofCircuitInput::<TREE_DEPTH> {
        query_input,
        issuer_schema_id: args.credential.issuer_schema_id.into(),
        cred_pk: args.credential.issuer.pk,
        cred_hashes: [
            *args.credential.claims_hash()?,
            *args.credential.associated_data_hash,
        ],
        cred_genesis_issued_at: args.credential.genesis_issued_at.into(),
        cred_genesis_issued_at_min: args.genesis_issued_at_min.into(),
        cred_expires_at: args.credential.expires_at.into(),
        cred_id: args.credential.id.into(),
        cred_sub_blinding_factor: *args.credential_sub_blinding_factor,
        cred_s: cred_signature.s,
        cred_r: cred_signature.r,
        id_commitment_r: *args.session_id_r_seed,
        id_commitment: *args.session_id,
        dlog_e: dlog_proof.e,
        dlog_s: dlog_proof.s,
        oprf_pk: oprf_public_key.inner(),
        oprf_response_blinded: blinded_response,
        oprf_response: unblinded_response,
        signal_hash: *args.signal_hash,
        current_timestamp: args.current_timestamp.into(),
    };

    // Generate witness JSON and create the Groth16 proof offline
    let (proof, public) = nullifier_material.generate_proof(&nullifier_input, &mut rng)?;

    // Verify the Groth16 proof offline
    nullifier_material
        .verify_proof(&proof, &public)
        .wrap_err("failed to verify nullifier proof offline")?;

    let nullifier = public[0];

    // Basic checks on public outputs
    assert_ne!(nullifier, Fq::ZERO);

    Ok(())
}
