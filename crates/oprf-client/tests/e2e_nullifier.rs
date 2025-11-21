use std::convert::TryInto;

use alloy::{network::EthereumWallet, providers::ProviderBuilder, sol_types::SolEvent};
use ark_babyjubjub::{EdwardsAffine, Fq, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, UniformRand};
use eddsa_babyjubjub::EdDSAPrivateKey;
use eyre::{eyre, WrapErr as _};
use k256::ecdsa::signature::Signer;
use oprf_client::sign_oprf_query;
use oprf_core::dlog_equality::DLogEqualityProof;
use oprf_types::ShareEpoch;
use oprf_world_types::proof_inputs::nullifier::NullifierProofInput;
use rand::{thread_rng, Rng};
use ruint::aliases::U256;
use test_utils::anvil::{AccountRegistry, CredentialSchemaIssuerRegistry, TestAnvil};
use test_utils::merkle::first_leaf_merkle_path;
use uuid::Uuid;

use world_id_core::{Authenticator, Credential, HashableCredential, OnchainKeyRepresentable};
use world_id_primitives::authenticator::AuthenticatorPublicKeySet;
use world_id_primitives::proof::SingleProofInput;
use world_id_primitives::rp::RpNullifierKey;
use world_id_primitives::{merkle::MerkleInclusionProof, rp::RpId, TREE_DEPTH};

#[tokio::test]
async fn e2e_nullifier() -> eyre::Result<()> {
    let query_material = oprf_client::load_embedded_query_material();
    let nullifier_material = oprf_client::load_embedded_nullifier_material();

    // Start Anvil and get default signer for deployments
    let anvil = TestAnvil::spawn().wrap_err("failed to launch anvil")?;
    let signer = anvil
        .signer(0)
        .wrap_err("failed to fetch default anvil signer")?;

    // Deploy proxy contracts used by the flow
    let issuer_registry = anvil
        .deploy_credential_schema_issuer_registry(signer.clone())
        .await
        .wrap_err("failed to deploy credential schema issuer registry proxy")?;
    let account_registry = anvil
        .deploy_account_registry(signer.clone())
        .await
        .wrap_err("failed to deploy account registry proxy")?;

    // Create an Issuer keypair (EdDSA on BabyJubJub) to sign credentials
    let mut rng = thread_rng();
    let issuer_sk = EdDSAPrivateKey::random(&mut rng);
    let issuer_pk = issuer_sk.public();

    // Convert Issuer pubkey to on‑chain struct shape
    let issuer_pubkey = CredentialSchemaIssuerRegistry::Pubkey {
        x: U256::from_limbs(issuer_pk.pk.x.into_bigint().0),
        y: U256::from_limbs(issuer_pk.pk.y.into_bigint().0),
    };

    // Set up a provider with the issuer (EOA) as the tx signer
    let issuer_signer = signer.clone();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(issuer_signer.clone()))
        .connect_http(
            anvil
                .endpoint()
                .parse()
                .wrap_err("invalid anvil endpoint URL")?,
        );

    let registry_contract = CredentialSchemaIssuerRegistry::new(issuer_registry, provider);

    // Register the Issuer and extract issuerSchemaId from the emitted event
    let receipt = registry_contract
        .register(issuer_pubkey.clone(), issuer_signer.address())
        .send()
        .await
        .wrap_err("failed to send issuer registration transaction")?
        .get_receipt()
        .await
        .wrap_err("failed to fetch issuer registration receipt")?;

    let issuer_schema_id = receipt
        .logs()
        .iter()
        .find_map(|log| {
            CredentialSchemaIssuerRegistry::IssuerSchemaRegistered::decode_log(log.inner.as_ref())
                .ok()
        })
        .ok_or_else(|| eyre!("IssuerSchemaRegistered event not emitted"))?
        .issuerSchemaId;

    // Verify on‑chain issuer pubkey matches the local EdDSA pubkey
    let onchain_pubkey = registry_contract
        .issuerSchemaIdToPubkey(issuer_schema_id)
        .call()
        .await
        .wrap_err("failed to fetch issuer pubkey from chain")?;

    assert_eq!(onchain_pubkey.x, issuer_pubkey.x);
    assert_eq!(onchain_pubkey.y, issuer_pubkey.y);

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

    // Prepare inputs for on‑chain createAccount call
    let offchain_pubkey = key_set[0].to_ethereum_representation()?;
    let leaf_commitment_fq = Authenticator::leaf_hash(&key_set);
    let leaf_commitment = U256::from_limbs(leaf_commitment_fq.into_bigint().0);

    // Precompute the Merkle path/root for the first insertion (index 1)
    let (merkle_siblings, expected_root_fq) = first_leaf_merkle_path(leaf_commitment_fq);
    let expected_root_u256 = U256::from_limbs(expected_root_fq.into_bigint().0);

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

    let credential = Credential::new()
        .issuer_schema_id(issuer_schema_id_u64)
        .account_id(account_index)
        .genesis_issued_at(genesis_issued_at)
        .expires_at(expires_at);

    // Issuer signs the credential (EdDSA over BabyJubJub)
    let credential = credential
        .sign(&issuer_sk)
        .wrap_err("failed to sign credential with issuer key")?;

    // Prepare Merkle membership witness for πR (query proof)
    let inclusion_proof = MerkleInclusionProof {
        root: expected_root_fq,
        account_id: account_index,
        siblings: merkle_siblings,
    };

    // Build OPRF query context (RP id, action, nonce, timestamp)
    let rp_id = RpId::new(rng.gen::<u128>());
    let share_epoch = ShareEpoch::default();
    let action = Fq::rand(&mut rng);
    let nonce = Fq::rand(&mut rng);
    let current_timestamp = genesis_issued_at + 60;

    // RP authenticates the query by signing LE(nonce) || LE(timestamp)
    let mut msg = Vec::new();
    msg.extend(nonce.into_bigint().to_bytes_le());
    msg.extend(current_timestamp.to_le_bytes());
    let rp_signing_key = k256::ecdsa::SigningKey::random(&mut rng);
    let rp_signature = rp_signing_key.sign(&msg);

    // Sample auxiliary public inputs exposed by the nullifier circuit
    let signal_hash = Fq::rand(&mut rng).into();
    let rp_session_id_r_seed = Fq::rand(&mut rng).into();

    // Emulate OPRF combination offline (single RP nullifier key)
    let rp_secret = Fr::rand(&mut rng);
    let rp_nullifier_key_point = (EdwardsAffine::generator() * rp_secret).into_affine();
    let rp_nullifier_key = RpNullifierKey::new(rp_nullifier_key_point);

    let proof_args = SingleProofInput::<TREE_DEPTH> {
        credential,
        inclusion_proof,
        key_set,
        key_index: 0,
        rp_session_id_r_seed,
        rp_id,
        share_epoch: share_epoch.into_inner(),
        action: action.into(),
        nonce: nonce.into(),
        current_timestamp,
        rp_signature,
        rp_nullifier_key,
        signal_hash,
    };

    // Produce πR (signed OPRF query) — blinded request + query inputs
    let request_id = Uuid::new_v4();
    let signed_query =
        sign_oprf_query(&proof_args, &query_material, &user_sk, request_id, &mut rng)
            .wrap_err("failed to sign oprf query")?;

    let oprf_request = signed_query.get_request();

    // Derive blinded response C = x * B, where B is the blinded query
    let blinded_query = oprf_request.blinded_query;
    let blinded_response = (blinded_query * rp_secret).into_affine();

    // Create and check Chaum‑Pedersen DLog equality proof for (K, C)
    let dlog_proof = DLogEqualityProof::proof(blinded_query, rp_secret, &mut rng);

    // Build nullifier proof input (πF witness payload)
    let nullifier_input = NullifierProofInput::<TREE_DEPTH>::new(
        signed_query.query_input().clone(),
        dlog_proof,
        rp_nullifier_key.into_inner(),
        blinded_response,
        *signal_hash,
        *rp_session_id_r_seed,
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
