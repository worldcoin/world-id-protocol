use std::{convert::TryInto, path::PathBuf};

use alloy::{network::EthereumWallet, providers::ProviderBuilder, sol_types::SolEvent};
use ark_babyjubjub::{EdwardsAffine, Fq, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, UniformRand};
use eddsa_babyjubjub::EdDSAPrivateKey;
use eyre::{eyre, WrapErr as _};
use k256::ecdsa::signature::Signer;
use oprf_client::{sign_oprf_query, OprfQuery};
use oprf_core::dlog_equality::DLogEqualityProof;
use oprf_types::{crypto::RpNullifierKey, RpId, ShareEpoch};
use oprf_world_types::proof_inputs::nullifier::NullifierProofInput;
use oprf_world_types::{
    MerkleMembership, MerkleRoot, UserKeyMaterial, UserPublicKeyBatch, TREE_DEPTH,
};
use oprf_zk::{
    Groth16Material, NULLIFIER_FINGERPRINT, NULLIFIER_GRAPH_BYTES, QUERY_FINGERPRINT,
    QUERY_GRAPH_BYTES,
};
use rand::{thread_rng, Rng};
use ruint::aliases::U256;
use test_utils::anvil::{AccountRegistry, CredentialSchemaIssuerRegistry, TestAnvil};
use test_utils::merkle::first_leaf_merkle_path;
use uuid::Uuid;

use world_id_core::{
    compress_offchain_pubkey, credential_to_credentials_signature, leaf_hash, Credential,
    HashableCredential,
};

#[tokio::test]
async fn e2e_nullifier() -> eyre::Result<()> {
    // Locate Groth16 proving material for the query and nullifier circuits
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../circom");

    let query_zkey = base.join("query.zkey");
    let nullifier_zkey = base.join("nullifier.zkey");
    let query_zkey_bytes =
        std::fs::read(&query_zkey).wrap_err("missing or unreadable query.zkey")?;
    let nullifier_zkey_bytes =
        std::fs::read(&nullifier_zkey).wrap_err("missing or unreadable nullifier.zkey")?;

    // Load Groth16 material (proving key + computation graph fingerprints)
    let query_material = Groth16Material::from_bytes(
        &query_zkey_bytes,
        Some(QUERY_FINGERPRINT),
        QUERY_GRAPH_BYTES,
    )
    .wrap_err("failed to load query groth16 material")?;
    let nullifier_material = Groth16Material::from_bytes(
        &nullifier_zkey_bytes,
        Some(NULLIFIER_FINGERPRINT),
        NULLIFIER_GRAPH_BYTES,
    )
    .wrap_err("failed to load nullifier groth16 material")?;

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
    let mut user_pk_batch = UserPublicKeyBatch {
        values: [EdwardsAffine::default(); 7],
    };
    user_pk_batch.values[0] = user_sk.public().pk;

    // Prepare inputs for on‑chain createAccount call
    let offchain_pubkey = compress_offchain_pubkey(&user_pk_batch.values[0])
        .wrap_err("failed to compress off-chain authenticator pubkey")?;
    let leaf_commitment_fq = leaf_hash(&user_pk_batch);
    let leaf_commitment = U256::from_limbs(leaf_commitment_fq.into_bigint().0);

    // Precompute the Merkle path/root for the first insertion (index 0)
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

    let merkle_index = account_index
        .checked_sub(1)
        .expect("account indices should be 1-indexed in the registry");

    // Convert issuerSchemaId to field‑friendly u64 for circuits
    let issuer_schema_id_u64: u64 = issuer_schema_id
        .try_into()
        .map_err(|_| eyre!("issuer schema id exceeded u64 range"))?;

    // Construct a minimal credential (bound to issuerSchemaId and account)
    let genesis_issued_at = 1_700_000_000u64;
    let expires_at = genesis_issued_at + 86_400;

    let credential = Credential::new()
        .issuer_schema_id(issuer_schema_id_u64)
        .account_id(merkle_index)
        .genesis_issued_at(genesis_issued_at)
        .expires_at(expires_at);

    // Issuer signs the credential (EdDSA over BabyJubJub)
    let credential = credential
        .sign(&issuer_sk)
        .wrap_err("failed to sign credential with issuer key")?;

    // Convert the signed credential into a CredentialsSignature using the helper
    let credential_signature = credential_to_credentials_signature(credential.clone())
        .wrap_err("failed to convert credential to CredentialsSignature")?;

    // Prepare Merkle membership witness for πR (query proof)
    let merkle_membership = MerkleMembership {
        root: MerkleRoot::new(expected_root_fq),
        mt_index: merkle_index,
        siblings: merkle_siblings,
    };

    // Bundle user authenticator keys for use in proofs
    let key_material = UserKeyMaterial {
        pk_batch: user_pk_batch.clone(),
        pk_index: 0,
        sk: user_sk.clone(),
    };

    // Build OPRF query context (RP id, action, nonce, timestamp)
    let rp_id = RpId::new(rng.gen::<u128>());
    let share_epoch = ShareEpoch::default();
    let action = Fq::rand(&mut rng);
    let nonce = Fq::rand(&mut rng);
    let current_time_stamp = genesis_issued_at + 60;

    // RP authenticates the query by signing LE(nonce) || LE(timestamp)
    let mut msg = Vec::new();
    msg.extend(nonce.into_bigint().to_bytes_le());
    msg.extend(current_time_stamp.to_le_bytes());
    let rp_signing_key = k256::ecdsa::SigningKey::random(&mut rng);
    let nonce_signature = rp_signing_key.sign(&msg);

    // Assemble query payload
    let query = OprfQuery {
        rp_id,
        share_epoch,
        action,
        nonce,
        current_time_stamp,
        nonce_signature,
    };

    // Produce πR (signed OPRF query) — blinded request + query inputs
    let request_id = Uuid::new_v4();
    let signed_query = sign_oprf_query(
        credential_signature.clone(),
        merkle_membership,
        &query_material,
        query,
        key_material,
        request_id,
        &mut rng,
    )
    .wrap_err("failed to sign oprf query")?;

    let oprf_request = signed_query.get_request();

    // Emulate OPRF combination offline (single RP nullifier key)
    let rp_secret = Fr::rand(&mut rng);
    let rp_nullifier_key_point = (EdwardsAffine::generator() * rp_secret).into_affine();
    let rp_nullifier_key = RpNullifierKey::new(rp_nullifier_key_point);

    // Derive blinded response C = x * B, where B is the blinded query
    let blinded_query = oprf_request.blinded_query;
    let blinded_response = (blinded_query * rp_secret).into_affine();

    // Create and check Chaum‑Pedersen DLog equality proof for (K, C)
    let dlog_proof = DLogEqualityProof::proof(blinded_query, rp_secret, &mut rng);

    // Sample auxiliary public inputs exposed by the nullifier circuit
    let signal_hash = Fq::rand(&mut rng);
    let id_commitment_r = Fq::rand(&mut rng);

    // Build nullifier proof input (πF witness payload)
    let nullifier_input = NullifierProofInput::<TREE_DEPTH>::new(
        request_id,
        signed_query.query_input().clone(),
        dlog_proof,
        rp_nullifier_key.inner(),
        blinded_response,
        signal_hash,
        id_commitment_r,
        signed_query.query_hash(),
    );

    // Generate witness JSON and create the Groth16 proof offline
    let nullifier_input_json = serde_json::to_value(&nullifier_input)
        .expect("nullifier input serializes to JSON")
        .as_object()
        .expect("nullifier input JSON must be an object")
        .to_owned();
    let nullifier_witness = nullifier_material
        .generate_witness(nullifier_input_json)
        .wrap_err("failed to generate nullifier witness")?;
    let (_nullifier_proof, public_inputs) = nullifier_material
        .generate_proof(&nullifier_witness, &mut rng)
        .wrap_err("failed to generate nullifier proof")?;

    // The circuit exposes [id_commitment, nullifier, ...] as public inputs
    let id_commitment = public_inputs[0];
    let nullifier = public_inputs[1];

    // Basic happy‑path checks on public outputs
    assert_ne!(
        id_commitment,
        Fq::ZERO,
        "id commitment should not be zero in the happy path"
    );
    assert_ne!(
        nullifier,
        Fq::ZERO,
        "nullifier should not be zero in the happy path"
    );

    Ok(())
}
