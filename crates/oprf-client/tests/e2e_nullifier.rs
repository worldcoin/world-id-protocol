use std::{convert::TryInto, path::PathBuf, str::FromStr};

use alloy::{network::EthereumWallet, providers::ProviderBuilder, sol_types::SolEvent};
use ark_babyjubjub::{EdwardsAffine, Fq};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use eddsa_babyjubjub::EdDSAPrivateKey;
use eyre::{eyre, WrapErr as _};
use k256::ecdsa::signature::Signer;
use oprf_client::{sign_oprf_query, OprfQuery};
use oprf_types::{RpId, ShareEpoch};
use oprf_world_types::{
    MerkleMembership, MerkleRoot, UserKeyMaterial, UserPublicKeyBatch, TREE_DEPTH,
};
use oprf_zk::{Groth16Material, NULLIFIER_FINGERPRINT, QUERY_FINGERPRINT};
use poseidon2::Poseidon2;
use rand::{thread_rng, Rng};
use ruint::aliases::U256;
use test_utils::anvil::{AccountRegistry, CredentialSchemaIssuerRegistry, TestAnvil};
use uuid::Uuid;
use world_id_core::{credential_to_credentials_signature, Credential, HashableCredential};

#[tokio::test]
async fn e2e_nullifier() -> eyre::Result<()> {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../circom");

    let query_zkey = base.join("query.zkey");
    let query_graph = base.join("query_graph.bin");
    let nullifier_zkey = base.join("nullifier.zkey");
    let nullifier_graph = base.join("nullifier_graph.bin");

    assert!(
        query_zkey.exists() && query_graph.exists(),
        "missing query proving material in {:?}",
        base
    );
    assert!(
        nullifier_zkey.exists() && nullifier_graph.exists(),
        "missing nullifier proving material in {:?}",
        base
    );

    let query_material = Groth16Material::new(&query_zkey, Some(QUERY_FINGERPRINT), &query_graph)
        .wrap_err("failed to load query groth16 material")?;
    let _nullifier_material = Groth16Material::new(
        &nullifier_zkey,
        Some(NULLIFIER_FINGERPRINT),
        &nullifier_graph,
    )
    .wrap_err("failed to load nullifier groth16 material")?;

    let anvil = TestAnvil::spawn().wrap_err("failed to launch anvil")?;
    let signer = anvil
        .signer(0)
        .wrap_err("failed to fetch default anvil signer")?;

    let issuer_registry = anvil
        .deploy_credential_schema_issuer_registry(signer.clone())
        .await
        .wrap_err("failed to deploy credential schema issuer registry proxy")?;
    let account_registry = anvil
        .deploy_account_registry(signer.clone())
        .await
        .wrap_err("failed to deploy account registry proxy")?;

    assert!(
        !issuer_registry.is_zero(),
        "issuer registry proxy address must be non-zero"
    );
    assert!(
        !account_registry.is_zero(),
        "account registry proxy address must be non-zero"
    );

    let mut rng = thread_rng();
    let issuer_sk = EdDSAPrivateKey::random(&mut rng);
    let issuer_pk = issuer_sk.public();

    let issuer_pubkey = CredentialSchemaIssuerRegistry::Pubkey {
        x: U256::from_limbs(issuer_pk.pk.x.into_bigint().0),
        y: U256::from_limbs(issuer_pk.pk.y.into_bigint().0),
    };

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

    let onchain_pubkey = registry_contract
        .issuerSchemaIdToPubkey(issuer_schema_id)
        .call()
        .await
        .wrap_err("failed to fetch issuer pubkey from chain")?;

    assert_eq!(onchain_pubkey.x, issuer_pubkey.x);
    assert_eq!(onchain_pubkey.y, issuer_pubkey.y);

    let recovery_signer = anvil
        .signer(1)
        .wrap_err("failed to fetch recovery anvil signer")?;
    let authenticator_signer = anvil
        .signer(2)
        .wrap_err("failed to fetch authenticator anvil signer")?;

    let account_provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(authenticator_signer.clone()))
        .connect_http(
            anvil
                .endpoint()
                .parse()
                .wrap_err("invalid anvil endpoint URL")?,
        );
    let account_contract = AccountRegistry::new(account_registry, account_provider);

    let user_sk = EdDSAPrivateKey::random(&mut rng);
    let mut user_pk_batch = UserPublicKeyBatch {
        values: [EdwardsAffine::default(); 7],
    };
    user_pk_batch.values[0] = user_sk.public().pk;

    let offchain_pubkey = compress_offchain_pubkey(&user_pk_batch.values[0])
        .wrap_err("failed to compress off-chain authenticator pubkey")?;
    let leaf_commitment_fq = leaf_hash(&user_pk_batch);
    let leaf_commitment = U256::from_limbs(leaf_commitment_fq.into_bigint().0);

    let (merkle_siblings, expected_root_fq) = first_leaf_merkle_path(leaf_commitment_fq);
    let expected_root_u256 = U256::from_limbs(expected_root_fq.into_bigint().0);

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

    let onchain_root = account_contract
        .currentRoot()
        .call()
        .await
        .wrap_err("failed to fetch account registry root from chain")?;

    assert_eq!(
        onchain_root, expected_root_u256,
        "on-chain root mismatch with locally computed root"
    );

    let account_created = account_receipt
        .logs()
        .iter()
        .find_map(|log| AccountRegistry::AccountCreated::decode_log(log.inner.as_ref()).ok())
        .ok_or_else(|| eyre!("AccountCreated event not emitted"))?;

    let account_index: u64 = account_created
        .accountIndex
        .try_into()
        .map_err(|_| eyre!("account index exceeded u64 range"))?;

    let issuer_schema_id_u64: u64 = issuer_schema_id
        .try_into()
        .map_err(|_| eyre!("issuer schema id exceeded u64 range"))?;

    let genesis_issued_at = 1_700_000_000u64;
    let expires_at = genesis_issued_at + 31_536_000;

    let credential = Credential::new()
        .issuer_schema_id(issuer_schema_id_u64)
        .account_id(account_index)
        .genesis_issued_at(genesis_issued_at)
        .expires_at(expires_at);

    let credential = credential
        .sign(&issuer_sk)
        .wrap_err("failed to sign credential with issuer key")?;

    let credential_signature = credential_to_credentials_signature(credential.clone())
        .wrap_err("failed to convert credential into credentials signature")?;

    assert_eq!(
        credential_signature.type_id,
        Fq::from(issuer_schema_id_u64),
        "credential signature type id mismatch"
    );
    assert_eq!(
        credential_signature.issuer, issuer_pk,
        "credential signature issuer mismatch"
    );
    assert_eq!(
        merkle_siblings.len(),
        TREE_DEPTH,
        "unexpected merkle sibling path length"
    );
    assert_ne!(
        expected_root_fq,
        Fq::ZERO,
        "expected root should not be zero after first insertion"
    );

    println!("Account index emitted: {account_index}");

    let merkle_membership = MerkleMembership {
        root: MerkleRoot::new(expected_root_fq),
        mt_index: account_index,
        siblings: merkle_siblings,
    };

    let key_material = UserKeyMaterial {
        pk_batch: user_pk_batch.clone(),
        pk_index: 0,
        sk: user_sk.clone(),
    };

    let rp_id = RpId::new(rng.gen::<u128>());
    let share_epoch = ShareEpoch::default();
    let action = Fq::rand(&mut rng);
    let nonce = Fq::rand(&mut rng);
    let current_time_stamp = 1_800_000_000u64;

    let mut msg = Vec::new();
    msg.extend(nonce.into_bigint().to_bytes_le());
    msg.extend(current_time_stamp.to_le_bytes());
    let rp_signing_key = k256::ecdsa::SigningKey::random(&mut rng);
    let nonce_signature = rp_signing_key.sign(&msg);

    let query = OprfQuery {
        rp_id,
        share_epoch,
        action,
        nonce,
        current_time_stamp,
        nonce_signature,
    };

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
    assert_eq!(oprf_request.request_id, request_id);

    Ok(())
}

fn leaf_hash(pk: &UserPublicKeyBatch) -> Fq {
    let poseidon2_16: Poseidon2<Fq, 16, 5> = Poseidon2::default();
    let mut input = [Fq::ZERO; 16];
    input[0] = Fq::from_str("105702839725298824521994315")
        .expect("poseidon domain separator constant must parse");
    for i in 0..7 {
        input[i * 2 + 1] = pk.values[i].x;
        input[i * 2 + 2] = pk.values[i].y;
    }
    poseidon2_16.permutation(&input)[1]
}

fn compress_offchain_pubkey(pk: &EdwardsAffine) -> eyre::Result<U256> {
    let mut compressed = Vec::with_capacity(32);
    pk.serialize_compressed(&mut compressed)?;
    Ok(U256::from_le_slice(&compressed))
}

fn first_leaf_merkle_path(leaf: Fq) -> ([Fq; TREE_DEPTH], Fq) {
    let poseidon2_2: Poseidon2<Fq, 2, 5> = Poseidon2::default();
    let mut siblings = [Fq::ZERO; TREE_DEPTH];
    let mut zero = Fq::ZERO;
    for sibling in siblings.iter_mut() {
        *sibling = zero;
        zero = poseidon2_compress(&poseidon2_2, zero, zero);
    }

    let mut current = leaf;
    for sibling in siblings.iter() {
        current = poseidon2_compress(&poseidon2_2, current, *sibling);
    }

    (siblings, current)
}

fn poseidon2_compress(poseidon2: &Poseidon2<Fq, 2, 5>, left: Fq, right: Fq) -> Fq {
    let mut state = poseidon2.permutation(&[left, right]);
    state[0] += left;
    state[0]
}
