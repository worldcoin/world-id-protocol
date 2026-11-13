#![cfg(feature = "authenticator")]
#![recursion_limit = "256"]

//! WIP-202 end to end: generate a Proof of Embedding Similarity from a Flamingo
//! Verifier result (unbilled), verify it as an RP (§4.8), and check the billed-token witness.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy::primitives::Bytes;
use eyre::{Result, eyre};
use tracing::info;
use tracing_subscriber::EnvFilter;
use world_id_core::{
    AuthenticatorError, EdDSAPrivateKey, FlamingoResult,
    artifacts::{ZkArtifactSource, ZkArtifactSourceExt as _},
    embedding_similarity::{
        EmbeddingSimilarityVerificationError as VerifyError, FlamingoAttestationVerifier,
        verify_embedding_similarity,
    },
    requests::{ProofRequest, ProofType},
};
use world_id_flamingo::{FlamingoClaims, FlamingoToken, engine_config_hash};
use world_id_primitives::{EmbeddingSimilarityParams, FieldElement};
use world_id_proof::embedding_similarity_proof::COMPARE_SOURCES;
use world_id_test_utils::embedding_similarity::{EmbeddingSimilarityFixture, image_hash};

fn zk_artifact_source() -> Arc<dyn ZkArtifactSource> {
    Arc::new(world_id_core::artifacts::embedded::EmbeddedZkArtifacts.cached())
}

fn init_test_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs()
}

/// The Flamingo Verifier's result for `proof_request`, comparing the thumbnail, a live capture
/// and the challenge under the WIP-202 entry layout (§4.3).
fn flamingo_result(
    proof_request: &ProofRequest,
    thumbnail: &[u8],
    challenge_hash: FieldElement,
    billing_nullifier: FieldElement,
) -> Result<FlamingoResult> {
    let verifier_sk = EdDSAPrivateKey::random(&mut rand::thread_rng());
    let claims = FlamingoClaims {
        now: u32::try_from(now_secs())?,
        compared_entry_hashes: [
            image_hash(thumbnail),
            image_hash(b"live capture"),
            challenge_hash,
            FieldElement::ZERO,
        ],
        aud: proof_request.rp_id.into(),
        nonce: proof_request.nonce,
        aat: None,
        compare_sources: COMPARE_SOURCES,
        engine_config_hash: engine_config_hash(&[0xE7; 32], 1, 2),
        billing_nullifier,
    };
    // Through the CWT encoding, as the token reaches the Authenticator.
    let token = FlamingoToken::sign(claims, &verifier_sk)?.to_cwt()?;
    Ok(FlamingoResult {
        token: FlamingoToken::from_cwt(&token)?,
        verifier_key: verifier_sk.public(),
        signing_key_attestation: Bytes::from(verifier_sk.public().to_compressed_bytes()?.to_vec()),
    })
}

/// Stands in for the Nitro check: the attestation is the attested key itself.
#[derive(Clone)]
struct StubAttestation;

impl FlamingoAttestationVerifier for StubAttestation {
    fn attested_key(&self, attestation: &[u8]) -> Result<world_id_core::EdDSAPublicKey, String> {
        let key: [u8; 32] = attestation
            .try_into()
            .map_err(|_| "not a key".to_string())?;
        world_id_core::EdDSAPublicKey::from_compressed_bytes(key).map_err(|e| e.to_string())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn e2e_embedding_similarity_proof() -> Result<()> {
    init_test_tracing();
    info!("starting e2e_embedding_similarity_proof");
    let mut rng = rand::thread_rng();
    let fixture = EmbeddingSimilarityFixture::spawn(zk_artifact_source()).await?;
    let EmbeddingSimilarityFixture {
        proof_request,
        credential_image,
        challenge,
        artifacts,
        ..
    } = &fixture;
    let challenge_hash = image_hash(challenge);

    // Unbilled Flamingo result: prove.
    let unbilled = flamingo_result(
        proof_request,
        credential_image,
        challenge_hash,
        FieldElement::ZERO,
    )?;
    let response = fixture.prove(&unbilled).await?;

    // The RP verifies it under WIP-202 §4.8.
    let policy = fixture.policy(
        StubAttestation,
        [engine_config_hash(&[0xE7; 32], 1, 2)].into(),
    );
    fixture.verify(proof_request, &response, &policy).await?;

    // Each policy check rejects on its own, before the proof is verified.
    let mut other_engine = policy.clone();
    other_engine.engine_config_hashes = [FieldElement::from(1u64)].into();
    let mut aat_required = policy.clone();
    aat_required.aat.required = true;
    for (policy, expected) in [
        (&other_engine, "EngineNotAccepted"),
        (&aat_required, "AatRequired"),
    ] {
        let err = fixture
            .verify(proof_request, &response, policy)
            .await
            .expect_err(expected);
        assert!(format!("{err:?}").starts_with(expected), "{err:?}");
    }
    let mut other_attestation = response.clone();
    other_attestation
        .embedding_similarity
        .as_mut()
        .ok_or_else(|| eyre!("no embedding similarity item"))?
        .signing_key_attestation = Bytes::from(
        EdDSAPrivateKey::random(&mut rng)
            .public()
            .to_compressed_bytes()?
            .to_vec(),
    );
    assert!(matches!(
        fixture
            .verify(proof_request, &other_attestation, &policy)
            .await,
        Err(VerifyError::AttestedKeyMismatch)
    ));
    let merkle_root = fixture.merkle_root;
    let valid_root = move |root| async move { Ok::<_, std::io::Error>(root == merkle_root) };
    let issuer_pk = fixture.issuer_key.pk;
    let trusted_issuer = move |key: world_id_core::EdDSAPublicKey| async move {
        Ok::<_, std::io::Error>(key.pk == issuer_pk)
    };
    let unknown_root = |_| async { Ok::<_, std::io::Error>(false) };
    assert!(matches!(
        verify_embedding_similarity(
            proof_request,
            &response,
            &policy,
            unknown_root,
            trusted_issuer,
            artifacts.as_ref(),
        )
        .await,
        Err(VerifyError::InvalidRoot(_))
    ));
    let unreachable_registry = |_| async { Err::<bool, _>(std::io::Error::other("registry down")) };
    assert!(matches!(
        verify_embedding_similarity(
            proof_request,
            &response,
            &policy,
            unreachable_registry,
            trusted_issuer,
            artifacts.as_ref(),
        )
        .await,
        Err(VerifyError::RootCheck(_))
    ));
    let untrusted_issuer = |_| async { Ok::<_, std::io::Error>(false) };
    assert!(matches!(
        verify_embedding_similarity(
            proof_request,
            &response,
            &policy,
            valid_root,
            untrusted_issuer,
            artifacts.as_ref(),
        )
        .await,
        Err(VerifyError::UntrustedIssuerKey)
    ));
    let unreachable_issuer_registry =
        |_| async { Err::<bool, _>(std::io::Error::other("registry down")) };
    assert!(matches!(
        verify_embedding_similarity(
            proof_request,
            &response,
            &policy,
            valid_root,
            unreachable_issuer_registry,
            artifacts.as_ref(),
        )
        .await,
        Err(VerifyError::IssuerCheck(_))
    ));

    // The proof binds the RP's request: another challenge fails the proof itself.
    let ProofType::EmbeddingSimilarity(params) = &proof_request.proof_type else {
        return Err(eyre!("not an embedding similarity request"));
    };
    let mut other_challenge = proof_request.clone();
    other_challenge.proof_type = ProofType::EmbeddingSimilarity(EmbeddingSimilarityParams {
        challenge_hash: image_hash(b"another frame"),
        ..params.clone()
    });
    assert!(matches!(
        fixture.verify(&other_challenge, &response, &policy).await,
        Err(VerifyError::Proof(_))
    ));

    // A billed token without a witness is rejected before proving.
    let billed = flamingo_result(
        proof_request,
        credential_image,
        challenge_hash,
        FieldElement::from(7u64),
    )?;
    let err = fixture
        .prove(&billed)
        .await
        .expect_err("a billed token needs the billing witness");
    assert!(
        matches!(err, AuthenticatorError::BillingWitnessRequired),
        "{err}"
    );

    info!("e2e_embedding_similarity_proof finished successfully");
    Ok(())
}
