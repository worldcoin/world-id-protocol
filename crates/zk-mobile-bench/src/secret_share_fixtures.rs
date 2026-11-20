//! Fixtures for the secret-share circuits (`oprf-query-v2`, `oprf-nullifier-v2`,
//! `share-fetch-xmss`): one account at leaf index 1 whose registry leaf commits to its key set,
//! `s` and one XMSS credential. The OPRF response comes from a real evaluation with `taceo-oprf`.

use std::sync::OnceLock;

use ark_ec::CurveGroup as _;
use eddsa_babyjubjub::EdDSAPrivateKey;
use rand::SeedableRng as _;
use rand_chacha::ChaCha20Rng;
use taceo_oprf::core::{
    dlog_equality::DLogEqualityProof,
    oprf::{BlindedOprfResponse, BlindingFactor, client},
};
use world_id_primitives::{
    AuthenticatorPublicKeySet, FieldElement,
    merkle::MerkleInclusionProof,
    secret_share::{self, NUM_XMSS_SLOTS},
    xmss::{XmssSecretKey, XmssSignature},
};
use world_id_proof::secret_share_proof::{
    OprfNullifierV2CircuitInput, OprfQueryV2CircuitInput, ShareFetchXmssCircuitInput,
};

use crate::fixtures::{first_leaf_merkle_path, generate_rp_fixture};

const LEAF_INDEX: u64 = 1;
const EPOCH: u64 = 1_700_000_000 / 300;

/// The account's static parts; XMSS key generation hashes ~630k times, so it runs once.
struct Account {
    key_set: AuthenticatorPublicKeySet,
    signer: EdDSAPrivateKey,
    s: FieldElement,
    xmss_root: FieldElement,
    pub_seed: FieldElement,
    tag_key: FieldElement,
    xmss_commitments: [FieldElement; NUM_XMSS_SLOTS],
    fetch_signature: XmssSignature,
    kem_pk_hash: FieldElement,
}

impl Account {
    fn get() -> &'static Self {
        static ACCOUNT: OnceLock<Account> = OnceLock::new();
        ACCOUNT.get_or_init(|| {
            let signer = EdDSAPrivateKey::from_bytes([42u8; 32]);
            let key_set = AuthenticatorPublicKeySet::new(vec![signer.public()]).unwrap();
            let mut xmss = XmssSecretKey::generate(FieldElement::from(0x5eed_u64));
            let mut xmss_commitments = [FieldElement::ZERO; NUM_XMSS_SLOTS];
            xmss_commitments[0] = xmss.commitment();
            let kem_pk_hash = FieldElement::from_arbitrary_raw_bytes(b"benchmark ML-KEM key");
            let fetch_signature = xmss
                .sign(secret_share::share_fetch_message(
                    LEAF_INDEX,
                    EPOCH,
                    kem_pk_hash,
                ))
                .unwrap();
            Self {
                key_set,
                signer,
                s: FieldElement::from(0x5ec2e7_u64),
                xmss_root: xmss.root(),
                pub_seed: xmss.pub_seed(),
                tag_key: xmss.tag_key(),
                xmss_commitments,
                fetch_signature,
                kem_pk_hash,
            }
        })
    }

    fn xmss_set_root(&self) -> FieldElement {
        secret_share::xmss_set_root(self.xmss_commitments)
    }

    fn inclusion_proof(&self) -> MerkleInclusionProof<{ world_id_primitives::TREE_DEPTH }> {
        let leaf = secret_share::registry_leaf(
            &self.key_set,
            secret_share::secret_commitment(self.s),
            self.xmss_set_root(),
        );
        let (siblings, root) = first_leaf_merkle_path(*leaf);
        MerkleInclusionProof::new(root, LEAF_INDEX, siblings)
    }
}

/// An `oprf-query-v2` input, with its query digest.
pub fn oprf_query_v2_fixture() -> (OprfQueryV2CircuitInput, BlindingFactor, FieldElement) {
    let account = Account::get();
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let rp = generate_rp_fixture(&mut rng);
    let rp_id = FieldElement::from(rp.world_rp_id);
    let action = FieldElement::from(rp.action);
    let query = secret_share::oprf_query_digest(LEAF_INDEX, rp_id, action, account.s);
    let blinding_factor = BlindingFactor::rand(&mut rng);

    let input = OprfQueryV2CircuitInput {
        key_set: account.key_set.clone(),
        key_index: 0,
        signature: account.signer.sign(*query),
        inclusion_proof: account.inclusion_proof(),
        s: account.s,
        xmss_set_root: account.xmss_set_root(),
        beta: blinding_factor.beta(),
        rp_id,
        action,
        nonce: rp.nonce.into(),
    };
    (input, blinding_factor, query)
}

/// An `oprf-nullifier-v2` input over a real OPRF evaluation of the query.
pub fn oprf_nullifier_v2_fixture() -> OprfNullifierV2CircuitInput {
    let (query, blinding_factor, digest) = oprf_query_v2_fixture();
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let rp = generate_rp_fixture(&mut rng);

    let blinded_query = client::blind_query(*digest, blinding_factor).blinded_query();
    let blinded_response = (blinded_query * rp.rp_secret).into_affine();
    let oprf_response =
        BlindedOprfResponse::new(blinded_response).unblind_response(&blinding_factor.prepare());
    let dlog = DLogEqualityProof::proof(blinded_query, rp.rp_secret, &mut rng);

    OprfNullifierV2CircuitInput {
        query,
        oprf_pk: rp.rp_nullifier_point,
        dlog_e: dlog.e(),
        dlog_s: dlog.s(),
        oprf_response,
    }
}

/// A `share-fetch-xmss` input signed with the credential's first one-time key.
pub fn share_fetch_xmss_fixture() -> ShareFetchXmssCircuitInput {
    let account = Account::get();
    ShareFetchXmssCircuitInput {
        key_set: account.key_set.clone(),
        inclusion_proof: account.inclusion_proof(),
        s_commitment: secret_share::secret_commitment(account.s),
        xmss_commitments: account.xmss_commitments,
        xmss_slot: 0,
        xmss_root: account.xmss_root,
        pub_seed: account.pub_seed,
        tag_key: account.tag_key,
        signature: account.fetch_signature.clone(),
        epoch: EPOCH,
        kem_pk_hash: account.kem_pk_hash,
    }
}

#[cfg(test)]
mod tests {
    use provekit_prover::Prove as _;
    use world_id_proof::{
        NoirCircuitInput,
        secret_share_proof::{self, embedded::Circuit},
    };

    use super::*;

    fn witness_satisfies(circuit: Circuit, input: impl NoirCircuitInput) -> bool {
        let mut prover = secret_share_proof::embedded::prover(circuit).unwrap();
        prover
            .generate_witness(input.into_witness().unwrap())
            .is_ok()
    }

    #[test]
    fn test_fixtures_satisfy_their_circuits() {
        assert!(witness_satisfies(
            Circuit::OprfQueryV2,
            oprf_query_v2_fixture().0
        ));
        assert!(witness_satisfies(
            Circuit::OprfNullifierV2,
            oprf_nullifier_v2_fixture()
        ));
        assert!(witness_satisfies(
            Circuit::ShareFetchXmss,
            share_fetch_xmss_fixture()
        ));
    }

    #[test]
    fn test_query_rejects_a_secret_other_than_the_committed_one() {
        let (mut input, _, _) = oprf_query_v2_fixture();
        input.s = FieldElement::from(1u64);
        assert!(!witness_satisfies(Circuit::OprfQueryV2, input));
    }

    #[test]
    fn test_share_fetch_rejects_another_epoch() {
        let mut input = share_fetch_xmss_fixture();
        input.epoch += 1;
        assert!(!witness_satisfies(Circuit::ShareFetchXmss, input));
    }

    #[test]
    fn test_share_fetch_rejects_an_unregistered_credential() {
        let mut input = share_fetch_xmss_fixture();
        input.xmss_commitments[0] = FieldElement::from(1u64);
        assert!(!witness_satisfies(Circuit::ShareFetchXmss, input));
    }

    #[test]
    #[ignore = "expensive: proves every circuit; run with --release --include-ignored"]
    fn test_proofs_verify_against_their_public_inputs() {
        let (query, blinding_factor, digest) = oprf_query_v2_fixture();
        let blinded = client::blind_query(*digest, blinding_factor).blinded_query();
        let query_public = vec![
            query.inclusion_proof.root,
            query.rp_id,
            query.action,
            query.nonce,
            blinded.x.into(),
            blinded.y.into(),
        ];
        prove_and_verify(Circuit::OprfQueryV2, query, &query_public);

        let nullifier = oprf_nullifier_v2_fixture();
        let expected_nullifier = world_id_primitives::poseidon::hash(
            world_id_primitives::poseidon::ds::OPRF_PROOF,
            [
                digest,
                nullifier.oprf_response.x.into(),
                nullifier.oprf_response.y.into(),
            ],
        );
        let oprf_pk = nullifier.oprf_pk;
        let nullifier_public = vec![
            nullifier.query.inclusion_proof.root,
            nullifier.query.rp_id,
            nullifier.query.action,
            nullifier.query.nonce,
            oprf_pk.x.into(),
            oprf_pk.y.into(),
            expected_nullifier,
        ];
        prove_and_verify(Circuit::OprfNullifierV2, nullifier, &nullifier_public);

        let fetch = share_fetch_xmss_fixture();
        let fetch_public = vec![
            fetch.inclusion_proof.root,
            FieldElement::from(fetch.inclusion_proof.leaf_index),
            FieldElement::from(fetch.epoch),
            fetch.kem_pk_hash,
            fetch.tag(),
        ];
        prove_and_verify(Circuit::ShareFetchXmss, fetch, &fetch_public);
    }

    fn prove_and_verify(circuit: Circuit, input: impl NoirCircuitInput, public: &[FieldElement]) {
        let prover = secret_share_proof::embedded::prover(circuit).unwrap();
        let proof = secret_share_proof::prove(input, prover).unwrap();
        let mut verifier = secret_share_proof::embedded::verifier(circuit).unwrap();
        secret_share_proof::verify(&mut verifier, public, &proof).unwrap();
    }
}
