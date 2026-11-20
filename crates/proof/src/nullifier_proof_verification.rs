//! Off-chain verification of Uniqueness and Session Proofs (the nullifier circuit `π2`).
//!
//! [`verify_nullifier_proof`] runs the Groth16 check that `WorldIDVerifier.verifyProofAndSignals`
//! runs on-chain, over the same 15 public signals in the same order. The caller resolves the
//! on-chain state the contract reads (Merkle root validity, Issuer key, OPRF key, expiration
//! threshold) and supplies it in [`NullifierPublicInputs`].

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey};
use eddsa_babyjubjub::EdDSAPublicKey;
use once_cell::sync::Lazy;
use world_id_primitives::{FieldElement, TREE_DEPTH, ZeroKnowledgeProof};

use crate::nullifier_verifying_key::nullifier_verifying_key;

type Affine = ark_babyjubjub::EdwardsAffine;

static PREPARED_VERIFYING_KEY: Lazy<PreparedVerifyingKey<Bn254>> =
    Lazy::new(|| ark_groth16::prepare_verifying_key(&nullifier_verifying_key()));

/// The public inputs of a Uniqueness or Session Proof, except the Merkle root, which the proof
/// carries itself (see [`ZeroKnowledgeProof`]).
///
/// Every value comes from the verifier: its own request, the response item it checks, and the
/// on-chain registries. None may be taken from the proof.
#[derive(Debug, Clone)]
pub struct NullifierPublicInputs {
    /// The nullifier: the response's nullifier for a Uniqueness Proof, or the first element of
    /// the session nullifier for a Session Proof.
    pub nullifier: FieldElement,
    /// The credential's issuer schema id.
    pub issuer_schema_id: u64,
    /// The Issuer's public key registered for `issuer_schema_id`.
    pub issuer_public_key: EdDSAPublicKey,
    /// The minimum credential expiration the proof shows.
    pub expires_at_min: u64,
    /// The minimum credential genesis issuance time the RP requires, `0` if none.
    pub genesis_issued_at_min: u64,
    /// The RP's id.
    pub rp_id: u64,
    /// The action: the RP's action for a Uniqueness Proof, or the second element of the session
    /// nullifier for a Session Proof.
    pub action: FieldElement,
    /// The OPRF public key registered for the RP.
    pub oprf_public_key: Affine,
    /// The hash of the RP's signal.
    pub signal_hash: FieldElement,
    /// The RP's nonce.
    pub nonce: FieldElement,
    /// The session id commitment the proof is bound to, `0` if none.
    pub session_id: FieldElement,
}

impl NullifierPublicInputs {
    /// The public signals in circuit order, as `WorldIDVerifier.verifyProofAndSignals` builds them.
    fn public_signals(&self, merkle_root: Fr) -> [Fr; 15] {
        [
            *self.nullifier,
            Fr::from(self.issuer_schema_id),
            self.issuer_public_key.pk.x,
            self.issuer_public_key.pk.y,
            Fr::from(self.expires_at_min),
            Fr::from(self.genesis_issued_at_min),
            merkle_root,
            Fr::from(TREE_DEPTH as u64),
            Fr::from(self.rp_id),
            *self.action,
            self.oprf_public_key.x,
            self.oprf_public_key.y,
            *self.signal_hash,
            *self.nonce,
            *self.session_id,
        ]
    }
}

/// Why a Uniqueness or Session Proof was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NullifierProofVerificationError {
    /// The proof's Merkle root is not a scalar field element.
    #[error("the proof's merkle root is not in the scalar field")]
    MerkleRootNotInField,
    /// A compressed proof point is not a valid curve point.
    #[error("the proof contains an invalid curve point")]
    InvalidProofPoint,
    /// The proof does not verify for the public inputs.
    #[error("the proof is invalid")]
    ProofInvalid,
}

/// Verifies a Uniqueness or Session Proof against `public`.
///
/// This is only the Groth16 check. The caller MUST also run the checks `WorldIDVerifier` runs
/// around it: the Merkle root ([`merkle_root`]) is a valid `WorldIDRegistry` root, the Issuer and
/// OPRF keys are the registered ones, `expires_at_min` is within the minimum expiration
/// threshold, and the action carries the prefix of its proof type.
///
/// # Errors
/// A [`NullifierProofVerificationError`] if the proof is malformed or does not verify.
pub fn verify_nullifier_proof(
    proof: &ZeroKnowledgeProof,
    public: &NullifierPublicInputs,
) -> Result<(), NullifierProofVerificationError> {
    let encoded = proof.as_ethereum_representation();
    let merkle_root =
        merkle_root(proof).ok_or(NullifierProofVerificationError::MerkleRootNotInField)?;
    let groth16_proof =
        taceo_groth16_sol::decompress_proof(&[encoded[0], encoded[1], encoded[2], encoded[3]])
            .map_err(|_| NullifierProofVerificationError::InvalidProofPoint)?;
    let signals = public.public_signals(*merkle_root);
    match Groth16::<Bn254>::verify_proof(&PREPARED_VERIFYING_KEY, &groth16_proof, &signals) {
        Ok(true) => Ok(()),
        _ => Err(NullifierProofVerificationError::ProofInvalid),
    }
}

/// The Merkle root a proof is generated against, if it is a scalar field element.
///
/// The verifier checks this root against the `WorldIDRegistry` before trusting the proof. The
/// contract rejects roots outside the field (`PublicInputNotInField`) instead of reducing them.
#[must_use]
pub fn merkle_root(proof: &ZeroKnowledgeProof) -> Option<FieldElement> {
    FieldElement::try_from(proof.as_ethereum_representation()[4]).ok()
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use ruint::aliases::U256;

    use super::*;

    // Proofs and public inputs from `contracts/test/core/WorldIDVerifierTest.t.sol`, which the
    // `Verifier` contract accepts.
    const ROOT: &str = "0x0af727d9412a9d5c73b685fd09dc39e727064e65b8269b233009edfc105f9853";
    const UNIQUENESS_PROOF: [&str; 4] = [
        "0x2a184f5930f2b6a0f367f649a80757e081b3fb28b76fffcfe325d82df87395b3",
        "0x0f6849ab589365a7537beeb70014958ae261fe2dd7fdbf5c4823c6b527aefa34",
        "0xac5ee090f2ee180619c5c9825f22cee8873fc0d4764b7b0c5ffd7802d8f2e0f9",
        "0x4a221ef1d3b5522ac95f38db43afda6863d34836f7a8cff0b50aa9c8ca52e727",
    ];
    const SESSION_PROOF: [&str; 4] = [
        "0x4930872a26a12446d943042e1958e65d4b3eecca9bf2b80c6bdba2dd24f37467",
        "0x15bba2773377d7ef96c76ede7d8d12bc5725441961de9f1b330484e1f24a19a8",
        "0x86dc81c5fccb1de6766036f308db3b6e1e6eb0fa7d780096d701cc97fb4a20f1",
        "0x3d4279efe1806d0c7747915b9852ade3738e8ffd87604e01034ca78e8cb81c54",
    ];

    fn u256(hex: &str) -> U256 {
        U256::from_str(hex).unwrap()
    }

    fn fe(hex: &str) -> FieldElement {
        FieldElement::try_from(u256(hex)).unwrap()
    }

    fn proof(points: [&str; 4]) -> ZeroKnowledgeProof {
        let [a, b, c, d] = points.map(u256);
        ZeroKnowledgeProof::from_ethereum_representation([a, b, c, d, u256(ROOT)])
    }

    fn affine(x: &str, y: &str) -> Affine {
        Affine::new_unchecked(*fe(x), *fe(y))
    }

    fn uniqueness_inputs() -> NullifierPublicInputs {
        NullifierPublicInputs {
            nullifier: fe("0x5968cd4d3c50bfd2305671d1092bee10ccb679b93db3ca779b6477e4885e476"),
            issuer_schema_id: 1,
            issuer_public_key: EdDSAPublicKey {
                pk: affine(
                    "0x0f178f8128469f6be2f108a02b2a3f96d107d9466c4f95460ed7d4e8f10384b3",
                    "0x21b8a276d0b75460b075f4a4cc1961938e62f4964bcca87cffce8ada4d6e11d5",
                ),
            },
            expires_at_min: 0x6a54_cd68,
            genesis_issued_at_min: 0,
            rp_id: 0x0387_df34_f862_cd4e,
            action: fe("0x978cc65f06353d8543971b65da8751833ff1253a192f58bed14f2739c0a345"),
            oprf_public_key: affine(
                "0x24a3480be33ae5a83f68fbefe658e65053cbe99ee442c178859070a23372a4d4",
                "0x2fc70cc380d5bb9d8537a8fd82e98fb29eb837ff3943f5704ec3957f444ec6cd",
            ),
            signal_hash: fe("0x1578ed0de47522ad0b38e87031739c6a65caecc39ce3410bf3799e756a220f"),
            nonce: fe("0x38ed3d4d95deac6e369dde48890d5b14b49a2d26a0b2e8854d429ff7c52cf99"),
            session_id: FieldElement::ZERO,
        }
    }

    fn session_inputs() -> NullifierPublicInputs {
        NullifierPublicInputs {
            nullifier: fe("0x08ce710377b04b2605fd6c5545f15f638527bd0315f223b8c2c070a4ac0a62d0"),
            action: fe("0x02b6b35cb561c84d7a137fbc715c9df67152fa28c1b81042a4c0e80d1ba01b00"),
            nonce: fe("0x0a138dc568a2548155f3991625ddec3b466d2a49b19d6ff26a94ba0310cdf5ba"),
            session_id: fe("0x2018a266d26fbc1cd41743cc3126321302b8f0af39c367fe5718eeafb341d494"),
            ..uniqueness_inputs()
        }
    }

    #[test]
    fn accepts_the_contract_fixtures() {
        verify_nullifier_proof(&proof(UNIQUENESS_PROOF), &uniqueness_inputs()).unwrap();
        verify_nullifier_proof(&proof(SESSION_PROOF), &session_inputs()).unwrap();
    }

    #[test]
    fn rejects_any_changed_public_input() {
        let changes: [fn(&mut NullifierPublicInputs); 12] = [
            |p| p.nullifier = FieldElement::from(7u64),
            |p| p.issuer_schema_id += 1,
            |p| p.issuer_public_key.pk.x += Fr::from(1u64),
            |p| p.expires_at_min += 1,
            |p| p.genesis_issued_at_min = 1,
            |p| p.rp_id += 1,
            |p| p.action = FieldElement::from(8u64),
            |p| p.oprf_public_key.y += Fr::from(1u64),
            |p| p.signal_hash = FieldElement::from(9u64),
            |p| p.nonce = FieldElement::from(10u64),
            |p| p.session_id = FieldElement::from(11u64),
            |p| p.oprf_public_key.x += Fr::from(1u64),
        ];
        for change in changes {
            let mut inputs = uniqueness_inputs();
            change(&mut inputs);
            assert_eq!(
                verify_nullifier_proof(&proof(UNIQUENESS_PROOF), &inputs),
                Err(NullifierProofVerificationError::ProofInvalid)
            );
        }
    }

    #[test]
    fn rejects_another_root_and_session_binding() {
        let mut encoded = proof(UNIQUENESS_PROOF).as_ethereum_representation();
        encoded[4] = U256::from(2);
        assert_eq!(
            verify_nullifier_proof(
                &ZeroKnowledgeProof::from_ethereum_representation(encoded),
                &uniqueness_inputs()
            ),
            Err(NullifierProofVerificationError::ProofInvalid)
        );
        // The session proof does not verify as a uniqueness proof without its session id.
        let mut unbound = session_inputs();
        unbound.session_id = FieldElement::ZERO;
        assert_eq!(
            verify_nullifier_proof(&proof(SESSION_PROOF), &unbound),
            Err(NullifierProofVerificationError::ProofInvalid)
        );
    }

    #[test]
    fn rejects_malformed_proofs() {
        let mut encoded = proof(UNIQUENESS_PROOF).as_ethereum_representation();
        encoded[4] = U256::MAX;
        assert_eq!(
            verify_nullifier_proof(
                &ZeroKnowledgeProof::from_ethereum_representation(encoded),
                &uniqueness_inputs()
            ),
            Err(NullifierProofVerificationError::MerkleRootNotInField)
        );

        let mut encoded = proof(UNIQUENESS_PROOF).as_ethereum_representation();
        encoded[0] = U256::MAX;
        assert_eq!(
            verify_nullifier_proof(
                &ZeroKnowledgeProof::from_ethereum_representation(encoded),
                &uniqueness_inputs()
            ),
            Err(NullifierProofVerificationError::InvalidProofPoint)
        );
    }

    #[test]
    fn verifying_key_is_the_zkeys() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../circom/");
        let material = crate::load_nullifier_material_from_paths(
            format!("{root}OPRFNullifier.arks.zkey"),
            format!("{root}OPRFNullifierGraph.bin"),
        )
        .unwrap();
        assert_eq!(nullifier_verifying_key(), material.zkey().pk.vk);
    }
}
