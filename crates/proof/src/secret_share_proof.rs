//! UNAUDITED RESEARCH PROTOTYPE. Noir/ProveKit proofs for a World ID secret `s` that is
//! Shamir-shared across the OPRF nodes and folded into the OPRF query digest
//! (see [`world_id_primitives::secret_share`]):
//!
//! - `oprf-query-v2`: the OPRF query proof (π1) over `q' = H(leaf_index, rp_id, action, s)`.
//! - `oprf-nullifier-v2`: the OPRF evaluation and nullifier over `q'`, the OPRF core of π2.
//! - `share-fetch-xmss`: authorizes a share fetch with an XMSS signature, so it rests only on
//!   hashes. The `EdDSA` alternative is checked natively, see
//!   [`ShareFetchRequest`](world_id_primitives::secret_share::ShareFetchRequest).

use std::collections::BTreeMap;

use ark_babyjubjub::EdwardsAffine;
use eddsa_babyjubjub::EdDSASignature;
use provekit_common::{InputMap, InputValue, NoirElement, WhirR1CSProof};
use world_id_primitives::{
    AuthenticatorPublicKeySet, FieldElement, TREE_DEPTH,
    merkle::MerkleInclusionProof,
    secret_share::NUM_XMSS_SLOTS,
    xmss::{self, XmssSignature},
};

use crate::{
    NoirCircuitInput, NoirRepresentable as _, ProofError,
    noir_components::{account_inputs, public_key},
    provekit, to_noir_element,
};

/// Inputs to the `oprf-query-v2` circuit.
pub struct OprfQueryV2CircuitInput {
    /// The account's registered authenticator keys.
    pub key_set: AuthenticatorPublicKeySet,
    /// Slot of the key that signed the query digest.
    pub key_index: u64,
    /// Signature over [`world_id_primitives::secret_share::oprf_query_digest`].
    pub signature: EdDSASignature,
    /// Inclusion of the account's [`world_id_primitives::secret_share::registry_leaf`].
    pub inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    /// The secret committed in the registry leaf.
    pub s: FieldElement,
    /// `0` for accounts without XMSS credentials.
    pub xmss_set_root: FieldElement,
    /// OPRF blinding factor.
    pub beta: ark_babyjubjub::Fr,
    /// The RP the query is for.
    pub rp_id: FieldElement,
    /// The RP's action.
    pub action: FieldElement,
    /// Binds the proof to the OPRF request.
    pub nonce: FieldElement,
}

/// Inputs to the `oprf-nullifier-v2` circuit.
pub struct OprfNullifierV2CircuitInput {
    /// The query the OPRF nodes evaluated.
    pub query: OprfQueryV2CircuitInput,
    /// The RP's OPRF public key.
    pub oprf_pk: EdwardsAffine,
    /// The OPRF nodes' DLog equality proof for the blinded response.
    pub dlog_e: ark_babyjubjub::Fq,
    /// The DLog equality proof's response.
    pub dlog_s: ark_babyjubjub::Fr,
    /// The unblinded OPRF response.
    pub oprf_response: EdwardsAffine,
}

/// Inputs to the `share-fetch-xmss` circuit.
pub struct ShareFetchXmssCircuitInput {
    /// The account's registered authenticator keys, part of its registry leaf.
    pub key_set: AuthenticatorPublicKeySet,
    /// Inclusion of the account's [`world_id_primitives::secret_share::registry_leaf`]; its index is public.
    pub inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    /// The account's `sCommit`, part of its registry leaf.
    pub s_commitment: FieldElement,
    /// The account's XMSS credential commitments; inactive slots hold `0`.
    pub xmss_commitments: [FieldElement; NUM_XMSS_SLOTS],
    /// Slot of the signing credential.
    pub xmss_slot: u64,
    /// Root of the signing credential's XMSS tree.
    pub xmss_root: FieldElement,
    /// The credential's public seed.
    pub pub_seed: FieldElement,
    /// The key deriving the credential's one-time-key tags.
    pub tag_key: FieldElement,
    /// Signature over [`world_id_primitives::secret_share::share_fetch_message`].
    pub signature: XmssSignature,
    /// The replay window the fetch is valid in.
    pub epoch: u64,
    /// Hash of the ML-KEM key the nodes encrypt the shares to.
    pub kem_pk_hash: FieldElement,
}

impl ShareFetchXmssCircuitInput {
    /// The one-time-key tag the nodes deduplicate on, a public input.
    #[must_use]
    pub fn tag(&self) -> FieldElement {
        xmss::tag(self.tag_key, self.signature.index)
    }
}

/// Proves `input` with `prover`.
///
/// # Errors
/// Returns [`ProofError`] if the inputs do not satisfy the circuit or proving fails.
pub fn prove<I: NoirCircuitInput>(
    input: I,
    prover: provekit_common::Prover,
) -> Result<WhirR1CSProof, ProofError> {
    provekit::prove(prover, input.into_witness()?)
}

/// Verifies `proof` against `public_inputs`: the circuit's public parameters in order, then its
/// return values.
///
/// # Errors
/// Returns [`ProofError::Verification`] if verification fails.
#[cfg(not(target_arch = "wasm32"))]
pub fn verify(
    verifier: &mut provekit_common::Verifier,
    public_inputs: &[FieldElement],
    proof: &WhirR1CSProof,
) -> Result<(), ProofError> {
    provekit::verify(verifier, public_inputs, proof)
}

impl NoirCircuitInput for OprfQueryV2CircuitInput {
    fn into_witness(self) -> Result<InputMap, ProofError> {
        let mut map = InputMap::new();
        insert_query_public_inputs(&mut map, &self);
        map.insert("inputs".into(), query_inputs(&self, BTreeMap::new()));
        Ok(map)
    }
}

impl NoirCircuitInput for OprfNullifierV2CircuitInput {
    fn into_witness(self) -> Result<InputMap, ProofError> {
        let mut map = InputMap::new();
        insert_query_public_inputs(&mut map, &self.query);
        map.insert("oprf_pk".into(), public_key(&self.oprf_pk));

        let mut extra = BTreeMap::new();
        extra.insert(
            "dlog_e".into(),
            InputValue::Field(to_noir_element(self.dlog_e)),
        );
        extra.insert(
            "dlog_s".into(),
            InputValue::Field(to_noir_element(self.dlog_s)),
        );
        extra.insert(
            "oprf_response".into(),
            InputValue::Vec(vec![
                InputValue::Field(to_noir_element(self.oprf_response.x)),
                InputValue::Field(to_noir_element(self.oprf_response.y)),
            ]),
        );
        map.insert("inputs".into(), query_inputs(&self.query, extra));
        Ok(map)
    }
}

impl NoirCircuitInput for ShareFetchXmssCircuitInput {
    fn into_witness(self) -> Result<InputMap, ProofError> {
        let mut map = InputMap::new();
        map.insert(
            "merkle_root".into(),
            self.inclusion_proof.root.into_noir_value(),
        );
        map.insert(
            "leaf_index".into(),
            InputValue::Field(NoirElement::from(self.inclusion_proof.leaf_index)),
        );
        map.insert(
            "epoch".into(),
            InputValue::Field(NoirElement::from(self.epoch)),
        );
        map.insert("kem_pk_hash".into(), self.kem_pk_hash.into_noir_value());
        map.insert("tag".into(), self.tag().into_noir_value());

        let mut key = BTreeMap::new();
        key.insert("pub_seed".into(), self.pub_seed.into_noir_value());
        key.insert("tag_key".into(), self.tag_key.into_noir_value());

        let mut sig = BTreeMap::new();
        sig.insert("chains".into(), fields(&self.signature.chains));
        sig.insert(
            "index".into(),
            InputValue::Field(NoirElement::from(self.signature.index)),
        );
        sig.insert("auth_path".into(), fields(&self.signature.auth_path));

        let mut inputs = BTreeMap::new();
        inputs.insert(
            "user_pk".into(),
            InputValue::Vec(
                self.key_set
                    .as_affine_array()
                    .iter()
                    .map(public_key)
                    .collect(),
            ),
        );
        inputs.insert("s_commitment".into(), self.s_commitment.into_noir_value());
        inputs.insert("xmss_commitments".into(), fields(&self.xmss_commitments));
        inputs.insert(
            "xmss_slot".into(),
            InputValue::Field(NoirElement::from(self.xmss_slot)),
        );
        inputs.insert("xmss_root".into(), self.xmss_root.into_noir_value());
        inputs.insert("key".into(), InputValue::Struct(key));
        inputs.insert("sig".into(), InputValue::Struct(sig));
        inputs.insert("siblings".into(), fields(&self.inclusion_proof.siblings));
        map.insert("inputs".into(), InputValue::Struct(inputs));
        Ok(map)
    }
}

fn insert_query_public_inputs(map: &mut InputMap, input: &OprfQueryV2CircuitInput) {
    map.insert(
        "merkle_root".into(),
        input.inclusion_proof.root.into_noir_value(),
    );
    map.insert("rp_id".into(), input.rp_id.into_noir_value());
    map.insert("action".into(), input.action.into_noir_value());
    map.insert("nonce".into(), input.nonce.into_noir_value());
}

fn query_inputs(
    input: &OprfQueryV2CircuitInput,
    mut extra: BTreeMap<String, InputValue>,
) -> InputValue {
    extra.insert(
        "account".into(),
        account_inputs(
            &input.key_set,
            input.key_index,
            &input.signature,
            &input.inclusion_proof,
        ),
    );
    extra.insert("s".into(), input.s.into_noir_value());
    extra.insert(
        "xmss_set_root".into(),
        input.xmss_set_root.into_noir_value(),
    );
    extra.insert(
        "beta".into(),
        InputValue::Field(to_noir_element(input.beta)),
    );
    InputValue::Struct(extra)
}

fn fields(values: &[FieldElement]) -> InputValue {
    InputValue::Vec(values.iter().map(|v| v.into_noir_value()).collect())
}

/// The prover and verifier keys `world-id-proof` embeds with the `embed-secret-share-prover` and
/// `embed-secret-share-verifier` features.
#[cfg(any(
    feature = "embed-secret-share-prover",
    feature = "embed-secret-share-verifier"
))]
pub mod embedded {
    /// One of the circuits in this module.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Circuit {
        /// `oprf-query-v2`.
        OprfQueryV2,
        /// `oprf-nullifier-v2`.
        OprfNullifierV2,
        /// `share-fetch-xmss`.
        ShareFetchXmss,
    }

    /// Loads the embedded prover for `circuit`.
    ///
    /// # Errors
    /// Fails if the embedded bytes cannot be deserialized.
    #[cfg(feature = "embed-secret-share-prover")]
    pub fn prover(circuit: Circuit) -> eyre::Result<provekit_common::Prover> {
        let bytes: &[u8] = match circuit {
            Circuit::OprfQueryV2 => {
                include_bytes!(concat!(env!("OUT_DIR"), "/oprf_query_v2.pkp"))
            }
            Circuit::OprfNullifierV2 => {
                include_bytes!(concat!(env!("OUT_DIR"), "/oprf_nullifier_v2.pkp"))
            }
            Circuit::ShareFetchXmss => {
                include_bytes!(concat!(env!("OUT_DIR"), "/share_fetch_xmss.pkp"))
            }
        };
        crate::provekit::load_prover_from_reader(bytes)
    }

    /// Loads the embedded verifier for `circuit`.
    ///
    /// # Errors
    /// Fails if the embedded bytes cannot be deserialized.
    #[cfg(all(feature = "embed-secret-share-verifier", not(target_arch = "wasm32")))]
    pub fn verifier(circuit: Circuit) -> eyre::Result<provekit_common::Verifier> {
        let bytes: &[u8] = match circuit {
            Circuit::OprfQueryV2 => {
                include_bytes!(concat!(env!("OUT_DIR"), "/oprf_query_v2.pkv"))
            }
            Circuit::OprfNullifierV2 => {
                include_bytes!(concat!(env!("OUT_DIR"), "/oprf_nullifier_v2.pkv"))
            }
            Circuit::ShareFetchXmss => {
                include_bytes!(concat!(env!("OUT_DIR"), "/share_fetch_xmss.pkv"))
            }
        };
        crate::provekit::load_verifier_from_reader(bytes)
    }
}
