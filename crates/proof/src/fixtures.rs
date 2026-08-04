use std::{collections::BTreeMap, env, fs, path::PathBuf};

use eddsa_babyjubjub::EdDSAPrivateKey;
use provekit_common::{InputMap, InputValue};
use world_id_primitives::{
    AuthenticatorPublicKeySet, Credential, FieldElement, TREE_DEPTH,
    merkle::{MerkleInclusionProof, first_leaf_merkle_path},
};

use crate::{
    NoirCircuitInput as _, circuit_inputs::OwnershipProofCircuitInput,
    ownership_proof::message_digest,
};

/// Builds static WIP-103 Ownership Proof fixture.
///
/// # Panics
/// Panics if the fixture cannot be built, not expected.
pub(crate) fn ownership_proof_fixture() -> OwnershipProofCircuitInput<TREE_DEPTH> {
    const LEAF_INDEX: u64 = 1;

    let sk = EdDSAPrivateKey::from_bytes([42u8; 32]);
    let key_set = AuthenticatorPublicKeySet::new(vec![sk.public()]).unwrap();
    let (siblings, root) = first_leaf_merkle_path(key_set.leaf_hash());

    let nonce = FieldElement::from(1_234_567_890u64); // <- this is an example, DO NOT use guessable nonces (see spec)
    let context = FieldElement::from(42u64);
    let commitment_blinder = FieldElement::from(999u64);
    let expected_commitment = Credential::compute_sub(LEAF_INDEX, commitment_blinder);

    OwnershipProofCircuitInput {
        key_index: 0,
        key_set,
        inclusion_proof: MerkleInclusionProof::new(root, LEAF_INDEX, siblings),
        nonce,
        expected_commitment,
        context,
        signature: sk.sign(*message_digest(expected_commitment, nonce, context)),
        commitment_blinder,
    }
}

mod ownership_proof_prover {
    use super::*;

    /// Every key the circuit ABI is expected to have, in `BTreeMap` (alphabetical) order. A circuit
    /// input added, removed or renamed without updating the renderer below fails these assertions.
    const TOP_LEVEL_KEYS: [&str; 6] = [
        "context",
        "depth",
        "expected_commitment",
        "inputs",
        "merkle_root",
        "nonce",
    ];
    const PRIVATE_KEYS: [&str; 6] = [
        "commitment_blinder",
        "merkle_proof",
        "pk_index",
        "query_r",
        "query_s",
        "user_pk",
    ];

    const HEADER: &str = "\
# Prover.toml for the Ownership Proof circuit (WIP-103).
#
# GENERATED FILE. Do not edit by hand; regenerate with:
#   UPDATE_PROVER_TOML=1 cargo test -p world-id-proof prover_toml
";

    fn fixture_witness() -> InputMap {
        ownership_proof_fixture()
            .into_witness()
            .expect("witness generation succeeds")
    }

    fn decimal(value: &InputValue, path: &str) -> String {
        match value {
            InputValue::Field(element) => element.into_repr().to_string(),
            other => panic!("expected `{path}` to be a field element, got {other:?}"),
        }
    }

    fn field(map: &BTreeMap<String, InputValue>, key: &str) -> String {
        decimal(
            map.get(key)
                .unwrap_or_else(|| panic!("missing field `{key}`")),
            key,
        )
    }

    fn array<'a>(map: &'a BTreeMap<String, InputValue>, key: &str) -> &'a [InputValue] {
        match map.get(key) {
            Some(InputValue::Vec(values)) => values,
            other => panic!("expected `{key}` to be an array, got {other:?}"),
        }
    }

    fn table<'a>(
        map: &'a BTreeMap<String, InputValue>,
        key: &str,
    ) -> &'a BTreeMap<String, InputValue> {
        match map.get(key) {
            Some(InputValue::Struct(fields)) => fields,
            other => panic!("expected `{key}` to be a struct, got {other:?}"),
        }
    }

    fn render(witness: &InputMap) -> String {
        let keys: Vec<&str> = witness.keys().map(String::as_str).collect();
        assert_eq!(
            keys, TOP_LEVEL_KEYS,
            "circuit public inputs changed; update this renderer"
        );
        let inputs = table(witness, "inputs");
        let input_keys: Vec<&str> = inputs.keys().map(String::as_str).collect();
        assert_eq!(
            input_keys, PRIVATE_KEYS,
            "circuit private inputs changed; update this renderer"
        );

        let mut out = String::from(HEADER);

        out.push_str("# Public inputs\n");
        for key in [
            "merkle_root",
            "depth",
            "nonce",
            "expected_commitment",
            "context",
        ] {
            out.push_str(&format!("{key} = \"{}\"\n", field(witness, key)));
        }

        out.push_str("\n[inputs]\nuser_pk = [\n");
        for (index, key) in array(inputs, "user_pk").iter().enumerate() {
            let path = format!("user_pk[{index}]");
            let InputValue::Struct(coordinates) = key else {
                panic!("expected `{path}` to be a struct, got {key:?}");
            };
            out.push_str(&format!(
                "    {{ x = \"{}\", y = \"{}\" }},\n",
                field(coordinates, "x"),
                field(coordinates, "y")
            ));
        }
        out.push_str("]\n");
        out.push_str(&format!("pk_index = \"{}\"\n", field(inputs, "pk_index")));
        out.push_str(&format!("query_s = \"{}\"\n", field(inputs, "query_s")));
        out.push_str("query_r = [\n");
        for (index, coordinate) in array(inputs, "query_r").iter().enumerate() {
            out.push_str(&format!(
                "    \"{}\",\n",
                decimal(coordinate, &format!("query_r[{index}]"))
            ));
        }
        out.push_str("]\n");

        let merkle_proof = table(inputs, "merkle_proof");
        out.push_str("\n# Merkle proof\n");
        out.push_str(&format!(
            "merkle_proof.leaf_index = \"{}\"\n",
            field(merkle_proof, "leaf_index")
        ));
        out.push_str("merkle_proof.siblings = [\n");
        for (index, sibling) in array(merkle_proof, "siblings").iter().enumerate() {
            out.push_str(&format!(
                "    \"{}\",\n",
                decimal(sibling, &format!("siblings[{index}]"))
            ));
        }
        out.push_str("]\n");

        out.push_str("\n# Commitment blinder\n");
        out.push_str(&format!(
            "commitment_blinder = \"{}\"\n",
            field(inputs, "commitment_blinder")
        ));

        out
    }

    #[test]
    fn prover_toml_matches_the_circuit_input_fixture() {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("noir/ownership-proof/Prover.toml");
        let rendered = render(&fixture_witness());

        if env::var_os("UPDATE_PROVER_TOML").is_some() {
            fs::write(&path, &rendered)
                .unwrap_or_else(|e| panic!("failed to write {}: {e}", path.display()));
            return;
        }

        let committed = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        assert_eq!(
            committed,
            rendered,
            "{} is out of date; regenerate with `UPDATE_PROVER_TOML=1 cargo test -p world-id-proof \
         prover_toml`",
            path.display()
        );
    }
}
