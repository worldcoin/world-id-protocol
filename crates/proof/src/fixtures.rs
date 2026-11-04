use std::{collections::BTreeMap, env, fs, path::PathBuf};

use eddsa_babyjubjub::EdDSAPrivateKey;
use provekit_common::{InputMap, InputValue};
use world_id_primitives::{
    AuthenticatorPublicKeySet, Credential, FieldElement, TREE_DEPTH,
    merkle::MerkleInclusionProof,
    poseidon::{self, ds},
};
use world_id_test_utils::merkle::first_leaf_merkle_path;

use crate::{NoirCircuitInput as _, circuit_inputs::OwnershipProofCircuitInput};

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
    let message = poseidon::hash(ds::OWNERSHIP_PROOF, [expected_commitment, nonce, context]);

    OwnershipProofCircuitInput {
        key_index: 0,
        key_set,
        inclusion_proof: MerkleInclusionProof::new(root, LEAF_INDEX, siblings),
        nonce,
        expected_commitment,
        context,
        signature: sk.sign(*message),
        commitment_blinder,
    }
}

/// `Prover.toml` shapes the Noir circuits share: field elements are decimal strings.
pub(crate) mod toml_types {
    use ark_ff::PrimeField as _;
    use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
    use serde::Serialize;

    /// A `world_id_components::types::PublicKey`.
    #[derive(Serialize)]
    pub(crate) struct PublicKey {
        pub(crate) x: String,
        pub(crate) y: String,
    }

    /// A `world_id_components::types::Signature`.
    #[derive(Serialize)]
    pub(crate) struct Signature {
        pub(crate) s: String,
        pub(crate) r: Vec<String>,
    }

    impl From<&EdDSAPublicKey> for PublicKey {
        fn from(key: &EdDSAPublicKey) -> Self {
            Self {
                x: key.pk.x.into_bigint().to_string(),
                y: key.pk.y.into_bigint().to_string(),
            }
        }
    }

    impl From<&EdDSASignature> for Signature {
        fn from(sig: &EdDSASignature) -> Self {
            Self {
                s: sig.s.into_bigint().to_string(),
                r: vec![
                    sig.r.x.into_bigint().to_string(),
                    sig.r.y.into_bigint().to_string(),
                ],
            }
        }
    }
}

mod ownership_proof_prover {
    use serde::Serialize;

    use super::{
        toml_types::{PublicKey, Signature},
        *,
    };

    /// Every key the circuit ABI is expected to have, in `BTreeMap` (alphabetical) order. A circuit
    /// input added, removed or renamed without updating the renderer below fails these assertions.
    const TOP_LEVEL_KEYS: [&str; 5] = [
        "context",
        "expected_commitment",
        "inputs",
        "merkle_root",
        "nonce",
    ];
    const PRIVATE_KEYS: [&str; 2] = ["account", "commitment_blinder"];
    const ACCOUNT_KEYS: [&str; 5] = ["leaf_index", "pk_index", "siblings", "sig", "user_pk"];

    const HEADER: &str = "\
# Prover.toml for the Ownership Proof circuit (WIP-103).
#
# GENERATED FILE. Do not edit by hand; regenerate with:
#   UPDATE_PROVER_TOML=1 cargo test -p world-id-proof prover_toml

# Public inputs
";

    #[derive(Serialize)]
    struct ProverToml {
        merkle_root: String,
        nonce: String,
        expected_commitment: String,
        context: String,
        inputs: PrivateInputs,
    }

    #[derive(Serialize)]
    struct PrivateInputs {
        commitment_blinder: String,
        account: AccountInputs,
    }

    #[derive(Serialize)]
    struct AccountInputs {
        pk_index: String,
        leaf_index: String,
        siblings: Vec<String>,
        sig: Signature,
        user_pk: Vec<PublicKey>,
    }

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

        let account = table(inputs, "account");
        let account_keys: Vec<&str> = account.keys().map(String::as_str).collect();
        assert_eq!(
            account_keys, ACCOUNT_KEYS,
            "circuit account inputs changed; update this renderer"
        );

        let user_pk = array(account, "user_pk")
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let path = format!("user_pk[{index}]");
                let InputValue::Struct(coordinates) = key else {
                    panic!("expected `{path}` to be a struct, got {key:?}");
                };
                PublicKey {
                    x: field(coordinates, "x"),
                    y: field(coordinates, "y"),
                }
            })
            .collect();
        let sig = table(account, "sig");
        let sig_r = array(sig, "r")
            .iter()
            .enumerate()
            .map(|(index, coordinate)| decimal(coordinate, &format!("sig.r[{index}]")))
            .collect();

        let siblings = array(account, "siblings")
            .iter()
            .enumerate()
            .map(|(index, sibling)| decimal(sibling, &format!("siblings[{index}]")))
            .collect();

        let prover_toml = ProverToml {
            merkle_root: field(witness, "merkle_root"),
            nonce: field(witness, "nonce"),
            expected_commitment: field(witness, "expected_commitment"),
            context: field(witness, "context"),
            inputs: PrivateInputs {
                commitment_blinder: field(inputs, "commitment_blinder"),
                account: AccountInputs {
                    pk_index: field(account, "pk_index"),
                    leaf_index: field(account, "leaf_index"),
                    siblings,
                    sig: Signature {
                        s: field(sig, "s"),
                        r: sig_r,
                    },
                    user_pk,
                },
            },
        };

        format!(
            "{HEADER}{}",
            toml::to_string_pretty(&prover_toml).expect("fixture serializes to TOML")
        )
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
