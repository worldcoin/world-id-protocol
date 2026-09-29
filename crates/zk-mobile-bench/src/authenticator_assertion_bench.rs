//! Witness mapping and embedded prover for the `authenticator-assertion-bench`
//! circuit (WIP-106 reference consumer; benchmark-only, not a proof type).

use std::collections::BTreeMap;

use ark_ff::{BigInteger as _, PrimeField as _};
use eddsa_babyjubjub::EdDSASignature;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use provekit_common::{InputMap, InputValue, NoirElement};
use world_id_primitives::FieldElement;
use world_id_proof::authenticator_attestation::{
    AuthenticatorAssertionClaims, TrustAnchorKeyClaims,
};

/// Maximum remaining AAT validity in seconds; mirrors `MAX_AAT_LIFETIME_SECS` in `aat.nr`.
pub const MAX_AAT_LIFETIME_SECS: u32 = 1800;

/// Maximum remaining TAKT validity in seconds; mirrors `MAX_TAKT_LIFETIME_SECS` in `takt.nr`.
pub const MAX_TAKT_LIFETIME_SECS: u32 = 604_800;

const PKP_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/authenticator_assertion_bench.pkp"
));

#[cfg(test)]
const PKV_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/authenticator_assertion_bench.pkv"
));

/// Inputs for the bench circuit; the public inputs are derived from the token
/// fields during witness generation, so they cannot diverge from the tokens.
#[derive(Debug, Clone)]
pub struct AuthenticatorAssertionBenchInput {
    /// Public. The Authenticator Provider's `trust_anchor_key`.
    pub trust_anchor_key: ark_babyjubjub::EdwardsAffine,
    /// Public. Verifier-supplied Unix time in seconds.
    pub now: u32,
    /// Private. The AAT claims; the bound claims are re-exposed as public inputs.
    pub aat_claims: AuthenticatorAssertionClaims,
    /// Private. ES256 signature over the AAT's COSE `Sig_structure` (`r || s`, low-S).
    pub aat_signature: [u8; 64],
    /// Private. The TAKT claims; the packed `sec_flags` is re-exposed as a public input.
    pub takt_claims: TrustAnchorKeyClaims,
    /// Private. EdDSA-BabyJubJub signature over the TAKT claim digest.
    pub takt_signature: EdDSASignature,
}

/// Loads the embedded ProveKit prover for the bench circuit.
///
/// # Errors
/// Fails if the embedded bytes cannot be deserialized.
pub fn load_embedded_prover() -> eyre::Result<provekit_common::Prover> {
    provekit_common::register_ntt();
    provekit_common::file::deserialize(PKP_BYTES).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Loads the embedded ProveKit verifier for the bench circuit.
///
/// # Errors
/// Fails if the embedded bytes cannot be deserialized.
#[cfg(test)]
pub fn load_embedded_verifier() -> eyre::Result<provekit_common::Verifier> {
    provekit_common::register_ntt();
    provekit_common::file::deserialize(PKV_BYTES).map_err(|e| eyre::eyre!(e.to_string()))
}

/// Emulates the circuit's token freshness constraints so a broken fixture
/// surfaces as a specific panic instead of an opaque proving failure.
///
/// # Panics
/// Panics if a token is expired, over its lifetime cap, or has an `exp`
/// outside the fixed-width `[2^16, 2^32)` window.
pub fn check_input_freshness(input: &AuthenticatorAssertionBenchInput) {
    for (token, exp, cap) in [
        ("AAT", input.aat_claims.exp, MAX_AAT_LIFETIME_SECS),
        ("TAKT", input.takt_claims.exp, MAX_TAKT_LIFETIME_SECS),
    ] {
        assert!(u16::try_from(exp).is_err(), "{token} exp below 2^16");
        assert!(input.now < exp, "{token} is expired");
        assert!(exp - input.now <= cap, "{token} over its lifetime cap");
    }
}

fn field(value: FieldElement) -> InputValue {
    InputValue::Field(NoirElement::from_repr(*value))
}

fn uint(value: u64) -> InputValue {
    InputValue::Field(NoirElement::from(value))
}

fn bytes(bytes: &[u8]) -> InputValue {
    InputValue::Vec(bytes.iter().map(|b| uint(u64::from(*b))).collect())
}

impl AuthenticatorAssertionBenchInput {
    /// Maps the input onto the circuit ABI.
    ///
    /// # Panics
    /// Panics if the assertion key has no affine coordinates, not expected.
    #[must_use]
    pub fn into_witness(self) -> InputMap {
        let point = self.takt_claims.assertion_key.to_encoded_point(false);
        let assertion_key_x = point.x().expect("assertion key affine x");
        let assertion_key_y = point.y().expect("assertion key affine y");

        let mut map = InputMap::new();

        // Public inputs, derived from the token fields so the bindings hold by construction.
        map.insert(
            "trust_anchor_key_x".into(),
            InputValue::Field(NoirElement::from_repr(self.trust_anchor_key.x)),
        );
        map.insert(
            "trust_anchor_key_y".into(),
            InputValue::Field(NoirElement::from_repr(self.trust_anchor_key.y)),
        );
        map.insert("now".into(), uint(u64::from(self.now)));
        map.insert("aud".into(), uint(self.aat_claims.aud.into_inner()));
        map.insert("nonce".into(), field(self.aat_claims.nonce));
        map.insert("cdh".into(), field(self.aat_claims.cdh));
        map.insert(
            "authenticator_meta".into(),
            uint(self.aat_claims.authenticator_meta.packed()),
        );
        map.insert("sec_flags".into(), uint(self.takt_claims.sec_flags()));

        let mut aat: BTreeMap<String, InputValue> = BTreeMap::new();
        aat.insert("aud".into(), uint(self.aat_claims.aud.into_inner()));
        aat.insert("exp".into(), uint(u64::from(self.aat_claims.exp)));
        aat.insert("nonce".into(), field(self.aat_claims.nonce));
        aat.insert("cdh".into(), field(self.aat_claims.cdh));
        aat.insert(
            "authenticator_meta".into(),
            uint(self.aat_claims.authenticator_meta.packed()),
        );
        aat.insert("signature".into(), bytes(&self.aat_signature));
        map.insert("aat".into(), InputValue::Struct(aat));

        let mut takt: BTreeMap<String, InputValue> = BTreeMap::new();
        takt.insert("exp".into(), uint(u64::from(self.takt_claims.exp)));
        takt.insert("assertion_key_x".into(), bytes(assertion_key_x));
        takt.insert("assertion_key_y".into(), bytes(assertion_key_y));
        takt.insert("sec_flags".into(), uint(self.takt_claims.sec_flags()));
        // babyjubjub scalar → bn254 scalar via big-endian bytes
        let s_native = ark_bn254::Fr::from_be_bytes_mod_order(
            &self.takt_signature.s.into_bigint().to_bytes_be(),
        );
        takt.insert(
            "sig_s".into(),
            InputValue::Field(NoirElement::from_repr(s_native)),
        );
        takt.insert(
            "sig_r".into(),
            InputValue::Vec(vec![
                InputValue::Field(NoirElement::from_repr(self.takt_signature.r.x)),
                InputValue::Field(NoirElement::from_repr(self.takt_signature.r.y)),
            ]),
        );
        map.insert("takt".into(), InputValue::Struct(takt));

        map
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs, path::PathBuf};

    use super::*;
    use crate::fixtures::authenticator_assertion_bench_fixture;

    /// Every key the circuit ABI is expected to have, in `BTreeMap` (alphabetical) order.
    const TOP_LEVEL_KEYS: [&str; 10] = [
        "aat",
        "aud",
        "authenticator_meta",
        "cdh",
        "nonce",
        "now",
        "sec_flags",
        "takt",
        "trust_anchor_key_x",
        "trust_anchor_key_y",
    ];

    const HEADER: &str = "\
# Prover.toml for the Authenticator Assertion bench circuit (WIP-106).
#
# GENERATED FILE. Do not edit by hand; regenerate with:
#   UPDATE_PROVER_TOML=1 cargo test -p zk-mobile-bench prover_toml
";

    /// End-to-end prove + verify, with a tampered-public-input negative control.
    #[test]
    #[ignore = "expensive proving test; the mobench workflow covers the proving path"]
    fn proves_and_verifies_the_fixture() {
        use provekit_prover::Prove as _;
        use provekit_verifier::Verify as _;

        let mut prover = load_embedded_prover().expect("embedded prover");
        let mut verifier = load_embedded_verifier().expect("embedded verifier");

        let witness = prover
            .generate_witness(authenticator_assertion_bench_fixture().into_witness())
            .expect("witness generation");
        let proof = prover.prove_with_witness(witness).expect("WHIR proving");
        verifier.verify(&proof).expect("proof verifies");

        // Negative control: flipping `now` (public input index 2) must fail.
        let mut tampered = proof;
        tampered.public_inputs.0[2] += ark_bn254::Fr::from(1u64);
        verifier
            .verify(&tampered)
            .expect_err("tampered public input must not verify");
    }

    fn to_toml(value: &InputValue, path: &str) -> toml::Value {
        match value {
            InputValue::Field(element) => toml::Value::String(element.into_repr().to_string()),
            InputValue::Vec(values) => toml::Value::Array(
                values
                    .iter()
                    .enumerate()
                    .map(|(index, value)| to_toml(value, &format!("{path}[{index}]")))
                    .collect(),
            ),
            InputValue::Struct(fields) => toml::Value::Table(
                fields
                    .iter()
                    .map(|(key, value)| (key.clone(), to_toml(value, &format!("{path}.{key}"))))
                    .collect(),
            ),
            other => panic!("`{path}` has no TOML rendering: {other:?}"),
        }
    }

    fn render(witness: &InputMap) -> String {
        let keys: Vec<&str> = witness.keys().map(String::as_str).collect();
        assert_eq!(
            keys, TOP_LEVEL_KEYS,
            "circuit inputs changed; update TOP_LEVEL_KEYS and regenerate"
        );

        // Scalars must precede tables in TOML, so partition before rendering.
        let mut table = toml::map::Map::new();
        for (key, value) in witness
            .iter()
            .filter(|(_, v)| !matches!(v, InputValue::Struct(_)))
            .chain(
                witness
                    .iter()
                    .filter(|(_, v)| matches!(v, InputValue::Struct(_))),
            )
        {
            table.insert(key.clone(), to_toml(value, key));
        }

        format!(
            "{HEADER}{}",
            toml::to_string_pretty(&table).expect("fixture serializes to TOML")
        )
    }

    /// Keeps the circuit's committed `Prover.toml` in sync with the fixture.
    #[test]
    fn prover_toml_matches_the_fixture() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../proof/noir/authenticator-assertion-bench/Prover.toml");
        let rendered = render(&authenticator_assertion_bench_fixture().into_witness());

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
            "{} is out of date; regenerate with `UPDATE_PROVER_TOML=1 cargo test -p \
             zk-mobile-bench prover_toml`",
            path.display()
        );
    }
}
