//! The RP's policy for Proofs of Embedding Similarity, read from a JSON file.
//!
//! The policy names what the RP accepts beyond its own request (WIP-202 §4.8): the Flamingo
//! Verifier enclaves, the Engine configurations, the AAT values and the Credential's
//! `issuer_version`. See `policy.example.json`.

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use pontifex::attestation::{self, PCR_LENGTH, PcrConfig};
use serde::{Deserialize, Deserializer};
use world_id_primitives::FieldElement;
use world_id_rp::embedding_similarity::{
    AatPolicy, AcceptedAatFlags, EmbeddingSimilarityPolicy, nitro_attestation_verifier,
};

/// Why a policy file was not loaded.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The file could not be read.
    #[error("failed to read the policy at {path}: {source}")]
    Read {
        /// The policy's path.
        path: PathBuf,
        /// The read error.
        source: std::io::Error,
    },
    /// The file is not a policy document.
    #[error("invalid policy: {0}")]
    Parse(#[from] serde_json::Error),
    /// The policy accepts no Flamingo Verifier, so it would reject every proof.
    #[error("the policy accepts no Flamingo Verifier")]
    NoFlamingoVerifiers,
    /// A Flamingo Verifier's PCR0 is all zero, which every debug-mode enclave reports (WIP-201
    /// §4.7 check 1).
    #[error("flamingo_verifiers[{0}] has an all-zero PCR0, which every debug-mode enclave reports")]
    DebugModePcrs(usize),
    /// The policy accepts no Engine configuration, so it would reject every proof.
    #[error("the policy accepts no Engine configuration")]
    NoEngineConfigs,
    /// The AAT policy accepts no AAT although it requires one, or lists trust anchors without flag
    /// combinations or the reverse.
    #[error(
        "the AAT policy accepts no AAT: trust_anchor_key_hashes and accepted_flags must both be \
         empty or both be set, and set when an AAT is required"
    )]
    AcceptsNoAat,
}

/// Loads the policy file at `path`.
///
/// # Errors
/// The file cannot be read or is not a valid policy, see [`parse`].
pub fn load(path: &Path) -> Result<EmbeddingSimilarityPolicy<attestation::Verifier>, PolicyError> {
    let json = fs::read_to_string(path).map_err(|source| PolicyError::Read {
        path: path.to_owned(),
        source,
    })?;
    parse(&json)
}

/// Parses a policy document.
///
/// Unknown fields are rejected, so a misspelt key fails startup rather than loosening or
/// tightening the policy unnoticed.
///
/// # Errors
/// The document is malformed, or accepts no Flamingo Verifier, no Engine configuration, or no
/// AAT where one is required.
pub fn parse(json: &str) -> Result<EmbeddingSimilarityPolicy<attestation::Verifier>, PolicyError> {
    let file: PolicyFile = serde_json::from_str(json)?;
    file.try_into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    issuer_version: u8,
    flamingo_verifiers: Vec<FlamingoVerifierPcrs>,
    engine_config_hashes: Vec<FieldElement>,
    aat: AatPolicyFile,
}

/// PCR0–2 of a Flamingo Verifier enclave image the RP accepts (WIP-201 §4.7 check 1).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FlamingoVerifierPcrs {
    pcr0: Pcr,
    pcr1: Pcr,
    pcr2: Pcr,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AatPolicyFile {
    required: bool,
    trust_anchor_key_hashes: Vec<FieldElement>,
    accepted_flags: Vec<AatFlags>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AatFlags {
    platform: u8,
    sec_level: u8,
    sec_meta: u8,
    authenticator_meta: u8,
}

/// A PCR value, as the hex string `nitro-cli describe-eif` prints.
struct Pcr([u8; PCR_LENGTH]);

impl<'de> Deserialize<'de> for Pcr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let hex = String::deserialize(deserializer)?;
        let bytes = hex::decode(hex.trim_start_matches("0x")).map_err(serde::de::Error::custom)?;
        let bytes = bytes.try_into().map_err(|bytes: Vec<u8>| {
            serde::de::Error::custom(format!("a PCR is {PCR_LENGTH} bytes, got {}", bytes.len()))
        })?;
        Ok(Self(bytes))
    }
}

impl TryFrom<PolicyFile> for EmbeddingSimilarityPolicy<attestation::Verifier> {
    type Error = PolicyError;

    fn try_from(file: PolicyFile) -> Result<Self, Self::Error> {
        if file.flamingo_verifiers.is_empty() {
            return Err(PolicyError::NoFlamingoVerifiers);
        }
        let pcr_configs = file
            .flamingo_verifiers
            .into_iter()
            .enumerate()
            .map(|(index, pcrs)| pcrs.into_pcr_config(index))
            .collect::<Result<_, _>>()?;
        if file.engine_config_hashes.is_empty() {
            return Err(PolicyError::NoEngineConfigs);
        }
        Ok(Self {
            attestation: nitro_attestation_verifier(pcr_configs),
            engine_config_hashes: file.engine_config_hashes.into_iter().collect(),
            issuer_version: file.issuer_version,
            aat: file.aat.try_into()?,
        })
    }
}

impl FlamingoVerifierPcrs {
    fn into_pcr_config(self, index: usize) -> Result<PcrConfig, PolicyError> {
        if self.pcr0.0 == [0; PCR_LENGTH] {
            return Err(PolicyError::DebugModePcrs(index));
        }
        Ok(PcrConfig::new(self.pcr0.0)
            .with_pcr(1, self.pcr1.0)
            .with_pcr(2, self.pcr2.0))
    }
}

impl TryFrom<AatPolicyFile> for AatPolicy {
    type Error = PolicyError;

    fn try_from(file: AatPolicyFile) -> Result<Self, Self::Error> {
        let lists_anchors = !file.trust_anchor_key_hashes.is_empty();
        let lists_flags = !file.accepted_flags.is_empty();
        if lists_anchors != lists_flags || (file.required && !lists_anchors) {
            return Err(PolicyError::AcceptsNoAat);
        }
        Ok(Self {
            required: file.required,
            trust_anchor_key_hashes: file.trust_anchor_key_hashes.into_iter().collect(),
            accepted_flags: file
                .accepted_flags
                .into_iter()
                .map(|flags| AcceptedAatFlags {
                    platform: flags.platform,
                    sec_level: flags.sec_level,
                    sec_meta: flags.sec_meta,
                    authenticator_meta: flags.authenticator_meta,
                })
                .collect::<HashSet<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn policy() -> Value {
        json!({
            "issuer_version": 1,
            "flamingo_verifiers": [{
                "pcr0": "11".repeat(PCR_LENGTH),
                "pcr1": "22".repeat(PCR_LENGTH),
                "pcr2": "33".repeat(PCR_LENGTH),
            }],
            "engine_config_hashes": [format!("0x{}", "01".repeat(32))],
            "aat": {
                "required": false,
                "trust_anchor_key_hashes": [],
                "accepted_flags": [],
            },
        })
    }

    fn parse_value(
        value: &Value,
    ) -> Result<EmbeddingSimilarityPolicy<attestation::Verifier>, PolicyError> {
        parse(&value.to_string())
    }

    #[test]
    fn parses_a_complete_policy() {
        let mut value = policy();
        value["aat"] = json!({
            "required": true,
            "trust_anchor_key_hashes": [format!("0x{}", "02".repeat(32))],
            "accepted_flags": [{"platform": 1, "sec_level": 2, "sec_meta": 0, "authenticator_meta": 3}],
        });

        let policy = parse_value(&value).unwrap();

        assert_eq!(policy.issuer_version, 1);
        assert_eq!(policy.engine_config_hashes.len(), 1);
        assert!(policy.aat.required);
        assert!(policy.aat.accepted_flags.contains(&AcceptedAatFlags {
            platform: 1,
            sec_level: 2,
            sec_meta: 0,
            authenticator_meta: 3,
        }));
    }

    #[test]
    fn rejects_unknown_fields() {
        let mut value = policy();
        value["aat"]["requried"] = json!(true);

        assert!(matches!(parse_value(&value), Err(PolicyError::Parse(_))));
    }

    #[test]
    fn rejects_pcrs_of_the_wrong_length() {
        let mut value = policy();
        value["flamingo_verifiers"][0]["pcr1"] = json!("22".repeat(32));

        assert!(matches!(parse_value(&value), Err(PolicyError::Parse(_))));
    }

    #[test]
    fn rejects_debug_mode_pcrs() {
        let mut value = policy();
        value["flamingo_verifiers"] = json!([
            policy()["flamingo_verifiers"][0],
            {"pcr0": "00".repeat(PCR_LENGTH), "pcr1": "00".repeat(PCR_LENGTH), "pcr2": "00".repeat(PCR_LENGTH)},
        ]);

        assert!(matches!(
            parse_value(&value),
            Err(PolicyError::DebugModePcrs(1))
        ));
    }

    #[test]
    fn rejects_policies_that_accept_nothing() {
        let mut no_verifiers = policy();
        no_verifiers["flamingo_verifiers"] = json!([]);
        let mut no_engines = policy();
        no_engines["engine_config_hashes"] = json!([]);

        assert!(matches!(
            parse_value(&no_verifiers),
            Err(PolicyError::NoFlamingoVerifiers)
        ));
        assert!(matches!(
            parse_value(&no_engines),
            Err(PolicyError::NoEngineConfigs)
        ));
    }

    #[test]
    fn rejects_aat_policies_that_accept_no_aat() {
        let mut required_without_anchors = policy();
        required_without_anchors["aat"]["required"] = json!(true);
        let mut anchors_without_flags = policy();
        anchors_without_flags["aat"]["trust_anchor_key_hashes"] =
            json!([format!("0x{}", "02".repeat(32))]);

        assert!(matches!(
            parse_value(&required_without_anchors),
            Err(PolicyError::AcceptsNoAat)
        ));
        assert!(matches!(
            parse_value(&anchors_without_flags),
            Err(PolicyError::AcceptsNoAat)
        ));
    }
}
