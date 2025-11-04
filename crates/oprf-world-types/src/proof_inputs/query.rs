use serde::Serialize;

type BaseField = ark_babyjubjub::Fq;
type ScalarField = ark_babyjubjub::Fr;
type Affine = ark_babyjubjub::EdwardsAffine;

pub const MAX_PUBLIC_KEYS: usize = 7;

#[derive(Debug, Clone, Serialize)]
pub struct QueryProofInput<const MAX_DEPTH: usize> {
    // Signature
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine_sequence")]
    pub pk: [Affine; MAX_PUBLIC_KEYS],
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub pk_index: BaseField, // 0..6
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fr")]
    pub s: ScalarField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    pub r: Affine,
    // Credential Signature
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub cred_type_id: BaseField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    pub cred_pk: Affine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq_sequence")]
    pub cred_hashes: [BaseField; 2], // [claims_hash, associated_data_hash]
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub cred_genesis_issued_at: BaseField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub cred_expires_at: BaseField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fr")]
    pub cred_s: ScalarField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_affine")]
    pub cred_r: Affine,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub current_time_stamp: BaseField,
    // Merkle proof
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub merkle_root: BaseField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub depth: BaseField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub mt_index: BaseField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq_sequence")]
    pub siblings: [BaseField; MAX_DEPTH],
    // OPRF query
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fr")]
    pub beta: ScalarField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub rp_id: BaseField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub action: BaseField,
    #[serde(serialize_with = "ark_serde_compat::serialize_babyjubjub_fq")]
    pub nonce: BaseField,
}
