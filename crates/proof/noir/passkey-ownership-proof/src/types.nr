use super::constants::{
    AUTHENTICATOR_DATA_MAX_LEN, CLIENT_DATA_JSON_MAX_LEN, MAX_DEPTH, NUM_KEYS, P256_LIMBS,
    P256_SCALAR_SLICES,
};

pub struct MerkleProof {
    pub leaf_index: u32,
    pub siblings: [Field; MAX_DEPTH],
}

pub struct WebAuthnWitness {
    pub public_key_x: [u8; 32],
    pub public_key_y: [u8; 32],
    pub signature: [u8; 64],
    pub client_data_json: BoundedVec<u8, CLIENT_DATA_JSON_MAX_LEN>,
    pub authenticator_data: BoundedVec<u8, AUTHENTICATOR_DATA_MAX_LEN>,
    pub challenge_index: u32,
    pub r_point_y: [u8; 32],
    pub message_limbs: [u128; P256_LIMBS],
    pub public_key_x_limbs: [u128; P256_LIMBS],
    pub public_key_y_limbs: [u128; P256_LIMBS],
    pub signature_r_limbs: [u128; P256_LIMBS],
    pub signature_s_limbs: [u128; P256_LIMBS],
    pub r_point_y_limbs: [u128; P256_LIMBS],
    pub s_g_limbs: [u128; P256_LIMBS],
    pub s_g_slices: [u8; P256_SCALAR_SLICES],
    pub s_g_skew: bool,
    pub s_g_borrow_low: bool,
    pub s_g_borrow_mid: bool,
    pub s_p_limbs: [u128; P256_LIMBS],
    pub s_p_slices: [u8; P256_SCALAR_SLICES],
    pub s_p_skew: bool,
    pub s_p_borrow_low: bool,
    pub s_p_borrow_mid: bool,
}

pub struct PasskeyOwnershipInputs {
    pub webauthn: WebAuthnWitness,
    pub public_key_x_limbs_field: [Field; P256_LIMBS],
    pub public_key_y_limbs_field: [Field; P256_LIMBS],
    pub slot_commitments: [Field; NUM_KEYS],
    pub passkey_slot_index: u32,
    pub merkle_proof: MerkleProof,
}
