use super::constants::{AUTHENTICATOR_DATA_MAX_LEN, CLIENT_DATA_JSON_MAX_LEN, MAX_DEPTH, NUM_KEYS};

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
}

pub struct PasskeyOwnershipInputs {
    pub webauthn: WebAuthnWitness,
    pub slot_commitments: [Field; NUM_KEYS],
    pub passkey_slot_index: u32,
    pub merkle_proof: MerkleProof,
}
