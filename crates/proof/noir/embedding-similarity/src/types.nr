use super::constants::{MAX_CLAIMS, MERKLE_DEPTH, NUM_KEYS};

/// An EdDSA public key over the BabyJubJub curve, represented as its affine coordinates (x, y).
pub struct PublicKey {
    pub x: Field,
    pub y: Field,
}

/// The `WorldIDRegistry` witness: the key set, its inclusion proof, and the
/// authenticator authorization signature (WIP-111 constraints 1-5, 10).
pub struct RegistryInputs {
    /// Authenticator public keys registered in the `WorldIDRegistry`, in slot
    /// order; inactive slots hold the identity (0, 1).
    pub user_pk: [PublicKey; NUM_KEYS],
    /// The index in `user_pk` of the key that signed the authorization message.
    pub pk_index: Field,
    /// The `s` component of the authorization signature (`sig_s` in WIP-111).
    pub sig_s: Field,
    /// The `r` component of the authorization signature (`sig_r` in WIP-111).
    pub sig_r: [Field; 2],
    /// Index of the user's World ID in the `WorldIDRegistry`.
    pub leaf_index: Field,
    /// Sibling nodes from `leaf_index` upwards.
    pub siblings: [Field; MERKLE_DEPTH],
}

/// The Credential fields covered by the Issuer signature (WIP-111 constraints 6-9).
///
/// Field names drop the `cred_` prefix WIP-111 uses; `sig_s`/`sig_r` are the
/// spec's `cred_s`/`cred_r`.
pub struct CredentialInputs {
    /// Credential claims; `claims[claim_index]` holds the credential commitment.
    pub claims: [Field; MAX_CLAIMS],
    /// Commitment to the credential's associated data (`cred_associated_data_hash`).
    pub associated_data_hash: Field,
    /// Timestamp of first issuance, Unix seconds (`cred_genesis_issued_at`).
    pub genesis_issued_at: Field,
    /// Expiration timestamp, Unix seconds (`cred_expires_at`).
    pub expires_at: Field,
    /// Blinding factor of the credential subject (`cred_sub_blinding_factor`).
    pub sub_blinding_factor: Field,
    /// Issuer-scoped credential identifier (`cred_id`), `< 2^64`.
    pub id: Field,
    /// The `s` component of the Issuer signature (`cred_s` in WIP-111).
    pub sig_s: Field,
    /// The `r` component of the Issuer signature (`cred_r` in WIP-111).
    pub sig_r: [Field; 2],
}

/// The WIP-110 Verifier token (`cwt`) witness: the claims the circuit reads and
/// the EdDSA signature over their digest (WIP-111 constraint 14).
///
/// The `challenge_commitment` claim is not carried here: it is bound to the
/// public input of the same name by hashing that input into the signed digest.
pub struct VerifierTokenInputs {
    /// Time of the comparison, seconds since the Unix epoch (`iat`).
    pub iat: Field,
    /// Commitment to the credential item the Verifier compared against.
    pub credential_commitment: Field,
    /// Commitment to the live capture the Verifier compared.
    pub live_commitment: Field,
    /// Score for live against credential.
    pub similarity_live: Field,
    /// Score for challenge against credential; `0` in the 2-way flow.
    pub similarity_challenge: Field,
    /// The `s` component of the Verifier's EdDSA signature.
    pub sig_s: Field,
    /// The `r` component of the Verifier's EdDSA signature.
    pub sig_r: [Field; 2],
}

/// The parsed TAKT witness (WIP-106). The `trust_anchor_key` is not carried
/// here: the token is reassembled from the public input of the same name, which
/// binds it into the signature check.
pub struct TaktInputs {
    /// Expiration as seconds since the Unix epoch (CWT `exp`).
    pub exp: Field,
    /// Big-endian affine x coordinate of the attested assertion key (`cnf`).
    pub assertion_key_x: [u8; 32],
    /// Big-endian affine y coordinate of the attested assertion key (`cnf`).
    pub assertion_key_y: [u8; 32],
    /// Packed security attributes (`sec_flags`).
    pub sec_flags: Field,
    /// EdDSA signature scalar component.
    pub sig_s: Field,
    /// EdDSA signature point component (affine x, y).
    pub sig_r: [Field; 2],
}

/// All private inputs of the Embedding Similarity Proof.
///
/// The AAT witness is only its `exp` and `ES256` signature: every other AAT
/// claim (`aud`, `nonce`, `signal`/`cdh`, `authenticator_meta`) is reassembled
/// from the public inputs and the `cwt` witness it must equal, which enforces
/// the equality constraints by construction.
pub struct PrivateInputs {
    pub registry: RegistryInputs,
    pub credential: CredentialInputs,
    pub cwt: VerifierTokenInputs,
    pub takt: TaktInputs,
    /// AAT expiration as seconds since the Unix epoch (CWT `exp`).
    pub aat_exp: Field,
    /// AAT `ES256` signature over the COSE `Sig_structure` (`r || s`, low-S).
    pub aat_signature: [u8; 64],
    /// Blinding factor for the session commitment.
    pub session_id_r: Field,
}
