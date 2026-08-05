// Maximum depth of the per-RP-per-period billing Merkle tree.
//
// The tree only ever holds the humans enrolled for one (rp_id, period) pair, so it is
// far smaller than the `WorldIDRegistry` tree. It is set to the same value here so the
// benchmark is directly comparable to the registry-sized trees used by the other
// circuits; the per-level cost is reported in `docs/benchmarks.md`.
pub global BILLING_MAX_DEPTH: u32 = 30;

// b"H(id, r)" -- domain separator of the session id commitment.
//
// Same value and construction as `signal computed_id_commitment` in
// `circom/client_side_proofs/oprf_nullifier.circom` and `SessionId::DS_C` in
// `world-id-primitives`, so the leaf this circuit opens is exactly the
// `SessionId::commitment` the authenticator already derives.
pub global DS_SESSION_COMMITMENT: Field = 5199521648757207593;

// b"H_CS(id, r)" -- domain separator of the credential subject commitment (`sub`).
pub global DS_CREDENTIAL_SUB: Field = 87492525752134038588518953;

// Number of claim slots in a V1 credential (`Credential::MAX_CLAIMS`).
pub global MAX_CLAIMS: u32 = 16;

// Which claim slot carries the PCP commitment.
//
// Slot 0 of the *iris* (orb signup) credential. `signup-service` issues exactly one claim
// there, `base64(hashes.json)` passed as a raw `Claims` entry so the signer Poseidon2-hashes
// it -- see the module docs in `main.nr`.
//
// Claim indices are scoped to the credential schema, not global: slot 0 of the *face*
// credential is a uniqueness flag, not a PCP. `issuer_schema_id` is what disambiguates,
// which is why it is a public input the TEE has to pin.
//
// Changing this changes the circuit and therefore the proving/verifying keys.
pub global PCP_CLAIM_INDEX: u32 = 0;

// b"POSEIDON2+EDDSA-BJJ" -- domain separator of the credential signature message.
pub global DS_CREDENTIAL_MESSAGE: Field = 1790969822004668215611014194230797064349043274;
