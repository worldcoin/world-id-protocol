//! DeepFace Query Proof -- the billing gate a user presents to the Verifier TEE.
//!
//! Implements the `Query Proof` of the YABS "Updated Design". The user proves, without
//! revealing which human it is, that:
//!
//! 1. it is enrolled for billing under some `(rp_id, period)` -- the billing tree whose
//!    `billing_root` the TEE holds in its host-fed root map, and from which `rp_id` and
//!    `period` are inferred, so neither is an explicit input;
//! 2. the enrolled billing leaf opens to *its* World ID (`mt_index`);
//! 3. a valid, unexpired Proof of Human credential for that same `mt_index` carries
//!    `pcp_hash` -- which is what stops one enrolled World ID from being used to verify a
//!    different human.
//!
//! Everything identity-bearing (`mt_index`, `r`, the leaf, the path) is a witness. The
//! public inputs are shared by everyone enrolled under that root, so requests from the
//! same human are unlinkable to the TEE.
//!
//! ## Not proven here
//!
//! Control of `mt_index` is *not* proven: there is no `WorldIDRegistry` inclusion proof
//! and no authenticator signature. Soundness therefore rests on `r` and the credential
//! being secrets only the holder has. Adding the missing block is exactly the
//! `ownership_proof` circuit, so its measured cost is the price of closing this gap --
//! see `docs/benchmarks.md`.
//!
//! ## Which credential field `pcp_hash` is
//!
//! `pcp_hash` is **one claim slot**, not the aggregate `claims_hash` and not
//! `associated_data_commitment`:
//!
//! - `claims` are documented as "commitments to data (e.g. passport image)" that the
//!   issuer attests about the subject, which is exactly what a PCP commitment is. A slot
//!   is set as `H(b"CLAIMS_HASH_V1" || bytes)`, so the enclave can derive it from the
//!   `hashes.json` it already holds.
//! - `associated_data_commitment` is ruled out: the `Credential` docs make it
//!   issuer-private ("never exposed to RPs or others") with a structure "solely determined
//!   by the issuer", so binding the protocol to it would both misuse the field and let the
//!   issuer break this circuit by changing its own encoding.
//! - The aggregate `claims_hash` is ruled out because the TEE cannot check it: deriving it
//!   needs *every* claim slot, and the TEE only ever sees the PCP. Publishing it would
//!   also leak a handle to claims the TEE has no business learning.
//!
//! Caveat, and the reason `PCP_CLAIM_INDEX` is provisional: **no issuer populates `claims`
//! today** -- they are marked "For Future Use" in `world-id-primitives` and nothing in the
//! repo, the faux issuer included, sets one. So this circuit is the first consumer, and
//! the slot index has to be pinned down together with the PoH credential schema.
pub(crate) mod commitment;
pub(crate) mod constants;
pub(crate) mod credential;
pub(crate) mod merkle_proof;
pub(crate) mod types;

use commitment::session_id_commitment;
use constants::BILLING_MAX_DEPTH;
use credential::verify_credential;
use merkle_proof::compute_merkle_root_poseidon2;
use types::{DeepFaceQueryProofInputs, PublicKey};

pub fn main(
    // Root of the per-RP-per-period billing Merkle tree. The TEE accepts it only if it is
    // in the root map the host feeds it, which is what ties the proof to (rp_id, period).
    billing_root: pub Field,
    billing_depth: pub Field,
    // Hash of the PCP this query is for. The TEE checks it against the hash it derives
    // from `hashes.json` itself. It is the credential's `claims_hash`.
    pcp_hash: pub Field,
    // Proof of Human credential inputs the TEE has to see to judge the credential.
    issuer_schema_id: pub Field,
    issuer_pk: pub PublicKey,
    current_timestamp: pub Field,
    genesis_issued_at_min: pub Field,
    // Nonce of the RP request, deduplicated by the host to stop replays.
    nonce: pub Field,
    inputs: DeepFaceQueryProofInputs<BILLING_MAX_DEPTH>,
) {
    // 1. The billing tree leaf is this human's session id commitment.
    let leaf = session_id_commitment(inputs.mt_index, inputs.commitment_r);

    // 2. That leaf is enrolled under `billing_root`.
    let computed_root = compute_merkle_root_poseidon2(
        leaf,
        billing_depth,
        inputs.billing_proof.mt_index,
        inputs.billing_proof.siblings,
    );
    assert(computed_root == billing_root, "Billing inclusion proof failed");

    // 3. A valid credential for the same `mt_index` carries `pcp_hash`.
    verify_credential(
        inputs.credential,
        inputs.mt_index,
        issuer_schema_id,
        issuer_pk,
        pcp_hash,
        current_timestamp,
        genesis_issued_at_min,
    );

    // SAFETY: The multiplication is constrained below, this is just to emulate the signal
    // hash coming from Circom/Semaphore.
    let nonce_squared = unsafe { unconstrained_mul(nonce, nonce) };
    assert(nonce_squared == nonce * nonce, "Nonce dummy constraint failed");
}

unconstrained fn unconstrained_mul(a: Field, b: Field) -> Field {
    a * b
}
