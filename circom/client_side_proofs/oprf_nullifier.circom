pragma circom 2.2.2;

include "oprf_query.circom";
include "verify_dlog/verify_dlog.circom";

// In the CheckCredentialSignature template, we need to recompute a hash and verify the signature of this hash. Furthermore, we need to check whether the credential is still valid (i.e., not expired) by proving the current_timestamp is less than expires_at, and we also check that the genesis_issues_at time is valid by comparing it to genesis_issues_at_min.
template CheckCredentialSignature() {
    // Signature
    signal input s;
    signal input r[2];
    // Public key
    signal input pk[2];
    // Blinded user id input
    signal input user_id;
    signal input user_id_r;
    // Credential data
    signal input issuer_schema_id;
    signal input genesis_issued_at;
    signal input expires_at;
    signal input hashes[2]; // [claims_hash, associated_data_hash]
    signal input cred_id;
    // Current time
    signal input current_timestamp;
    // Minimum allowed genesis issue time
    signal input genesis_issued_at_min;

    // Calculate the blinded user id
    var DS_CS_C = 87492525752134038588518953; // b"H_CS(id, r)"
    var poseidon_comm[3] = Poseidon2(3)([DS_CS_C, user_id, user_id_r]); // capacity element at 0, so we take [1] below

    // Calculate the message hash
    component hash = Poseidon2(8);
    hash.in[0] <== 1790969822004668215611014194230797064349043274; // Domain separator in capacity element b"POSEIDON2+EDDSA-BJJ"
    hash.in[1] <== issuer_schema_id;
    hash.in[2] <== poseidon_comm[1]; // Blinded user id = H(user_id, user_id_r)
    hash.in[3] <== genesis_issued_at;
    hash.in[4] <== expires_at;
    hash.in[5] <== hashes[0];
    hash.in[6] <== hashes[1];
    hash.in[7] <== cred_id;

    // Verify the signature
    component eddsa_verifier = EdDSAPoseidon2Verifier();
    eddsa_verifier.Ax <== pk[0];
    eddsa_verifier.Ay <== pk[1];
    eddsa_verifier.S <== s;
    eddsa_verifier.Rx <== r[0];
    eddsa_verifier.Ry <== r[1];
    eddsa_verifier.M <== hash.out[1];

    // Range check the 3 timestamps
    // We think these two checks are not really necessary since it would produce an invalid signature if they were out of range (and the signer should have checked it), but it does not add many constraints....
    var genesis_in_range[64] = Num2Bits(64)(genesis_issued_at);
    var expires_in_range[64] = Num2Bits(64)(expires_at);
    // var current_in_range[64] = Num2Bits(64)(current_timestamp); // Should be checked outside of the ZK proof
    // var genesis_limit_in_range[64] = Num2Bits(64)(genesis_issued_at_limit); // Should be checked outside of the ZK proof

    // Check the credential is currently valid
    var lt_expiry = LessThan(64)([current_timestamp, expires_at]);
    // Check the credential is issued at or after the minimum allowed genesis issue time
    var leq_issued = LessEqThan(64)([genesis_issued_at_min, genesis_issued_at]);
    lt_expiry === 1;
    leq_issued === 1;
}


// Checks outside of the ZK proof: The public key oprf_pk needs to be a valid BabyJubJub point in the correct subgroup.

template OprfNullifier(MAX_DEPTH) {
    // Signature verification of the OPRF nonce (There such that sk corresponding to pk is never used in a proof directly)
    signal input pk[7][2];
    signal input pk_index; // 0..6
    signal input s;
    signal input r[2];
    // Credential Signature
    signal input issuer_schema_id; // Public
    signal input cred_pk[2]; // Public
    signal input cred_hashes[2]; // [claims_hash, associated_data_hash]
    signal input cred_genesis_issued_at;
    signal input cred_expires_at;
    signal input cred_s;
    signal input cred_r[2];
    signal input current_timestamp; // Public
    signal input cred_genesis_issued_at_min; // Public
    signal input cred_user_id_r; // blinding for the credential signature userid commitment
    signal input cred_id;
    // Merkle proof
    signal input merkle_root; // Public
    signal input depth; // Public
    signal input mt_index;
    signal input siblings[MAX_DEPTH];
    // Oprf query
    signal input beta;
    signal input rp_id; // Public
    signal input action; // Public
    // Dlog Equality Proof
    signal input dlog_e;
    signal input dlog_s;
    signal input oprf_pk[2]; // Public
    signal input oprf_response_blinded[2];
    // Unblinded response
    signal input oprf_response[2];
    // Nonce and signal hash
    signal input signal_hash; // Public
    signal input nonce; // Public
    // Commitment to the id
    signal input id_commitment_r;
    signal input id_commitment; // Public
    // Nullifier computation
    signal output nullifier; // Public

    // Derive the query
    // The domain separator is in the capacity element b"World ID Query"
    var query_poseidon[4] = Poseidon2(4)([1773399373884719043551600379785849, mt_index, rp_id, action]);
    signal query <== query_poseidon[1];

    // 1-2. Show that the original query was computed correctly
    component oprf_query = OprfQueryInner(MAX_DEPTH);
    oprf_query.pk <== pk;
    oprf_query.pk_index <== pk_index;
    oprf_query.s <== s;
    oprf_query.r <== r;
    oprf_query.merkle_root <== merkle_root;
    oprf_query.depth <== depth;
    oprf_query.mt_index <== mt_index;
    oprf_query.siblings <== siblings;
    oprf_query.beta <== beta;
    oprf_query.query <== query;

    // 3. Credential signature is valid
    component cred_sig_checker = CheckCredentialSignature();
    cred_sig_checker.s <== cred_s;
    cred_sig_checker.r <== cred_r;
    cred_sig_checker.pk <== cred_pk;
    cred_sig_checker.issuer_schema_id <== issuer_schema_id;
    cred_sig_checker.user_id <== mt_index;
    cred_sig_checker.genesis_issued_at <== cred_genesis_issued_at;
    cred_sig_checker.expires_at <== cred_expires_at;
    cred_sig_checker.hashes <== cred_hashes;
    cred_sig_checker.current_timestamp <== current_timestamp;
    cred_sig_checker.genesis_issued_at_min <== cred_genesis_issued_at_min;
    cred_sig_checker.user_id_r <== cred_user_id_r;
    cred_sig_checker.cred_id <== cred_id;

    // 4. Check the dlog equality proof
    BabyJubJubBaseField() e;
    e.f <== dlog_e;
    component dlog_eq_verifier = VerifyDlog();
    dlog_eq_verifier.e <== e;
    dlog_eq_verifier.s <== dlog_s;
    dlog_eq_verifier.a <== oprf_pk;
    dlog_eq_verifier.b <== oprf_query.q;
    dlog_eq_verifier.c <== oprf_response_blinded;

    // 5. Unblind the OPRF response
    BabyJubJubScalarField() beta_f;
    beta_f.f <== beta;
    // The following checks that the oprf_response is on the curve and in the correct subgroup.
    component p_check = BabyJubJubCheckAndSubgroupCheck();
    p_check.x <== oprf_response[0];
    p_check.y <== oprf_response[1];

    // Preconditions: p_check.p is a valid point in the correct subgroup, checked above
    component unblinder = BabyJubJubScalarMul();
    unblinder.e <== beta_f;
    unblinder.p <== p_check.p;
    oprf_response_blinded[0] === unblinder.out.x;
    oprf_response_blinded[1] === unblinder.out.y;

    // Hash the result to get the output of the OPRF
    var DS_N = 1773399373884719043551596035141478; // b"World ID Proof"
    var poseidon_nullifier[4] = Poseidon2(4)([DS_N, query, oprf_response[0], oprf_response[1]]);
    nullifier <== poseidon_nullifier[1];

    // Produce the commitment to the id
    var DS_C = 5199521648757207593; // b"H(id, r)"
    var poseidon_comm[3] = Poseidon2(3)([DS_C, mt_index, id_commitment_r]);
    signal computed_id_commitment <== poseidon_comm[1];
    // id commitment either needs to be equal to computed, or 0
    // Below term is zero if:
    // - id_commitment == 0, as intended
    // - id_commitment - computed_id_commitment == 0, meaning id_commitment == computed_id_commitment, as intended
    id_commitment * (id_commitment - computed_id_commitment) === 0;

    // Dummy square to prevent tampering signal_hash.
    // Same as done in Semaphore
    signal signal_hash_squared <== signal_hash * signal_hash;
    // Same for the nonce
    signal nonce_squared <== nonce * nonce;
}

// component main {public [issuer_schema_id, cred_pk, current_timestamp, cred_genesis_issued_at_min, merkle_root, depth, rp_id, action, oprf_pk, signal_hash, nonce, id_commitment]} = OprfNullifier(30);
