pragma circom 2.2.2;

include "oprf_query.circom";
include "oprf_nullifier.circom";
include "verify_dlog/verify_dlog.circom";

// Checks outside of the ZK proof: The public key oprf_pk needs to be a valid BabyJubJub point in the correct subgroup.

// Implements encryption following Algorithm 7 from the SAFE-API paper (https://eprint.iacr.org/2023/522.pdf)
template AuthenticatedEncryption() {
    signal input key;
    signal input plaintext[3];
    signal input nonce;
    signal output ciphertext[3];
    signal output tag;

    // From SAFE-API paper (https://eprint.iacr.org/2023/522.pdf)
    // Absorb 2, squeeze 3, absorb 3, squeeze 1, domainsep = 0x4142
    // [0x80000002, 0x00000003, 0x80000003, 0x00000001, 0x4142]
    var T3_DS = 0x800000020000000380000003000000014142;
    var state[4] = Poseidon2(4)([T3_DS, key, nonce, 0]);

    component poseidon2_tag = Poseidon2(4);
    poseidon2_tag.in[0] <== state[0];
    for (var i = 0; i < 3; i++) {
        poseidon2_tag.in[i + 1] <== plaintext[i] + state[i + 1];
        ciphertext[i] <== plaintext[i] + state[i + 1];
    }
    tag <== poseidon2_tag.out[1];
}


// We expect that the mpc_public_keys are on curve and in correct subgroup. These are public inputs therefore we assume the verifier to check this.
template OprfDelegate(MAX_DEPTH, RP_MAX_DEPTH) {
    // Signature verification of the OPRF nonce (There such that sk correponding to pk is never used in a proof directly)
    signal input user_pk[7][2];
    signal input pk_index; // 0..6
    signal input query_s;
    signal input query_r[2];
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
    signal input user_id_r; // blinding for the credential signature userid commitment
    signal input cred_id;
    // Merkle proof
    signal input merkle_root; // Public
    signal input depth; // Public
    signal input mt_index;
    signal input siblings[MAX_DEPTH];
    // Oprf query
    signal input beta;
    // Dlog Equality Proof
    signal input dlog_e;
    signal input dlog_s;
    signal input oprf_pk[2]; // Public
    signal input oprf_response_blinded[2];
    // Unblinded response
    signal input oprf_response[2];
    // Nonce
    signal input nonce; // Public
    // Commitment to the id
    signal input id_commitment_r;
    // secret key for the encryption of the shares
    signal input encryption_sk;
    signal input mpc_public_keys[3][2]; // Public
    // Merkle proof for the RP registry
    signal input rp_merkle_root; // Public
    signal input rp_depth; // Public
    signal input rp_mt_index;
    signal input rp_siblings[RP_MAX_DEPTH];
    // secret shares
    signal input map_id_share[3];
    signal input r_share[3];
    signal input expiration; // Public
    // Outputs
    signal output id_commitment; // Public
    signal output map_id_commitment; // Public
    signal output encryption_pk[2]; // Public
    signal output ciphertexts[3][4]; // Public

    // 1-2. Show that the original query was computed correctly
    component oprf_query = OprfQueryInner(MAX_DEPTH);
    oprf_query.pk <== user_pk;
    oprf_query.pk_index <== pk_index;
    oprf_query.s <== query_s;
    oprf_query.r <== query_r;
    oprf_query.merkle_root <== merkle_root;
    oprf_query.depth <== depth;
    oprf_query.mt_index <== mt_index;
    oprf_query.siblings <== siblings;
    oprf_query.beta <== beta;
    oprf_query.query <== mt_index;

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
    cred_sig_checker.user_id_r <== user_id_r;
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

    // Precondition: p_check.p is in the correct subgroup, checked above.
    component unblinder = BabyJubJubScalarMul();
    unblinder.e <== beta_f;
    unblinder.p <== p_check.p;
    oprf_response_blinded[0] === unblinder.out.x;
    oprf_response_blinded[1] === unblinder.out.y;

    // Hash the result to get the output of the OPRF
    var DS_N = 1773399373884719043551596035141478; // b"World ID Proof"
    var poseidon_rp_specific_id[4] = Poseidon2(4)([DS_N, mt_index, oprf_response[0], oprf_response[1]]);
    signal rp_specific_id <== poseidon_rp_specific_id[1];

    // Constrain the shares
    signal map_id_commitment_r <== r_share[0] + r_share[1] + r_share[2];
    rp_mt_index === map_id_share[0] + map_id_share[1] + map_id_share[2];

    // Produce the commitment to the id
    var DS_C = 5199521648757207593; // b"H(id, r)"
    var poseidon_comm[3] = Poseidon2(3)([DS_C, mt_index, id_commitment_r]);
    id_commitment <== poseidon_comm[1];

    // Produce the commitment to the map_id
    var poseidon_comm_map[3] = Poseidon2(3)([DS_C, rp_mt_index, map_id_commitment_r]);
    map_id_commitment <== poseidon_comm_map[1];

    // Check the Merkle root of the RP registry (maps the rp_specific_id to the map_id)
    component merkle_proof = BinaryMerkleRoot(RP_MAX_DEPTH);
    merkle_proof.leaf <== rp_specific_id;
    merkle_proof.depth <== rp_depth;
    merkle_proof.index <== rp_mt_index;
    merkle_proof.siblings <== rp_siblings;
    merkle_proof.out === rp_merkle_root;

    // Derive the encryption public key
    component sk_f = BabyJubJubIsInFr(); // Range check included
    sk_f.in <== encryption_sk;
    component encryption_pk_comp = BabyJubJubScalarGenerator();
    encryption_pk_comp.e <== sk_f.out;
    encryption_pk[0] <== encryption_pk_comp.out.x;
    encryption_pk[1] <== encryption_pk_comp.out.y;

    // Derive the symmetric keys for encryption
    component sym_keys[3];
    BabyJubJubPoint() { twisted_edwards_in_subgroup } pk_p[3];
    for (var i=0; i<3; i++) {
        pk_p[i].x <== mpc_public_keys[i][0];
        pk_p[i].y <== mpc_public_keys[i][1];
        // Precondition: pk_p[i] is in the correct subgroup, checked outside of the circuit.
        sym_keys[i] = BabyJubJubScalarMul();
        sym_keys[i].p <== pk_p[i];
        sym_keys[i].e <== sk_f.out;
    }

    // Encrypt the shares
    component authenticated_encryptions[3];
    for (var i=0; i<3; i++) {
        authenticated_encryptions[i] = AuthenticatedEncryption();
        authenticated_encryptions[i].key <== sym_keys[i].out.x;
        authenticated_encryptions[i].plaintext[0] <== map_id_share[i];
        authenticated_encryptions[i].plaintext[1] <== r_share[i];
        authenticated_encryptions[i].plaintext[2] <== expiration;
        authenticated_encryptions[i].nonce <== 0; // We don't use a nonce since it is a one-time encryption with a fresh key
        for (var j=0; j<3; j++) {
            ciphertexts[i][j] <== authenticated_encryptions[i].ciphertext[j];
        }
        ciphertexts[i][3] <== authenticated_encryptions[i].tag;
    }

    // Dummy square to prevent tampering nonce.
    // Same as done in Semaphore
    signal nonce_squared <== nonce * nonce;
}

// component main {public [issuer_schema_id, cred_pk, current_timestamp, cred_genesis_issued_at_min, merkle_root, depth, oprf_pk, nonce, mpc_public_keys, rp_merkle_root, rp_depth, expiration]} = OprfDelegate(30, 30);
