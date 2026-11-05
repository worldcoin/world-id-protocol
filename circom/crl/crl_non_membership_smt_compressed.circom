pragma circom 2.2.2;

include "smt/smt_verifier.circom";

// Non-membership proof against a credential revocation list held as a
// *compressed* sparse Merkle tree, following the Iden3 / Polygon ID revocation
// model (`checkClaimNotRevoked`).
//
// Leaves sit at the shortest depth that distinguishes them, so N_LEVELS tracks
// the number of revoked entries rather than the key width — empirically about
// 2x the indexed Merkle tree's ceil(log2(N)) for random keys.
//
// N_LEVELS must carry a safety margin: a key whose distinguishing path exceeds
// it cannot be represented, which is a liveness failure. Keys must therefore be
// hashed, otherwise an issuer can mint ids sharing a long prefix and push paths
// past N_LEVELS on purpose.
template CrlNonMembershipSmtCompressed(N_LEVELS) {
    signal input crl_root;
    signal input key;
    signal input crl_siblings[N_LEVELS];
    // Where the path terminates: an empty node (is_old_0 = 1) or a different
    // leaf (is_old_0 = 0, in which case key != old_key is enforced).
    signal input old_key;
    signal input old_value;
    signal input is_old_0;

    component verifier = SMTVerifier(N_LEVELS);
    verifier.enabled <== 1;
    verifier.fnc <== 1; // non-inclusion
    verifier.root <== crl_root;
    verifier.siblings <== crl_siblings;
    verifier.key <== key;
    verifier.value <== 0;
    verifier.oldKey <== old_key;
    verifier.oldValue <== old_value;
    verifier.isOld0 <== is_old_0;
}
