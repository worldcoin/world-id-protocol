pragma circom 2.2.0;
include "client_side_proofs/oprf_query.circom";

component main {public [merkle_root, depth, rp_id, action, nonce]} = OprfQuery(30);
