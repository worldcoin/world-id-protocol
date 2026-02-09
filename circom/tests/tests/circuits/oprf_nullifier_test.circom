pragma circom 2.2.2;

include "client_side_proofs/oprf_nullifier.circom";

component main {public [issuer_schema_id, cred_pk, current_timestamp, cred_genesis_issued_at_min, merkle_root, depth, rp_id, action, oprf_pk, signal_hash, nonce]} = OprfNullifier(30);
