//! Bindings for World ID proof verification.

use alloy::sol;

sol!(
    /// World ID verifier with uniqueness and session proof entry points.
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc, ignore_unlinked)]
    WorldIdVerifier,
    "abi/WorldIDVerifierV2Abi.json"
);

// These errors originate in contracts called by WorldIDVerifier and are not in its ABI.
sol! {
    /// The Groth16 proof is invalid.
    error ProofInvalid();
    /// A public input exceeds the circuit's scalar field.
    error PublicInputNotInField();
    /// The session commitment was rejected by a verifier that enforces nonzero sessions.
    error InvalidSessionId();
    /// The requested OPRF key is not registered or not yet generated.
    error UnknownId(uint160 id);
    /// The requested OPRF key has been deleted.
    error DeletedId(uint160 id);
}
