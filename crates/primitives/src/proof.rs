use std::io::Cursor;

use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{de::Error as _, ser::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    authenticator::AuthenticatorPublicKeySet,
    merkle::MerkleInclusionProof,
    rp::{RpId, RpNullifierKey},
    Credential, FieldElement, PrimitiveError,
};

/// Represents a base World ID proof.
///
/// Both the Query Proof (π1) and the Nullifier Proof (π2) are World ID Proofs.
///
/// Internally, the World ID Proofs are Groth16 ZKPs. In the World ID Protocol,
/// the Merkle Root that proves inclusion into the set of World ID accounts (`AccountRegistry`)
/// is also encoded as part of the proof.
#[derive(Debug, Default, Clone)]
pub struct WorldIdProof {
    /// The Groth16 ZKP
    pub zkp: ark_groth16::Proof<Bn254>,
    /// The hash of the root of the Merkle tree that proves inclusion into the set of World ID accounts (`AccountRegistry`).
    pub merkle_root: FieldElement,
}

impl WorldIdProof {
    /// Initialize a new proof.
    #[must_use]
    pub const fn new(zkp: ark_groth16::Proof<Bn254>, merkle_root: FieldElement) -> Self {
        Self { zkp, merkle_root }
    }

    /// Serializes the proof into a compressed and packed byte vector.
    ///
    /// Uses `ark-serialize` to compress affine points as it guarantees correct formatting (elements are padded).
    ///
    /// # Errors
    /// Will return an error if the serialization unexpectedly fails.
    pub fn to_compressed_bytes(&self) -> Result<Vec<u8>, PrimitiveError> {
        let mut bytes = Vec::with_capacity(160);

        // A = G1 (32 bytes compressed)
        self.zkp
            .a
            .serialize_compressed(&mut bytes)
            .map_err(|e| PrimitiveError::Serialization(e.to_string()))?;

        // B = G2 (64 bytes compressed)
        self.zkp
            .b
            .serialize_compressed(&mut bytes)
            .map_err(|e| PrimitiveError::Serialization(e.to_string()))?;

        // C = G1 (32 bytes compressed)
        self.zkp
            .c
            .serialize_compressed(&mut bytes)
            .map_err(|e| PrimitiveError::Serialization(e.to_string()))?;

        // Merkle root = Field element (32 bytes compressed)
        self.merkle_root
            .0
            .serialize_compressed(&mut bytes)
            .map_err(|e| PrimitiveError::Serialization(e.to_string()))?;

        debug_assert!(bytes.len() == 160);

        Ok(bytes)
    }
    /// Deserializes a proof from a compressed byte vector.
    ///
    /// # Errors
    /// Will return an error if the provided input is not a valid compressed proof. For example, invalid field points.
    pub fn from_compressed_bytes(bytes: &[u8]) -> Result<Self, PrimitiveError> {
        if bytes.len() != 160 {
            return Err(PrimitiveError::Deserialization(
                "Invalid proof length. Expected 160 bytes.".to_string(),
            ));
        }

        let mut reader = Cursor::new(bytes);
        let a = G1Affine::deserialize_compressed(&mut reader)
            .map_err(|e| PrimitiveError::Deserialization(e.to_string()))?;
        let b = G2Affine::deserialize_compressed(&mut reader)
            .map_err(|e| PrimitiveError::Deserialization(e.to_string()))?;
        let c = G1Affine::deserialize_compressed(&mut reader)
            .map_err(|e| PrimitiveError::Deserialization(e.to_string()))?;

        let merkle_root: FieldElement = FieldElement::deserialize_from_bytes(&mut reader)
            .map_err(|e| PrimitiveError::Deserialization(e.to_string()))?;

        Ok(Self {
            zkp: ark_groth16::Proof { a, b, c },
            merkle_root,
        })
    }
}

impl Serialize for WorldIdProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let compressed_bytes = self.to_compressed_bytes().map_err(S::Error::custom)?;
        serializer.serialize_str(&hex::encode(compressed_bytes))
    }
}

impl<'de> Deserialize<'de> for WorldIdProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let compressed_bytes =
            hex::decode(String::deserialize(deserializer)?).map_err(D::Error::custom)?;
        Self::from_compressed_bytes(&compressed_bytes).map_err(D::Error::custom)
    }
}

/// The arguments required to generate a World ID Uniqueness Proof (also called a "Presentation").
///
/// This request results in a final Nullifier Proof (π2), but a Query Proof (π1) must be
/// generated in the process.
pub struct SingleProofInput<const TREE_DEPTH: usize> {
    // SECTION: User Inputs
    /// The credential of the user which will be proven in the World ID Proof.
    pub credential: Credential,
    /// The Merkle inclusion proof which proves ownership of the user's account in the `AccountRegistry` contract.
    pub inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    /// The complete set of authenticator public keys for the World ID Account.
    pub key_set: AuthenticatorPublicKeySet,
    /// The index of the public key which will be used to sign from the set of public keys.
    pub key_index: u64,
    /// The `r_seed` is a random seed used to generate the `rpSessionId`. The `rpSessionId` is a unique identifier
    /// for the RP+User pair for a particular action, and it lets the user prove they are still the same
    /// person in future proofs if the RP already has an `rpSessionId` for them.
    pub rp_session_id_r_seed: FieldElement,

    /// SECTION: RP Inputs

    /// The ID of the RP requesting the proof.
    pub rp_id: RpId,
    /// The epoch of the `DLog` share (currently always `0`).
    pub share_epoch: u128,
    /// The specific hashed action for which the user is generating the proof. The output nullifier will
    /// be unique for the combination of this action, the `rp_id` and the user.
    pub action: FieldElement,
    /// The unique identifier for this proof request. Provided by the RP.
    pub nonce: FieldElement,
    /// The timestamp from the RP's request.
    /// TODO: Document why this is required.
    pub current_timestamp: u64,
    /// The RP's signature over the request. This is used to ensure the RP is legitimately requesting the proof
    /// from the user and reduce phishing surface area.
    ///
    /// The signature is computed over `H(nonce || timestamp)`, ECDSA on the `secp256k1` curve.
    ///
    /// TODO: Refactor what is actually signed.
    pub rp_signature: k256::ecdsa::Signature,
    /// The public key of the RP used to verify the computed nullifier.
    ///
    /// TODO: This requires more details.
    pub rp_nullifier_key: RpNullifierKey,
    /// The signal hashed into the field. The signal is a commitment to arbitrary data that can be used
    /// to ensure the integrity of the proof. For example, in a voting application, the signal could
    /// be used to encode the user's vote.
    pub signal_hash: FieldElement,
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fq2;
    use ruint::uint;

    use super::*;

    #[test]
    fn test_encoding_round_trip() {
        let proof = WorldIdProof::default();
        let compressed_bytes = proof.to_compressed_bytes().unwrap();

        assert_eq!(compressed_bytes.len(), 160);

        let encoded = serde_json::to_string(&proof).unwrap();
        assert_eq!(encoded, "\"00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000\"");

        let proof_from = WorldIdProof::from_compressed_bytes(&compressed_bytes).unwrap();

        assert_eq!(proof.merkle_root, proof_from.merkle_root);
        assert_eq!(proof.zkp.a, proof_from.zkp.a);
        assert_eq!(proof.zkp.b, proof_from.zkp.b);
        assert_eq!(proof.zkp.c, proof_from.zkp.c);
    }

    /// This proof is taken from the `semaphore-rs` crate as a test case.
    #[test]
    #[allow(clippy::similar_names)]
    fn test_real_proof() {
        // Point A (G1)
        let a_x = uint!(0x15c1fc6907219676890dfe147ee6f10b580c7881dddacb1567b3bcbfc513a54d_U256);
        let a_y = uint!(0x233afda3efff43a7631990d2e79470abcbae3ccad4b920476e64745bfe97bb0a_U256);
        let a = G1Affine::new(a_x.try_into().unwrap(), a_y.try_into().unwrap());

        // Point B (G2) - Swapping c0/c1 to match Ethereum convention
        let b_x_c1 = uint!(0xc8c7d7434c382d590d601d951c29c8463d555867db70f9e84f7741c81c2e1e6_U256);
        let b_x_c0 = uint!(0x241d2ddf1c9e6670a24109a0e9c915cd6e07d0248a384dd38d3c91e9b0419f5f_U256);
        let b_y_c1 = uint!(0xb23c5467a06eff56cc2c246ada1e7d5705afc4dc8b43fd5a6972c679a2019c5_U256);
        let b_y_c0 = uint!(0x91ed6522f7924d3674d08966a008f947f9aa016a4100bb12f911326f3e1befd_U256);
        let b_x = Fq2::new(b_x_c0.try_into().unwrap(), b_x_c1.try_into().unwrap());
        let b_y = Fq2::new(b_y_c0.try_into().unwrap(), b_y_c1.try_into().unwrap());
        let b = G2Affine::new(b_x, b_y);

        // Point C (G1)
        let c_x = uint!(0xacdf5a5996e00933206cbec48f3bbdcee2a4ca75f8db911c00001e5a0547487_U256);
        let c_y = uint!(0x2446d6f1c1506837392a30fdc73d66fd89f4e1b1a5d14b93e2ad0c5f7b777520_U256);
        let c = G1Affine::new(c_x.try_into().unwrap(), c_y.try_into().unwrap());

        let zkp = ark_groth16::Proof { a, b, c };
        let merkle_root = FieldElement::try_from(uint!(
            0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256
        ))
        .unwrap();
        let proof = WorldIdProof::new(zkp, merkle_root);

        // Test roundtrip serialization
        let json_str = serde_json::to_string(&proof).unwrap();
        dbg!(&json_str);
        assert_eq!(json_str[306..], *"1ac917bce23d211\""); // assert hex encoding of merkle root
        let deserialized_proof: WorldIdProof = serde_json::from_str(&json_str).unwrap();

        // Verify the roundtrip preserved all values
        assert_eq!(proof.zkp.a, deserialized_proof.zkp.a);
        assert_eq!(proof.zkp.b, deserialized_proof.zkp.b);
        assert_eq!(proof.zkp.c, deserialized_proof.zkp.c);
        assert_eq!(
            FieldElement::try_from(uint!(
                8060603437403478431405594370235290687560488504242369439470699636878115808450_U256
            ))
            .unwrap(),
            deserialized_proof.merkle_root
        );
    }
}
