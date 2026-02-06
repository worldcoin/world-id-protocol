use ark_bn254::Bn254;
use ark_groth16::Proof;
use ruint::aliases::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::FieldElement;

/// Encoded World ID Proof.
///
/// Internally, the first 4 elements are a compressed Groth16 proof
/// [a (G1), b (G2), b (G2), c (G1)]. Proofs also require the root hash of the Merkle tree
/// in the `WorldIDRegistry` as a public input. To simplify transmission, that root is encoded as the last element
/// with the proof.
///
/// The `WorldIDVerifier.sol` contract handles the decoding and verification.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ZeroKnowledgeProof {
    /// Array of 5 U256 values: first 4 are compressed Groth16 proof, last is Merkle root.
    inner: [U256; 5],
}

impl ZeroKnowledgeProof {
    /// Initialize a new proof from a Groth16 proof and Merkle root.
    #[must_use]
    pub fn from_groth16_proof(groth16_proof: &Proof<Bn254>, merkle_root: FieldElement) -> Self {
        let compressed_proof = taceo_groth16_sol::prepare_compressed_proof(groth16_proof);
        Self {
            inner: [
                compressed_proof[0],
                compressed_proof[1],
                compressed_proof[2],
                compressed_proof[3],
                merkle_root.into(),
            ],
        }
    }

    /// Outputs the proof as a Solidity-friendly representation.
    #[must_use]
    pub const fn as_ethereum_representation(&self) -> [U256; 5] {
        self.inner
    }

    /// Initializes a proof from an encoded Solidity-friendly representation.
    #[must_use]
    pub const fn from_ethereum_representation(value: [U256; 5]) -> Self {
        Self { inner: value }
    }

    /// Converts the proof to compressed bytes (160 bytes total: 5 × 32 bytes).
    #[must_use]
    pub fn to_compressed_bytes(&self) -> Vec<u8> {
        self.inner
            .iter()
            .flat_map(U256::to_be_bytes::<32>)
            .collect()
    }

    /// Constructs a proof from compressed bytes (must be exactly 160 bytes).
    ///
    /// # Errors
    /// Returns an error if the input is not exactly 160 bytes or if bytes cannot be parsed.
    pub fn from_compressed_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 160 {
            return Err(format!(
                "Invalid length: expected 160 bytes, got {}",
                bytes.len()
            ));
        }

        let mut inner = [U256::ZERO; 5];
        for (i, chunk) in bytes.chunks_exact(32).enumerate() {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(chunk);
            inner[i] = U256::from_be_bytes(arr);
        }

        Ok(Self { inner })
    }
}

impl Serialize for ZeroKnowledgeProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.to_compressed_bytes();
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }
}

impl<'de> Deserialize<'de> for ZeroKnowledgeProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let hex_str = String::deserialize(deserializer)?;
            hex::decode(hex_str).map_err(D::Error::custom)?
        } else {
            Vec::deserialize(deserializer)?
        };

        Self::from_compressed_bytes(&bytes).map_err(D::Error::custom)
    }
}

impl From<ZeroKnowledgeProof> for [U256; 5] {
    fn from(value: ZeroKnowledgeProof) -> Self {
        value.inner
    }
}

#[cfg(test)]
mod tests {
    use ruint::uint;

    use super::*;

    #[test]
    fn test_encoding_round_trip() {
        let proof = ZeroKnowledgeProof::default();
        let compressed_bytes = proof.to_compressed_bytes();

        assert_eq!(compressed_bytes.len(), 160);

        let encoded = serde_json::to_string(&proof).unwrap();
        assert_eq!(
            encoded,
            "\"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\""
        );

        let proof_from = ZeroKnowledgeProof::from_compressed_bytes(&compressed_bytes).unwrap();

        assert_eq!(proof.inner, proof_from.inner);
    }

    #[test]
    fn test_json_deserialization() {
        let proof = ZeroKnowledgeProof::default();

        // Test roundtrip serialization
        let json_str = serde_json::to_string(&proof).unwrap();
        let deserialized_proof: ZeroKnowledgeProof = serde_json::from_str(&json_str).unwrap();

        // Verify the roundtrip preserved all values
        assert_eq!(proof.inner, deserialized_proof.inner);
    }

    #[test]
    fn test_from_ethereum_representation() {
        let values = [
            uint!(0x0000000000000000000000000000000000000000000000000000000000000001_U256),
            uint!(0x0000000000000000000000000000000000000000000000000000000000000002_U256),
            uint!(0x0000000000000000000000000000000000000000000000000000000000000003_U256),
            uint!(0x0000000000000000000000000000000000000000000000000000000000000004_U256),
            uint!(0x11d223ce7b91ac212f42cf50f0a3439ae3fcdba4ea32acb7f194d1051ed324c2_U256),
        ];

        let proof = ZeroKnowledgeProof::from_ethereum_representation(values);
        assert_eq!(proof.as_ethereum_representation(), values);

        // Test serialization roundtrip
        let bytes = proof.to_compressed_bytes();
        assert_eq!(bytes.len(), 160);

        let proof_from_bytes = ZeroKnowledgeProof::from_compressed_bytes(&bytes).unwrap();
        assert_eq!(proof.inner, proof_from_bytes.inner);
    }

    #[test]
    fn test_invalid_bytes_length() {
        let too_short = vec![0u8; 159];
        let result = ZeroKnowledgeProof::from_compressed_bytes(&too_short);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid length"));

        let too_long = vec![0u8; 161];
        let result = ZeroKnowledgeProof::from_compressed_bytes(&too_long);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid length"));
    }
}
