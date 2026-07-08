use std::sync::Arc;

use crate::{
    OwnershipProver, OwnershipVerifier,
    artifacts::{ZkArtifactError, ZkArtifactKind, ZkArtifactSource},
    nullifier_proof::CircomGroth16Material,
};

/// ZK artifacts embedded into the binary.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmbeddedZkArtifacts;

impl ZkArtifactSource for EmbeddedZkArtifacts {
    fn query_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        #[cfg(feature = "embed-zkeys")]
        {
            zkeys::load_embedded_query_material()
                .map(Arc::new)
                .map_err(|e| ZkArtifactError::load(ZkArtifactKind::QueryMaterial, e))
        }

        #[cfg(not(feature = "embed-zkeys"))]
        {
            Err(ZkArtifactError::Unavailable {
                kind: ZkArtifactKind::QueryMaterial,
                reason: "enable `embed-zkeys`",
            })
        }
    }

    fn nullifier_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        #[cfg(feature = "embed-zkeys")]
        {
            zkeys::load_embedded_nullifier_material()
                .map(Arc::new)
                .map_err(|e| ZkArtifactError::load(ZkArtifactKind::NullifierMaterial, e))
        }

        #[cfg(not(feature = "embed-zkeys"))]
        {
            Err(ZkArtifactError::Unavailable {
                kind: ZkArtifactKind::NullifierMaterial,
                reason: "enable `embed-zkeys`",
            })
        }
    }

    fn ownership_prover(&self) -> Result<OwnershipProver, ZkArtifactError> {
        // NOTE: Relying on wasm32 as a gate might seem weird here
        //       but it's because the relevant code from provekit that allows
        //       deserializing ProveKit artifacts has io/fs dependencies (and some C-based
        //       libraries) - once that's resolved we should only rely on the
        //       embed-ownership-prover feature gate.

        #[cfg(all(not(target_arch = "wasm32"), feature = "embed-ownership-prover"))]
        {
            noir::load_embedded_ownership_prover()
                .map_err(|e| ZkArtifactError::load(ZkArtifactKind::OwnershipProver, e))
        }

        #[cfg(any(target_arch = "wasm32", not(feature = "embed-ownership-prover")))]
        {
            Err(ZkArtifactError::Unavailable {
                kind: ZkArtifactKind::OwnershipProver,
                reason: "enable `embed-ownership-prover` on a native target",
            })
        }
    }

    fn ownership_verifier(&self) -> Result<OwnershipVerifier, ZkArtifactError> {
        // NOTE: Relying on wasm32 as a gate might seem weird here
        //       but it's because the relevant code from provekit that allows
        //       deserializing ProveKit artifacts has io/fs dependencies (and some C-based
        //       libraries) - once that's resolved we should only rely on the
        //       embed-ownership-verifier feature gate.

        #[cfg(all(not(target_arch = "wasm32"), feature = "embed-ownership-verifier"))]
        {
            noir::load_embedded_ownership_verifier()
                .map_err(|e| ZkArtifactError::load(ZkArtifactKind::OwnershipVerifier, e))
        }

        #[cfg(any(target_arch = "wasm32", not(feature = "embed-ownership-verifier")))]
        {
            Err(ZkArtifactError::Unavailable {
                kind: ZkArtifactKind::OwnershipVerifier,
                reason: "enable `embed-ownership-verifier` on a native target",
            })
        }
    }
}

#[cfg(feature = "embed-zkeys")]
pub mod zkeys {
    use std::sync::OnceLock;

    use crate::nullifier_proof::CircomGroth16Material;

    #[cfg(not(docsrs))]
    const CIRCUIT_ARCHIVE: &[u8] = {
        #[cfg(feature = "zstd-compress-zkeys")]
        {
            include_bytes!(concat!(env!("OUT_DIR"), "/circuit_files.tar.zst"))
        }
        #[cfg(not(feature = "zstd-compress-zkeys"))]
        {
            include_bytes!(concat!(env!("OUT_DIR"), "/circuit_files.tar"))
        }
    };

    #[cfg(docsrs)]
    const CIRCUIT_ARCHIVE: &[u8] = &[];

    static CIRCUIT_FILES: OnceLock<Result<EmbeddedCircuitFiles, String>> = OnceLock::new();

    #[derive(Clone, Debug)]
    pub struct EmbeddedCircuitFiles {
        /// Embedded query witness graph bytes.
        pub query_graph: Vec<u8>,
        /// Embedded nullifier witness graph bytes.
        pub nullifier_graph: Vec<u8>,
        /// Embedded query zkey bytes (decompressed if `compress-zkeys` is enabled).
        pub query_zkey: Vec<u8>,
        /// Embedded nullifier zkey bytes (decompressed if `compress-zkeys` is enabled).
        pub nullifier_zkey: Vec<u8>,
    }

    /// Loads the [`CircomGroth16Material`] for the uniqueness proof (internally also nullifier proof)
    /// from the embedded keys in the binary without caching.
    ///
    /// # Errors
    /// Will return an error if the embedded material cannot be loaded or verified.
    pub fn load_embedded_nullifier_material() -> eyre::Result<CircomGroth16Material> {
        let files = load_embedded_circuit_files()?;
        crate::nullifier_proof::load_nullifier_material_from_reader(
            files.nullifier_zkey.as_slice(),
            files.nullifier_graph.as_slice(),
        )
    }

    /// Loads the [`CircomGroth16Material`] for the uniqueness proof (internally also query proof)
    /// from the embedded keys in the binary without caching.
    ///
    /// # Errors
    /// Will return an error if the embedded material cannot be loaded or verified.
    pub fn load_embedded_query_material() -> eyre::Result<CircomGroth16Material> {
        let files = load_embedded_circuit_files()?;
        crate::nullifier_proof::load_query_material_from_reader(
            files.query_zkey.as_slice(),
            files.query_graph.as_slice(),
        )
    }

    pub fn load_embedded_circuit_files() -> eyre::Result<EmbeddedCircuitFiles> {
        match CIRCUIT_FILES.get_or_init(|| init_circuit_files().map_err(|e| format!("{e:#}"))) {
            Ok(files) => Ok(files.clone()),
            Err(message) => Err(eyre::eyre!(message.clone())),
        }
    }

    fn init_circuit_files() -> eyre::Result<EmbeddedCircuitFiles> {
        use std::io::Read as _;

        use eyre::ContextCompat;

        // Step 1: Decode archive bytes (optional zstd decompression)
        let tar_bytes: Vec<u8> = {
            #[cfg(feature = "zstd-compress-zkeys")]
            {
                zstd::stream::decode_all(CIRCUIT_ARCHIVE)?
            }
            #[cfg(not(feature = "zstd-compress-zkeys"))]
            {
                CIRCUIT_ARCHIVE.to_vec()
            }
        };

        // Step 2: Untar — extract 4 entries by filename
        let mut query_graph = None;
        let mut nullifier_graph = None;
        let mut query_zkey = None;
        let mut nullifier_zkey = None;

        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_path_buf();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();

            let mut buf = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut buf)?;

            match name {
                "OPRFQueryGraph.bin" => query_graph = Some(buf),
                "OPRFNullifierGraph.bin" => nullifier_graph = Some(buf),
                "OPRFQuery.arks.zkey" => query_zkey = Some(buf),
                "OPRFNullifier.arks.zkey" => nullifier_zkey = Some(buf),
                _ => {}
            }
        }

        let query_graph = query_graph.context("OPRFQueryGraph.bin not found in archive")?;
        let nullifier_graph =
            nullifier_graph.context("OPRFNullifierGraph.bin not found in archive")?;
        #[allow(unused_mut)]
        let mut query_zkey = query_zkey.context("OPRFQuery zkey not found in archive")?;
        #[allow(unused_mut)]
        let mut nullifier_zkey =
            nullifier_zkey.context("OPRFNullifier zkey not found in archive")?;

        // Step 3: ARK decompress zkeys if compress-zkeys is active
        #[cfg(feature = "compress-zkeys")]
        {
            if let Ok(decompressed) = ark_decompress_zkey(&query_zkey) {
                query_zkey = decompressed;
            }
            if let Ok(decompressed) = ark_decompress_zkey(&nullifier_zkey) {
                nullifier_zkey = decompressed;
            }
        }

        Ok(EmbeddedCircuitFiles {
            query_graph,
            nullifier_graph,
            query_zkey,
            nullifier_zkey,
        })
    }

    /// ARK-decompresses a zkey.
    #[cfg(feature = "compress-zkeys")]
    pub fn ark_decompress_zkey(compressed: &[u8]) -> eyre::Result<Vec<u8>> {
        let zkey = <circom_types::groth16::ArkZkey<ark_bn254::Bn254> as ark_serialize::CanonicalDeserialize>::deserialize_with_mode(
            compressed,
            ark_serialize::Compress::Yes,
            ark_serialize::Validate::Yes,
        )?;

        let mut uncompressed = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_with_mode(
            &zkey,
            &mut uncompressed,
            ark_serialize::Compress::No,
        )?;
        Ok(uncompressed)
    }
}

#[cfg(all(
    not(target_arch = "wasm32"),
    any(
        feature = "embed-ownership-prover",
        feature = "embed-ownership-verifier"
    )
))]
pub mod noir {
    #[cfg(all(feature = "embed-ownership-prover", not(docsrs)))]
    const PKP_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ownership_proof.pkp"));

    #[cfg(all(feature = "embed-ownership-prover", docsrs))]
    const PKP_BYTES: &[u8] = &[];

    /// Loads the embedded ownership proof prover.
    ///
    /// # Errors
    /// Returns an error if embedded Noir artifacts are missing or invalid.
    #[cfg(feature = "embed-ownership-prover")]
    pub fn load_embedded_ownership_prover() -> eyre::Result<crate::OwnershipProver> {
        crate::ownership_proof::load_ownership_prover_from_reader(PKP_BYTES)
    }

    #[cfg(all(feature = "embed-ownership-verifier", not(docsrs)))]
    const PKV_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ownership_proof.pkv"));

    #[cfg(all(feature = "embed-ownership-verifier", docsrs))]
    const PKV_BYTES: &[u8] = &[];

    /// Loads the embedded ownership proof verifier.
    ///
    /// # Errors
    /// Returns an error if embedded Noir artifacts are missing or invalid.
    #[cfg(feature = "embed-ownership-verifier")]
    pub fn load_embedded_ownership_verifier() -> eyre::Result<crate::OwnershipVerifier> {
        crate::ownership_proof::load_ownership_verifier_from_reader(PKV_BYTES)
    }
}

#[cfg(all(test, feature = "embed-zkeys"))]
mod tests {
    use super::zkeys;

    #[test]
    fn loads_embedded_circuit_files() {
        let files = zkeys::load_embedded_circuit_files().unwrap();
        assert!(!files.query_graph.is_empty());
        assert!(!files.nullifier_graph.is_empty());
        assert!(!files.query_zkey.is_empty());
        assert!(!files.nullifier_zkey.is_empty());
    }

    #[test]
    fn builds_materials_from_embedded_readers() {
        let files = zkeys::load_embedded_circuit_files().unwrap();
        crate::nullifier_proof::load_query_material_from_reader(
            files.query_zkey.as_slice(),
            files.query_graph.as_slice(),
        )
        .unwrap();
        crate::nullifier_proof::load_nullifier_material_from_reader(
            files.nullifier_zkey.as_slice(),
            files.nullifier_graph.as_slice(),
        )
        .unwrap();
    }

    #[test]
    fn convenience_embedded_material_loaders_work() {
        zkeys::load_embedded_query_material().unwrap();
        zkeys::load_embedded_nullifier_material().unwrap();
    }

    #[cfg(feature = "compress-zkeys")]
    #[test]
    fn ark_decompress_zkey_roundtrip() {
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
        use circom_types::{ark_bn254::Bn254, groth16::ArkZkey};

        let files = zkeys::load_embedded_circuit_files().unwrap();
        let zkey = ArkZkey::<Bn254>::deserialize_with_mode(
            files.query_zkey.as_slice(),
            Compress::No,
            Validate::Yes,
        )
        .unwrap();
        let mut compressed = Vec::new();
        zkey.serialize_with_mode(&mut compressed, Compress::Yes)
            .unwrap();

        let decompressed = zkeys::ark_decompress_zkey(&compressed).unwrap();
        assert_eq!(decompressed, files.query_zkey);
    }
}
