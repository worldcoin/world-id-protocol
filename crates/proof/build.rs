use eyre::OptionExt;
use std::{
    env, fs,
    path::{Path, PathBuf},
};

const GITHUB_REPO: &str = "worldcoin/world-id-protocol";
const CIRCUIT_ARTIFACT_RELEASE_TAG: &str = "circuit-artifacts-v0.1.0";

const CIRCUIT_FILES: &[&str] = &[
    "circom/OPRFQueryGraph.bin",
    "circom/OPRFNullifierGraph.bin",
    "circom/OPRFQuery.arks.zkey",
    "circom/OPRFNullifier.arks.zkey",
];

#[cfg(not(feature = "build-noir-artifacts"))]
const NOIR_ARTIFACT_FILES: &[&str] = &["ownership_proof.pkp", "ownership_proof.pkv"];

fn main() -> eyre::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var_os("DOCS_RS").is_some() {
        // Define a cfg only for THIS crate’s compilation.
        println!("cargo:rustc-cfg=docsrs");
        println!("cargo:rustc-check-cfg=cfg(docsrs)");
    }

    // Skip for docs.rs as it doesn't have network access or nargo.
    if env::var("DOCS_RS").is_ok() {
        println!("cargo:warning=Building for docs.rs, skipping circuit compilation");
        return Ok(());
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    if should_embed_noir_artifacts() {
        setup_noir_ownership_proof(&out_dir)?;
    }

    if env::var("CARGO_FEATURE_EMBED_ZKEYS").is_err() {
        return Ok(());
    };

    for path_str in CIRCUIT_FILES {
        let path = Path::new(path_str);

        fetch_circuit_file(path, &out_dir)?;
    }

    // ARK point compression (when compress-zkeys feature is active)
    let use_ark = std::env::var("CARGO_FEATURE_COMPRESS_ZKEYS").is_ok();
    if use_ark {
        ark_compress_zkeys(&out_dir)?;
    }

    // Create tar archive of all circuit files
    let use_zstd = std::env::var("CARGO_FEATURE_ZSTD_COMPRESS_ZKEYS").is_ok();
    let archive_name = if use_zstd {
        "circuit_files.tar.zst"
    } else {
        "circuit_files.tar"
    };
    let archive_path = out_dir.join(archive_name);

    // Collect files: use .compressed zkeys if ARK compression active, raw otherwise
    let mut files_to_bundle: Vec<(&str, PathBuf)> = Vec::new();
    for path_str in CIRCUIT_FILES {
        let file_name = Path::new(path_str).file_name().unwrap().to_str().unwrap();
        if is_arks_zkey(Path::new(file_name)) && use_ark {
            files_to_bundle.push((file_name, out_dir.join(format!("{file_name}.compressed"))));
        } else {
            files_to_bundle.push((file_name, out_dir.join(file_name)));
        }
    }

    let needs_rebuild = files_to_bundle
        .iter()
        .any(|(_, src)| !is_up_to_date(src, &archive_path));

    if needs_rebuild {
        let file = fs::File::create(&archive_path)?;
        if use_zstd {
            let encoder = zstd::Encoder::new(file, 9)?;
            let mut tar = tar::Builder::new(encoder);
            for (name, path) in &files_to_bundle {
                tar.append_path_with_name(path, name)?;
            }
            tar.into_inner()?.finish()?;
        } else {
            let mut tar = tar::Builder::new(file);
            for (name, path) in &files_to_bundle {
                tar.append_path_with_name(path, name)?;
            }
            tar.finish()?;
        }
    }

    Ok(())
}

fn should_embed_noir_artifacts() -> bool {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").ok();
    target_arch.as_deref() != Some("wasm32")
        && env::var_os("CARGO_FEATURE_EMBED_NOIR_ARTIFACTS").is_some()
}

fn circuit_artifact_url(file_name: &str) -> String {
    format!(
        "https://github.com/{GITHUB_REPO}/releases/download/{CIRCUIT_ARTIFACT_RELEASE_TAG}/{file_name}"
    )
}

fn download_file(url: &str, output_path: &Path) -> eyre::Result<()> {
    use std::{fs::File, io};

    let response = reqwest::blocking::get(url)?;

    if !response.status().is_success() {
        eyre::bail!("HTTP error {}: {}", response.status(), url);
    }

    let mut file = File::create(output_path)?;
    let content = response.bytes()?;
    io::copy(&mut content.as_ref(), &mut file)?;

    Ok(())
}

fn fetch_circuit_file(path: &Path, out_dir: &Path) -> eyre::Result<()> {
    let output_path = out_dir.join(path.file_name().ok_or_eyre("invalid path")?);

    // Check for local file first (development)
    if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
        let local_path = Path::new(&manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join(path));

        if let Some(path) = local_path
            && path.exists()
        {
            if output_path.exists() {
                fs::remove_file(&output_path)?;
            }
            // Hard links fail across filesystem boundaries (e.g. in cross Docker containers),
            // so fall back to copying the file.
            if std::fs::hard_link(&path, &output_path).is_err() {
                fs::copy(&path, &output_path)?;
            }
            println!("cargo:rerun-if-changed={}", path.display());
            return Ok(());
        }
    }

    // Download from GitHub releases: we need to do this because crates.io enforce a hard limit on
    // the size of a crate upload of ~10MB and the circuit files are heavier than that.
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_eyre("invalid path")?;
    let url = circuit_artifact_url(file_name);

    download_file(&url, &output_path)?;
    Ok(())
}

fn is_arks_zkey(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".arks.zkey"))
}

fn is_up_to_date(input: &Path, output: &Path) -> bool {
    let input_modified = match fs::metadata(input).and_then(|m| m.modified()) {
        Ok(time) => time,
        Err(_) => return false,
    };

    let output_modified = match fs::metadata(output).and_then(|m| m.modified()) {
        Ok(time) => time,
        Err(_) => return false,
    };

    output_modified >= input_modified
}

fn ark_compress_zkeys(out_dir: &Path) -> eyre::Result<()> {
    use rayon::prelude::*;

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or_eyre("failed to resolve workspace root from CARGO_MANIFEST_DIR")?;
    let circom_dir = workspace_root.join("circom");

    if !circom_dir.is_dir() {
        fs::create_dir_all(&circom_dir)?;
    }

    // Watch the directory itself for new/removed files
    println!("cargo:rerun-if-changed={}", circom_dir.display());

    // Process directory entries in parallel while propagating any IO errors.
    fs::read_dir(out_dir)?
        .par_bridge()
        .try_for_each(|entry| -> eyre::Result<()> {
            let path = entry?.path();
            if !is_arks_zkey(&path) {
                return Ok(());
            }

            let file_name = path
                .file_name()
                .ok_or_eyre("missing filename")?
                .to_str()
                .ok_or_eyre("non-utf8 filename")?;
            let output_path = out_dir.join(format!("{file_name}.compressed"));

            // Skip if output exists and is newer than input
            if is_up_to_date(&path, &output_path) {
                return eyre::Ok(());
            }

            compress_zkey(&path, &output_path)?;

            Ok(())
        })?;

    Ok(())
}

fn setup_noir_ownership_proof(out_dir: &Path) -> eyre::Result<()> {
    #[cfg(feature = "build-noir-artifacts")]
    {
        build_noir_ownership_proof(out_dir)
    }

    #[cfg(not(feature = "build-noir-artifacts"))]
    {
        download_noir_ownership_proof(out_dir)
    }
}

#[cfg(feature = "build-noir-artifacts")]
fn build_noir_ownership_proof(out_dir: &Path) -> eyre::Result<()> {
    use generate_noir_artifacts::{
        OwnershipProofArtifactConfig, generate_ownership_proof_artifacts,
    };

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let circuit_dir = manifest_dir.join("noir/ownership-proof");

    println!(
        "cargo:rerun-if-changed={}",
        circuit_dir.join("src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        circuit_dir.join("Nargo.toml").display()
    );

    let config = OwnershipProofArtifactConfig {
        circuit_dir,
        artifact_dir: out_dir.to_path_buf(),
    };
    generate_ownership_proof_artifacts(&config)?;

    Ok(())
}

#[cfg(not(feature = "build-noir-artifacts"))]
fn download_noir_ownership_proof(out_dir: &Path) -> eyre::Result<()> {
    for file_name in NOIR_ARTIFACT_FILES {
        fetch_noir_artifact(file_name, out_dir)?;
    }

    Ok(())
}

#[cfg(not(feature = "build-noir-artifacts"))]
fn fetch_noir_artifact(file_name: &str, out_dir: &Path) -> eyre::Result<()> {
    let output_path = out_dir.join(file_name);
    let url = circuit_artifact_url(file_name);

    download_file(&url, &output_path).map_err(|e| {
        eyre::eyre!(
            "failed to fetch Noir artifact {file_name}. Enable `build-noir-artifacts` to generate it locally, or publish it at {url}: {e}"
        )
    })?;

    Ok(())
}

fn compress_zkey(input: &Path, output: &Path) -> eyre::Result<()> {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
    use circom_types::{ark_bn254::Bn254, groth16::ArkZkey};

    let input_bytes = fs::read(input)?;
    let zkey = ArkZkey::<Bn254>::deserialize_with_mode(
        input_bytes.as_slice(),
        Compress::No,
        Validate::Yes,
    )?;

    let mut compressed = Vec::new();
    zkey.serialize_with_mode(&mut compressed, Compress::Yes)?;
    fs::write(output, compressed)?;

    Ok(())
}
