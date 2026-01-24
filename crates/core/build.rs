use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use circom_types::{ark_bn254::Bn254, groth16::ArkZkey};
use rayon::prelude::*;
use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("cargo:rerun-if-changed=build.rs");

    if !std::env::var("CARGO_FEATURE_COMPRESS_ZKEYS").is_ok() {
        return Ok(());
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or("failed to resolve workspace root from CARGO_MANIFEST_DIR")?;
    let circom_dir = workspace_root.join("circom");

    if !circom_dir.is_dir() {
        return Err(format!("circom directory not found at {}", circom_dir.display()).into());
    }

    // Watch the directory itself for new/removed files
    println!("cargo:rerun-if-changed={}", circom_dir.display());

    // Collect all zkey files first
    let zkey_files: Vec<_> = fs::read_dir(&circom_dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| is_arks_zkey(path))
        .collect();

    // Register rerun-if-changed for all zkey files
    for path in &zkey_files {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    // Process files in parallel, collecting errors
    let results: Vec<_> = zkey_files
        .par_iter()
        .filter_map(|path| {
            let file_name = path.file_name()?.to_str()?;
            let output_path = circom_dir.join(format!("{file_name}.compressed"));

            // Skip if output exists and is newer than input
            if is_up_to_date(path, &output_path) {
                return None;
            }

            Some(compress_zkey(path, &output_path))
        })
        .collect();

    // Check for any errors
    for result in results {
        result?;
    }

    Ok(())
}

fn is_arks_zkey(path: &Path) -> bool {
    match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => name.ends_with(".arks.zkey"),
        None => false,
    }
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

fn compress_zkey(
    input: &Path,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
