use eyre::{OptionExt, bail};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[cfg(feature = "embed-zkeys")]
use std::{fs::File, io};

#[cfg(feature = "embed-zkeys")]
const GITHUB_REPO: &str = "worldcoin/world-id-protocol";

#[cfg(feature = "embed-zkeys")]
const CIRCUIT_COMMIT: &str = "cebbe92ba48fac9dd5f60c3f9272a2b82f075ecc"; // TODO: Figure out a better way for static commits

const CIRCUIT_FILES: &[&str] = &[
    "circom/OPRFQueryGraph.bin",
    "circom/OPRFNullifierGraph.bin",
    "circom/OPRFQuery.arks.zkey",
    "circom/OPRFNullifier.arks.zkey",
];

fn main() -> eyre::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var_os("DOCS_RS").is_some() {
        // Define a cfg only for THIS crate’s compilation.
        println!("cargo:rustc-cfg=docsrs");
        println!("cargo:rustc-check-cfg=cfg(docsrs)");
    }

    // Skip for docs.rs as it doesn't have network access
    if env::var("DOCS_RS").is_ok() {
        println!("cargo:warning=Building for docs.rs, skipping circuit file downloads");
        return Ok(());
    }

    if env::var("CARGO_FEATURE_EMBED_ZKEYS").is_err() {
        return Ok(());
    };

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

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
            let encoder = zstd::Encoder::new(file, 19)?;
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

#[cfg(feature = "embed-zkeys")]
fn download_file(url: &str, output_path: &Path) -> eyre::Result<()> {
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

        if let Some(path) = local_path {
            if path.exists() {
                std::fs::hard_link(&path, &output_path).ok();
                println!("cargo:rerun-if-changed={}", path.display());
                return Ok(());
            }
        }
    }

    // Download from GitHub
    #[cfg(feature = "embed-zkeys")]
    {
        let url = format!(
            "https://raw.githubusercontent.com/{}/{}/{}",
            GITHUB_REPO,
            CIRCUIT_COMMIT,
            path.to_str().ok_or_eyre("invalid path")?
        );

        download_file(&url, &output_path)?;
        Ok(())
    }

    #[cfg(not(feature = "embed-zkeys"))]
    return Ok(());
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
        bail!("circom directory not found at {}", circom_dir.display());
    }

    // Watch the directory itself for new/removed files
    println!("cargo:rerun-if-changed={}", circom_dir.display());

    // Collect all zkey files first
    fs::read_dir(out_dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| is_arks_zkey(path))
        .par_bridge()
        .try_for_each(|path| {
            let file_name = path
                .file_name()
                .ok_or_eyre("missing filename")?
                .to_str()
                .unwrap();
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
