use std::{
    env,
    fs::File,
    io,
    path::{Path, PathBuf},
};

#[cfg(feature = "embed-zkeys")]
const GITHUB_REPO: &str = "worldcoin/world-id-protocol";

#[cfg(feature = "embed-zkeys")]
const CIRCUIT_COMMIT: &str = "cebbe92ba48fac9dd5f60c3f9272a2b82f075ecc"; // TODO: Figure out a better way for static commits

const CIRCUIT_FILES: &[(&str, &str)] = &[
    ("OPRFQueryGraph.bin", "circom/OPRFQueryGraph.bin"),
    ("OPRFNullifierGraph.bin", "circom/OPRFNullifierGraph.bin"),
    ("OPRFQuery.arks.zkey", "circom/OPRFQuery.arks.zkey"),
    ("OPRFNullifier.arks.zkey", "circom/OPRFNullifier.arks.zkey"),
];

#[cfg(feature = "embed-zkeys")]
fn download_file(url: &str, output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let response = reqwest::blocking::get(url)?;

    if !response.status().is_success() {
        return Err(format!("HTTP error {}: {}", response.status(), url).into());
    }

    let mut file = File::create(output_path)?;
    let content = response.bytes()?;
    io::copy(&mut content.as_ref(), &mut file)?;

    Ok(())
}

fn fetch_circuit_file(
    filename: &str,
    repo_path: &str,
    out_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let output_path = out_dir.join(filename);

    // Check for local file first (development)
    if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
        let local_path = Path::new(&manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join(repo_path));

        if let Some(path) = local_path {
            if path.exists() {
                std::fs::copy(&path, &output_path)?;
                println!("cargo:rerun-if-changed={}", path.display());
                return Ok(output_path);
            }
        }
    }

    // Download from GitHub
    #[cfg(feature = "embed-zkeys")]
    {
        let url = format!(
            "https://raw.githubusercontent.com/{}/{}/{}",
            GITHUB_REPO, CIRCUIT_COMMIT, repo_path
        );

        download_file(&url, &output_path)?;
        Ok(output_path)
    }

    #[cfg(not(feature = "embed-zkeys"))]
    {
        Err(format!(
            "Circuit file {} not found locally and embed-zkeys feature is not enabled. \
             Enable the embed-zkeys feature or provide circuit files manually.",
            filename
        )
        .into())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=build.rs");

    // Skip for docs.rs as it doesn't have network access
    if env::var("DOCS_RS").is_ok() {
        println!("cargo:warning=Building for docs.rs, skipping circuit file downloads");
        return Ok(());
    }

    let embed_zkeys = env::var("CARGO_FEATURE_EMBED_ZKEYS").is_ok();

    // Only fetch circuit files if embed-zkeys feature is enabled
    if embed_zkeys {
        let out_dir = PathBuf::from(env::var("OUT_DIR")?);

        for (filename, repo_path) in CIRCUIT_FILES {
            fetch_circuit_file(filename, repo_path, &out_dir)?;
        }
    }

    Ok(())
}
