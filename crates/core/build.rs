use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use serde_json::Value;
use std::env;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::{
    fs,
    hash::{DefaultHasher, Hash, Hasher},
    process::{Command, Stdio},
};

const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

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

// (sol_file_name, contract_name) - usually the same, but can differ
const CONTRACT_TARGETS: &[(&str, &str)] = &[
    (
        "CredentialSchemaIssuerRegistry",
        "CredentialSchemaIssuerRegistry",
    ),
    ("Poseidon2", "Poseidon2T2"),
    ("PackedAccountData", "PackedAccountData"),
    ("BinaryIMT", "BinaryIMT"),
    ("WorldIDRegistry", "WorldIDRegistry"),
    ("Verifier", "Verifier"),
    ("BabyJubJub", "BabyJubJub"),
    ("OprfKeyRegistry", "OprfKeyRegistry"),
    ("ERC1967Proxy", "ERC1967Proxy"),
];

#[cfg(feature = "embed-zkeys")]
fn download_file(url: &str, output_path: &Path) -> anyhow::Result<()> {
    let response = reqwest::blocking::get(url)?;

    if !response.status().is_success() {
        return Err(anyhow::format_err!(format!(
            "HTTP error {}: {}",
            response.status(),
            url
        )));
    }

    let mut file = File::create(output_path)?;
    let content = response.bytes()?;
    io::copy(&mut content.as_ref(), &mut file)?;

    Ok(())
}

fn fetch_circuit_file(filename: &str, repo_path: &str, out_dir: &Path) -> anyhow::Result<PathBuf> {
    let output_path = out_dir.join(filename);

    // Check for local file first (development)

    let local_path = Path::new(&CARGO_MANIFEST_DIR)
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

fn embed_zkeys() -> anyhow::Result<()> {
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

fn compile_contracts() -> anyhow::Result<()> {
    let status = Command::new("forge")
        .arg("build")
        .current_dir("../../contracts")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    if !status.success() {
        panic!("fialed to compile contracts");
    }

    let forge_out_dir = PathBuf::from(CARGO_MANIFEST_DIR).join("../../contracts/out");
    let res_out_dir = PathBuf::from(CARGO_MANIFEST_DIR).join("contracts/out");

    CONTRACT_TARGETS
        .par_iter()
        .for_each(|(sol_file, contract_name)| {
            let new_abi = forge_out_dir
                .join(format!("{sol_file}.sol"))
                .join(format!("{contract_name}.json"));

            if !new_abi.exists() {
                panic!("Contract ABI not found at {}", new_abi.display());
            }

            let prev_abi = res_out_dir
                .join(format!("{sol_file}.sol"))
                .join(format!("{contract_name}Abi.json"));

            if !prev_abi.exists() {
                if let Some(parent) = prev_abi.parent() {
                    fs::create_dir_all(parent).expect("failed to create abi directory");
                }

                fs::copy(&new_abi, &prev_abi).unwrap();

                let prev_contents: Value =
                    serde_json::from_str(&fs::read_to_string(&prev_abi).unwrap()).unwrap();
                let new_contents: Value =
                    serde_json::from_str(&fs::read_to_string(&new_abi).unwrap()).unwrap();

                let prev_bytecode = prev_contents["bytecode"]["object"]
                    .as_str()
                    .expect("Missing prev bytecode");
                let new_bytecode = new_contents["bytecode"]["object"]
                    .as_str()
                    .expect("Missing new bytecode");

                if hash(prev_bytecode) != hash(new_bytecode) {
                    fs::copy(&new_abi, &prev_abi).unwrap();
                }
            }
        });

    println!("cargo:rerun-if-changed=contracts");

    Ok(())
}

fn hash(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn main() -> anyhow::Result<()> {
    // Skip for docs.rs as it doesn't have network access
    if env::var("DOCS_RS").is_ok() {
        println!("cargo:warning=Building for docs.rs, skipping circuit file downloads");
        return Ok(());
    }

    let _ = rayon::join(|| compile_contracts(), || embed_zkeys());

    println!("cargo:rerun-if-changed=build.rs");

    Ok(())
}
