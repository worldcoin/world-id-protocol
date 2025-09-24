use std::{env, fs, path::PathBuf};

fn main() {
    // Path to the root of the repo
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf();

    // Source ABI produced by Foundry
    let src = repo_root
        .join("contracts")
        .join("out")
        .join("AccountRegistry.sol")
        .join("AccountRegistry.json");

    // Destination inside OUT_DIR for include_bytes!
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dst = out_dir.join("AccountRegistry.json");

    // Rebuild if the ABI changes
    println!("cargo:rerun-if-changed={}", src.display());

    fs::create_dir_all(&out_dir).unwrap();
    fs::copy(&src, &dst).expect("failed to copy AccountRegistry ABI");
}
