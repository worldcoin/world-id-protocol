use std::env;
use std::fs;
use std::path::PathBuf;

/// Copies the contract ABIs and circuit material to the crate directory to allow publishing.
fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_path = PathBuf::from(&manifest_dir);

    let workspace_root = manifest_path.parent().unwrap().parent().unwrap();
    let contracts_src =
        workspace_root.join("contracts/out/AccountRegistry.sol/AccountRegistryAbi.json");
    let circom_dir = workspace_root.join("circom");

    let contracts_dest = manifest_path.join("contracts/out/AccountRegistry.sol");
    let circom_dest = manifest_path.join("circom");

    if contracts_src.exists() {
        fs::create_dir_all(&contracts_dest).ok();
        fs::copy(
            &contracts_src,
            contracts_dest.join("AccountRegistryAbi.json"),
        )
        .ok();
    }

    if circom_dir.exists() {
        fs::create_dir_all(&circom_dest).ok();

        for file in &[
            "OPRFQueryGraph.bin",
            "OPRFNullifierGraph.bin",
            "OPRFQuery.arks.zkey",
            "OPRFNullifier.arks.zkey",
        ] {
            let src = circom_dir.join(file);
            if src.exists() {
                fs::copy(&src, circom_dest.join(file)).ok();
            }
        }
    }

    println!(
        "cargo:rerun-if-changed=../../contracts/out/AccountRegistry.sol/AccountRegistryAbi.json"
    );
    println!("cargo:rerun-if-changed=../../circom/OPRFQueryGraph.bin");
    println!("cargo:rerun-if-changed=../../circom/OPRFNullifierGraph.bin");
    println!("cargo:rerun-if-changed=../../circom/OPRFQuery.arks.zkey");
    println!("cargo:rerun-if-changed=../../circom/OPRFNullifier.arks.zkey");
}
