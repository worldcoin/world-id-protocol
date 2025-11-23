use std::env;
use std::fs;
use std::path::PathBuf;

/// Copies the contract ABIs and circuit material to the crate directory for cargo package.
/// This runs automatically as part of the build process.
fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_path = PathBuf::from(&manifest_dir);
    let workspace_root = manifest_path.parent().unwrap().parent().unwrap();

    // Source paths (in workspace root)
    let workspace_circom = workspace_root.join("circom");
    let workspace_contract = workspace_root.join("contracts/out/AccountRegistry.sol/AccountRegistryAbi.json");

    // Destination paths (in crate directory)
    let crate_circom = manifest_path.join("circom");
    let crate_contract_dir = manifest_path.join("contracts/out/AccountRegistry.sol");

    // Copy circom files
    if workspace_circom.exists() && !crate_circom.exists() {
        fs::create_dir_all(&crate_circom).ok();
        for file in &[
            "OPRFQueryGraph.bin",
            "OPRFNullifierGraph.bin",
            "OPRFQuery.arks.zkey",
            "OPRFNullifier.arks.zkey",
        ] {
            let src = workspace_circom.join(file);
            if src.exists() {
                fs::copy(&src, crate_circom.join(file)).ok();
            }
        }
    }

    // Copy contract ABI
    if workspace_contract.exists() {
        fs::create_dir_all(&crate_contract_dir).ok();
        fs::copy(&workspace_contract, crate_contract_dir.join("AccountRegistryAbi.json")).ok();
    }

    // Tell cargo to rerun if source files change
    println!("cargo:rerun-if-changed=../../contracts/out/AccountRegistry.sol/AccountRegistryAbi.json");
    println!("cargo:rerun-if-changed=../../circom");
}
