use std::path::PathBuf;
use std::process::{Command, Stdio};

const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn main() {
    let contracts_dir = PathBuf::from(CARGO_MANIFEST_DIR).join("../../contracts");

    // Only compile if the contracts directory exists
    if contracts_dir.exists() {
        let status = Command::new("forge")
            .arg("build")
            .current_dir(&contracts_dir)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();

        match status {
            Ok(s) if s.success() => {}
            Ok(_) => panic!("forge build failed"),
            Err(e) => {
                // Don't fail if forge isn't installed - contracts may already be built
                println!("cargo:warning=forge not available: {e}");
            }
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../contracts");
}
