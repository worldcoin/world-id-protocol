use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn main() {
    let contracts_dir = PathBuf::from(CARGO_MANIFEST_DIR).join("../../contracts");

    // Skip forge build when contract artifacts are pre-built (e.g. in CI).
    // Set CONTRACTS_PREBUILT=1 when contracts/out/ is provided externally.
    let prebuilt = std::env::var("CONTRACTS_PREBUILT").is_ok();

    if contracts_dir.exists() && !prebuilt {
        let status = Command::new("forge")
            .arg("build")
            .current_dir(&contracts_dir)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();

        match status {
            Ok(s) if s.success() => {}
            Ok(_) => panic!("forge build failed"),
            Err(e) => panic!("forge build failed {}, forge is likely not installed", e),
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../contracts/src");
}
