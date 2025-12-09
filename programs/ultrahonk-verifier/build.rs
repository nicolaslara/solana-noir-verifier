// Build script to copy the VK file based on CIRCUIT environment variable
//
// Usage:
//   CIRCUIT=simple_square cargo build-sbf          # default
//   CIRCUIT=iterated_square_100 cargo build-sbf
//   CIRCUIT=hash_batch cargo build-sbf
//
// TODO: Support loading VK from an account for production use.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Get circuit name from environment, default to simple_square
    let circuit = env::var("CIRCUIT").unwrap_or_else(|_| "simple_square".to_string());

    // Build source and destination paths
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let src_path = Path::new(&manifest_dir)
        .join("..")
        .join("..")
        .join("test-circuits")
        .join(&circuit)
        .join("target")
        .join("keccak")
        .join("vk");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dst_path = Path::new(&out_dir).join("vk.bin");

    // Copy VK file
    if src_path.exists() {
        fs::copy(&src_path, &dst_path).expect("Failed to copy VK file");
        println!("cargo:rustc-env=VK_PATH={}", dst_path.display());
        println!("cargo:warning=Using VK from circuit: {}", circuit);
    } else {
        panic!(
            "VK file not found: {}\nMake sure to build the circuit first:\n  cd test-circuits/{} && nargo compile && bb write_vk ...",
            src_path.display(),
            circuit
        );
    }

    // Rerun if CIRCUIT changes or VK file changes
    println!("cargo:rerun-if-env-changed=CIRCUIT");
    println!("cargo:rerun-if-changed={}", src_path.display());
}
