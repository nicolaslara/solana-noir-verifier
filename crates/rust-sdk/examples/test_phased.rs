//! End-to-end test for UltraHonk verification using the Rust SDK
//!
//! This mirrors the JavaScript test_phased.mjs - it's the main test entrypoint
//! for the Rust SDK.
//!
//! Usage:
//!   cargo run --example test_phased                    # Test simple_square (default)
//!   CIRCUIT=merkle_membership cargo run --example test_phased  # Test specific circuit
//!   VERBOSE=1 cargo run --example test_phased          # Show detailed output
//!
//! Environment variables:
//!   RPC_URL     - RPC endpoint (default: http://127.0.0.1:8899)
//!   PROGRAM_ID  - Verifier program ID (default: uses surfnet deployed program)
//!   CIRCUIT     - Circuit to test (default: simple_square)
//!   VERBOSE     - Show detailed output (default: 0)

use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_noir_verifier_sdk::{
    ReceiptInfo, SolanaNoirVerifier, VerificationResult, VerifierConfig, VerifyOptions,
    VkUploadResult, PROOF_SIZE, VK_SIZE,
};
use solana_sdk::{
    native_token::LAMPORTS_PER_SOL, pubkey::Pubkey, signature::Keypair, signer::Signer,
};
use std::{
    env, fs,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

fn main() {
    env_logger::init();

    // Configuration from environment
    let rpc_url = env::var("RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8899".to_string());
    let program_id_str = env::var("PROGRAM_ID")
        .unwrap_or_else(|_| "7sfMWfVs6P1ACjouyvRwWHjiAj6AsFkYARP2v9RBSSoe".to_string());
    let circuit_name = env::var("CIRCUIT").unwrap_or_else(|_| "simple_square".to_string());
    let _verbose = env::var("VERBOSE").unwrap_or_else(|_| "0".to_string()) == "1";

    let program_id = Pubkey::from_str(&program_id_str).expect("Invalid PROGRAM_ID");

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║       UltraHonk Verification Test (Rust SDK)                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    println!("Circuit: {}", circuit_name);
    println!("Program: {}", program_id);
    println!("RPC: {}", rpc_url);

    // Load test data
    let circuit_paths = get_circuit_paths(&circuit_name);
    let proof = fs::read(&circuit_paths.proof).unwrap_or_else(|_| {
        panic!(
            "Proof not found: {:?}\n   Run: cd test-circuits/{} && ./build.sh",
            circuit_paths.proof, circuit_name
        )
    });
    let public_inputs =
        fs::read(&circuit_paths.public_inputs).expect("Failed to read public inputs");
    let vk = fs::read(&circuit_paths.vk).expect("Failed to read VK");

    println!("\nProof: {} bytes (expected: {})", proof.len(), PROOF_SIZE);
    println!("VK: {} bytes (expected: {})", vk.len(), VK_SIZE);
    println!(
        "Public inputs: {} × 32 = {} bytes\n",
        public_inputs.len() / 32,
        public_inputs.len()
    );

    // Setup client
    let client = Arc::new(RpcClient::new_with_commitment(
        rpc_url.clone(),
        CommitmentConfig::confirmed(),
    ));

    // Generate and fund payer
    let payer = Keypair::new();
    println!("Funding payer account...");

    // Request airdrop
    let airdrop_sig = client
        .request_airdrop(&payer.pubkey(), 10 * LAMPORTS_PER_SOL)
        .expect("Airdrop failed");

    // Wait for confirmation
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(500));
        if let Ok(Some(result)) = client.get_signature_status(&airdrop_sig) {
            if result.is_ok() {
                break;
            }
        }
    }
    println!("  ✅ Funded\n");

    // Create verifier
    let verifier = SolanaNoirVerifier::new(client.clone(), VerifierConfig::new(program_id));

    // VK Upload
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           CIRCUIT DEPLOYMENT (one-time per circuit)          ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    let vk_start = Instant::now();
    let vk_result: VkUploadResult = verifier.upload_vk(&payer, &vk).expect("VK upload failed");
    let vk_time = vk_start.elapsed();

    println!("  VK Account: {}", vk_result.vk_account);
    println!("  Chunks: {}", vk_result.num_chunks);
    println!("  Time: {:.2}s", vk_time.as_secs_f64());
    println!("  ✅ VK uploaded\n");

    // Verification
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║              PROOF VERIFICATION (per proof)                  ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    let verify_start = Instant::now();
    let result: VerificationResult = verifier
        .verify(
            &payer,
            &proof,
            &public_inputs,
            &vk_result.vk_account,
            Some(VerifyOptions::new().without_auto_close()), // Don't auto-close, we'll do it manually
        )
        .expect("Verification failed");
    let verify_time = verify_start.elapsed();

    println!(
        "\n  Verified: {}",
        if result.verified { "✅ YES" } else { "❌ NO" }
    );
    println!("  Total CUs: {}", format_number(result.total_cus));
    println!(
        "  Transactions: {} ({} sequential steps)",
        result.num_transactions, result.num_steps
    );
    println!("  Time: {:.2}s", verify_time.as_secs_f64());

    if !result.verified {
        eprintln!("\n❌ Verification failed!");
        std::process::exit(1);
    }

    // Receipt
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║         RECEIPT CREATION (for integrators)                   ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    let (receipt_pda, _) = verifier.derive_receipt_pda(&vk_result.vk_account, &public_inputs);
    println!("  Receipt PDA: {}", receipt_pda);

    verifier
        .create_receipt(
            &payer,
            &result.state_account,
            &result.proof_account,
            &vk_result.vk_account,
            &public_inputs,
        )
        .expect("Receipt creation failed");
    println!("  ✅ Receipt created\n");

    // Validate receipt
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║         RECEIPT VALIDATION (integrator check)                ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    let receipt: Option<ReceiptInfo> = verifier
        .get_receipt(&vk_result.vk_account, &public_inputs)
        .expect("Failed to get receipt");

    if let Some(info) = receipt {
        println!("  ✅ Receipt found!");
        println!("     Verified at slot: {}", info.verified_slot);
        println!(
            "     Verified at: {}",
            format_timestamp(info.verified_timestamp)
        );
    } else {
        eprintln!("  ❌ Receipt not found");
        std::process::exit(1);
    }

    // Close accounts
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║         ACCOUNT CLEANUP (recover rent)                       ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    let (recovered, _) = verifier
        .close_accounts(&payer, &result.state_account, &result.proof_account)
        .expect("Failed to close accounts");
    let sol_recovered = recovered as f64 / LAMPORTS_PER_SOL as f64;
    println!("  ✅ Accounts closed");
    println!(
        "     Recovered: {:.4} SOL ({} lamports)",
        sol_recovered, recovered
    );

    // Summary
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                         SUMMARY                              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    println!("\n  Circuit: {}", circuit_name);
    println!("  VK deployment: {:.2}s (one-time)", vk_time.as_secs_f64());
    println!("  Proof verification: {:.2}s", verify_time.as_secs_f64());
    println!("  Total CUs: {}", format_number(result.total_cus));
    println!(
        "  Transactions: {} ({} sequential steps)",
        result.num_transactions, result.num_steps
    );
    println!("  Rent recovered: {:.4} SOL", sol_recovered);
    println!("\n  VK Account: {}", vk_result.vk_account);
    println!("  Receipt: {}", receipt_pda);

    println!("\n  🎉 All tests passed!\n");
}

struct CircuitPaths {
    proof: PathBuf,
    public_inputs: PathBuf,
    vk: PathBuf,
}

fn get_circuit_paths(circuit_name: &str) -> CircuitPaths {
    // Find workspace root
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();

    let circuit_dir = workspace_root
        .join("test-circuits")
        .join(circuit_name)
        .join("target")
        .join("keccak");

    CircuitPaths {
        proof: circuit_dir.join("proof"),
        public_inputs: circuit_dir.join("public_inputs"),
        vk: circuit_dir.join("vk"),
    }
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, c);
    }
    result
}

fn format_timestamp(ts: i64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    if ts <= 0 {
        return "N/A".to_string();
    }

    let dt = UNIX_EPOCH + Duration::from_secs(ts as u64);
    match dt.duration_since(UNIX_EPOCH) {
        Ok(_) => {
            // Simple ISO-ish format
            let now = SystemTime::now();
            match now.duration_since(UNIX_EPOCH) {
                Ok(now_dur) => {
                    let diff = now_dur.as_secs().saturating_sub(ts as u64);
                    if diff < 60 {
                        format!("{} seconds ago", diff)
                    } else if diff < 3600 {
                        format!("{} minutes ago", diff / 60)
                    } else {
                        format!("Unix timestamp: {}", ts)
                    }
                }
                Err(_) => format!("Unix timestamp: {}", ts),
            }
        }
        Err(_) => format!("Unix timestamp: {}", ts),
    }
}
