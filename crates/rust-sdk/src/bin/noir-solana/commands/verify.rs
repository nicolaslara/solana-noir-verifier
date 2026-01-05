//! Verify command - verify a proof on-chain

use crate::config::Config;
use crate::CommonArgs;
use anyhow::{Context, Result};
use clap::Args;
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use solana_noir_verifier_sdk::{SolanaNoirVerifier, VerifierConfig, VerifyOptions};
use solana_sdk::pubkey::Pubkey;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Args)]
pub struct VerifyArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// Path to the proof file
    #[arg(long)]
    proof: PathBuf,

    /// Path to the public inputs file
    #[arg(long)]
    public_inputs: PathBuf,

    /// VK account public key
    #[arg(long)]
    vk_account: String,

    /// Skip preflight simulation (faster but less safe)
    #[arg(long)]
    skip_preflight: bool,

    /// Don't close accounts after verification (keep state for debugging)
    #[arg(long)]
    no_close: bool,
}

pub fn run(config: &Config, args: VerifyArgs) -> Result<()> {
    // Load proof and public inputs
    let proof_bytes = fs::read(&args.proof)
        .with_context(|| format!("Failed to read proof file: {:?}", args.proof))?;
    let pi_bytes = fs::read(&args.public_inputs).with_context(|| {
        format!(
            "Failed to read public inputs file: {:?}",
            args.public_inputs
        )
    })?;

    let vk_account = Pubkey::from_str(&args.vk_account).context("Invalid VK account public key")?;

    if !config.quiet {
        println!(
            "{} Verifying proof on {}...",
            style("→").cyan().bold(),
            config.rpc_url
        );
        println!("  Proof: {} bytes", proof_bytes.len());
        println!("  Public inputs: {} bytes", pi_bytes.len());
        println!("  VK Account: {}", vk_account);
        println!();
    }

    // Setup client
    let program_id = config.require_program_id()?;
    let keypair = config.load_keypair()?;
    let client = config.rpc_client();

    let verifier = SolanaNoirVerifier::new(client, VerifierConfig::new(program_id));

    // Progress bar for phases
    let pb = if !config.quiet && !config.json_output {
        let pb = ProgressBar::new(9); // 9 transactions
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} TXs - {msg}")
                .unwrap()
                .progress_chars("█▓░"),
        );
        pb.set_message("Starting verification...");
        Some(pb)
    } else {
        None
    };

    // Verification options
    let options = VerifyOptions {
        skip_preflight: args.skip_preflight,
        auto_close: !args.no_close,
    };

    // Run verification
    let result = verifier.verify(
        &keypair,
        &proof_bytes,
        &pi_bytes,
        &vk_account,
        Some(options),
    );

    if let Some(pb) = &pb {
        pb.finish_and_clear();
    }

    match result {
        Ok(result) => {
            if config.json_output {
                println!(
                    r#"{{"verified": {}, "total_cus": {}, "num_transactions": {}, "state_account": "{}", "proof_account": "{}"}}"#,
                    result.verified,
                    result.total_cus,
                    result.num_transactions,
                    result.state_account,
                    result.proof_account
                );
            } else if !config.quiet {
                if result.verified {
                    println!("{} Proof verified successfully!", style("✓").green().bold());
                } else {
                    println!("{} Proof verification failed", style("✗").red().bold());
                }
                println!();
                println!("  Transactions: {}", result.num_transactions);
                println!("  Total CUs: {}", result.total_cus);
                println!("  State Account: {}", result.state_account);
                println!("  Proof Account: {}", result.proof_account);

                if !args.no_close {
                    println!();
                    println!("  {} Accounts closed, rent reclaimed", style("→").dim());
                }
            }
            Ok(())
        }
        Err(e) => {
            if config.json_output {
                println!(r#"{{"verified": false, "error": "{}"}}"#, e);
            }
            Err(e.into())
        }
    }
}
