//! Upload VK command - upload a verification key to the chain

use crate::config::Config;
use crate::CommonArgs;
use anyhow::{Context, Result};
use clap::Args;
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use solana_noir_verifier_sdk::{SolanaNoirVerifier, VerifierConfig};
use std::fs;
use std::path::PathBuf;

#[derive(Args)]
pub struct UploadVkArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// Path to the verification key file
    #[arg(long)]
    vk: PathBuf,
}

pub fn run(config: &Config, args: UploadVkArgs) -> Result<()> {
    // Load VK
    let vk_bytes =
        fs::read(&args.vk).with_context(|| format!("Failed to read VK file: {:?}", args.vk))?;

    if !config.quiet {
        println!(
            "{} Uploading VK ({} bytes) to {}...",
            style("→").cyan().bold(),
            vk_bytes.len(),
            config.rpc_url
        );
    }

    // Setup client
    let program_id = config.require_program_id()?;
    let keypair = config.load_keypair()?;
    let client = config.rpc_client();

    let verifier = SolanaNoirVerifier::new(client, VerifierConfig::new(program_id));

    // Progress bar
    let pb = if !config.quiet && !config.json_output {
        let pb = ProgressBar::new(100);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {msg}")
                .unwrap()
                .progress_chars("█▓░"),
        );
        pb.set_message("Uploading VK...");
        Some(pb)
    } else {
        None
    };

    // Upload VK
    let result = verifier.upload_vk(&keypair, &vk_bytes)?;

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    if config.json_output {
        println!(
            r#"{{"vk_account": "{}", "chunks": {}, "signatures": {:?}}}"#,
            result.vk_account,
            result.num_chunks,
            result
                .signatures
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
    } else if !config.quiet {
        println!("{} VK uploaded successfully!", style("✓").green().bold());
        println!(
            "  VK Account: {}",
            style(result.vk_account.to_string()).cyan()
        );
        println!("  Chunks: {}", result.num_chunks);
        println!();
        println!("Use this account for verification:");
        println!("  noir-solana verify --vk-account {}", result.vk_account);
    }

    Ok(())
}
