//! Receipt commands - create and check verification receipts

use crate::config::Config;
use crate::CommonArgs;
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use console::style;
use solana_noir_verifier_sdk::{SolanaNoirVerifier, VerifierConfig};
use solana_sdk::pubkey::Pubkey;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Subcommand)]
pub enum ReceiptCommands {
    /// Create a verification receipt
    Create(CreateReceiptArgs),
    /// Check if a receipt exists
    Check(CheckReceiptArgs),
}

impl ReceiptCommands {
    pub fn common(&self) -> &CommonArgs {
        match self {
            ReceiptCommands::Create(args) => &args.common,
            ReceiptCommands::Check(args) => &args.common,
        }
    }
}

#[derive(Args)]
pub struct CreateReceiptArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// State account public key
    #[arg(long)]
    state_account: String,

    /// Proof account public key
    #[arg(long)]
    proof_account: String,

    /// VK account public key
    #[arg(long)]
    vk_account: String,

    /// Path to the public inputs file
    #[arg(long)]
    public_inputs: PathBuf,
}

#[derive(Args)]
pub struct CheckReceiptArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// VK account public key
    #[arg(long)]
    vk_account: String,

    /// Path to the public inputs file
    #[arg(long)]
    public_inputs: PathBuf,
}

pub fn run(config: &Config, command: ReceiptCommands) -> Result<()> {
    match command {
        ReceiptCommands::Create(args) => create_receipt(config, args),
        ReceiptCommands::Check(args) => check_receipt(config, args),
    }
}

fn create_receipt(config: &Config, args: CreateReceiptArgs) -> Result<()> {
    let state_account =
        Pubkey::from_str(&args.state_account).context("Invalid state account public key")?;
    let proof_account =
        Pubkey::from_str(&args.proof_account).context("Invalid proof account public key")?;
    let vk_account = Pubkey::from_str(&args.vk_account).context("Invalid VK account public key")?;
    let pi_bytes = fs::read(&args.public_inputs)
        .with_context(|| format!("Failed to read public inputs: {:?}", args.public_inputs))?;

    if !config.quiet && !config.json_output {
        println!(
            "{} Creating verification receipt...",
            style("→").cyan().bold()
        );
    }

    // Setup client
    let program_id = config.require_program_id()?;
    let keypair = config.load_keypair()?;
    let client = config.rpc_client();

    let verifier = SolanaNoirVerifier::new(client, VerifierConfig::new(program_id));

    // Derive receipt PDA
    let (receipt_pda, _bump) = verifier.derive_receipt_pda(&vk_account, &pi_bytes);

    // Create receipt
    let receipt_pubkey = verifier.create_receipt(
        &keypair,
        &state_account,
        &proof_account,
        &vk_account,
        &pi_bytes,
    )?;

    if config.json_output {
        println!(r#"{{"receipt_pda": "{}"}}"#, receipt_pubkey);
    } else if !config.quiet {
        println!("{} Receipt created!", style("✓").green().bold());
        println!("  Receipt PDA: {}", style(receipt_pda.to_string()).cyan());
    }

    Ok(())
}

fn check_receipt(config: &Config, args: CheckReceiptArgs) -> Result<()> {
    let vk_account = Pubkey::from_str(&args.vk_account).context("Invalid VK account public key")?;
    let pi_bytes = fs::read(&args.public_inputs)
        .with_context(|| format!("Failed to read public inputs: {:?}", args.public_inputs))?;

    if !config.quiet && !config.json_output {
        println!(
            "{} Checking verification receipt...",
            style("→").cyan().bold()
        );
    }

    // Setup client
    let program_id = config.require_program_id()?;
    let client = config.rpc_client();

    let verifier = SolanaNoirVerifier::new(client, VerifierConfig::new(program_id));

    // Check receipt
    let receipt = verifier.get_receipt(&vk_account, &pi_bytes)?;

    match receipt {
        Some(receipt) => {
            if config.json_output {
                println!(
                    r#"{{"exists": true, "verified_slot": {}, "verified_timestamp": {}}}"#,
                    receipt.verified_slot, receipt.verified_timestamp
                );
            } else if !config.quiet {
                println!("{} Receipt found!", style("✓").green().bold());
                println!("  Verified Slot: {}", receipt.verified_slot);
                println!("  Verified At: {}", receipt.verified_timestamp);
            }
        }
        None => {
            if config.json_output {
                println!(r#"{{"exists": false}}"#);
            } else if !config.quiet {
                println!(
                    "{} No receipt found for this proof",
                    style("✗").yellow().bold()
                );
            }
        }
    }

    Ok(())
}
