//! Close command - close accounts and reclaim rent

use crate::config::Config;
use crate::CommonArgs;
use anyhow::{Context, Result};
use clap::Args;
use console::style;
use solana_noir_verifier_sdk::{SolanaNoirVerifier, VerifierConfig};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

#[derive(Args)]
pub struct CloseArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// State account public key
    #[arg(long)]
    state_account: String,

    /// Proof account public key
    #[arg(long)]
    proof_account: String,
}

pub fn run(config: &Config, args: CloseArgs) -> Result<()> {
    let state_account =
        Pubkey::from_str(&args.state_account).context("Invalid state account public key")?;
    let proof_account =
        Pubkey::from_str(&args.proof_account).context("Invalid proof account public key")?;

    if !config.quiet && !config.json_output {
        println!(
            "{} Closing accounts and reclaiming rent...",
            style("→").cyan().bold()
        );
    }

    // Setup client
    let program_id = config.require_program_id()?;
    let keypair = config.load_keypair()?;
    let client = config.rpc_client();

    let verifier = SolanaNoirVerifier::new(client, VerifierConfig::new(program_id));

    // Close accounts
    let (rent_reclaimed, signature) =
        verifier.close_accounts(&keypair, &state_account, &proof_account)?;

    if config.json_output {
        println!(
            r#"{{"closed": true, "rent_reclaimed_lamports": {}, "signature": "{}"}}"#,
            rent_reclaimed, signature
        );
    } else if !config.quiet {
        println!("{} Accounts closed!", style("✓").green().bold());
        println!(
            "  Rent reclaimed: {} lamports ({:.6} SOL)",
            rent_reclaimed,
            rent_reclaimed as f64 / 1_000_000_000.0
        );
        println!("  Signature: {}", signature);
    }

    Ok(())
}
