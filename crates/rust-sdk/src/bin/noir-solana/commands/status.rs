//! Status command - check verification state

use crate::config::Config;
use crate::CommonArgs;
use anyhow::{Context, Result};
use clap::Args;
use console::style;
use solana_noir_verifier_sdk::{SolanaNoirVerifier, VerificationPhase, VerifierConfig};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

#[derive(Args)]
pub struct StatusArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// State account public key
    #[arg(long)]
    state_account: String,
}

pub fn run(config: &Config, args: StatusArgs) -> Result<()> {
    let state_account =
        Pubkey::from_str(&args.state_account).context("Invalid state account public key")?;

    if !config.quiet && !config.json_output {
        println!(
            "{} Checking verification status...",
            style("→").cyan().bold()
        );
    }

    // Setup client
    let program_id = config.require_program_id()?;
    let client = config.rpc_client();

    let verifier = SolanaNoirVerifier::new(client, VerifierConfig::new(program_id));

    // Get verification state
    let state = verifier.get_verification_state(&state_account)?;

    let is_complete = state.phase == VerificationPhase::Verified;
    let is_failed = state.phase == VerificationPhase::Failed;

    if config.json_output {
        println!(
            r#"{{"phase": {:?}, "complete": {}, "failed": {}, "verified": {}}}"#,
            state.phase, is_complete, is_failed, state.verified
        );
    } else if !config.quiet {
        println!();
        println!("  State Account: {}", state_account);
        println!("  Current Phase: {:?}", state.phase);

        if is_complete {
            println!("  Status: {}", style("Complete ✓").green());
        } else if is_failed {
            println!("  Status: {}", style("Failed ✗").red());
        } else {
            println!("  Status: {}", style("In Progress...").yellow());
        }
    }

    Ok(())
}
