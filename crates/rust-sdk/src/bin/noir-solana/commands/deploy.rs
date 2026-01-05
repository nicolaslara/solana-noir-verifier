//! Deploy command - deploy verifier program to the network

use crate::config::Config;
use crate::CommonArgs;
use anyhow::{Context, Result};
use clap::Args;
use console::style;
use std::path::PathBuf;
use std::process::Command;

#[derive(Args)]
pub struct DeployArgs {
    #[command(flatten)]
    pub common: CommonArgs,

    /// Path to the compiled program (.so file)
    #[arg(
        long,
        default_value = "programs/ultrahonk-verifier/target/deploy/ultrahonk_verifier.so"
    )]
    program: PathBuf,

    /// Use existing keypair for program ID (for upgrades)
    #[arg(long)]
    program_keypair: Option<PathBuf>,
}

pub fn run(config: &Config, args: DeployArgs) -> Result<()> {
    if !config.quiet {
        println!(
            "{} Deploying verifier program to {}...",
            style("→").cyan().bold(),
            config.rpc_url
        );
    }

    // Check if program file exists
    if !args.program.exists() {
        anyhow::bail!(
            "Program file not found: {:?}\n\
            Build it first with: cd programs/ultrahonk-verifier && cargo build-sbf",
            args.program
        );
    }

    // Get keypair path
    let keypair_path = config
        .keypair_path
        .as_ref()
        .context("Keypair required for deployment")?;

    // Build solana deploy command
    let mut cmd = Command::new("solana");
    cmd.arg("program")
        .arg("deploy")
        .arg(&args.program)
        .arg("--url")
        .arg(&config.rpc_url)
        .arg("--keypair")
        .arg(keypair_path);

    if let Some(program_keypair) = &args.program_keypair {
        cmd.arg("--program-id").arg(program_keypair);
    }

    // Run deployment
    let output = cmd.output().context("Failed to run solana CLI")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Deployment failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse program ID from output
    // Format: "Program Id: <pubkey>"
    let program_id = stdout
        .lines()
        .find(|line| line.contains("Program Id:"))
        .and_then(|line| line.split(':').nth(1))
        .map(|s| s.trim())
        .context("Could not parse program ID from output")?;

    if config.json_output {
        println!(r#"{{"program_id": "{}"}}"#, program_id);
    } else if !config.quiet {
        println!(
            "{} Program deployed successfully!",
            style("✓").green().bold()
        );
        println!("  Program ID: {}", style(program_id).cyan());
        println!();
        println!("Add to your config:");
        println!("  export VERIFIER_PROGRAM_ID={}", program_id);
    }

    Ok(())
}
