//! noir-solana CLI - Verify Noir proofs on Solana
//!
//! This CLI provides commands for deploying the verifier program,
//! uploading verification keys, and verifying proofs on Solana.

mod commands;
mod config;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use commands::{close, deploy, receipt, status, upload_vk, verify};
use console::style;

/// CLI for verifying Noir UltraHonk proofs on Solana
#[derive(Parser)]
#[command(name = "noir-solana")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Common options shared across commands
#[derive(Args, Clone)]
pub struct CommonArgs {
    /// Network to connect to (mainnet, devnet, localnet, or custom URL)
    #[arg(short, long, env = "SOLANA_RPC_URL", default_value = "localnet")]
    pub network: String,

    /// Path to keypair file
    #[arg(short, long, env = "KEYPAIR_PATH")]
    pub keypair: Option<String>,

    /// Verifier program ID
    #[arg(short, long, env = "VERIFIER_PROGRAM_ID")]
    pub program_id: Option<String>,

    /// Output format (human, json)
    #[arg(long, default_value = "human")]
    pub output: OutputFormat,

    /// Quiet mode (minimal output)
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
}

#[derive(Subcommand)]
enum Commands {
    /// Deploy the verifier program to the network
    Deploy(deploy::DeployArgs),

    /// Upload a verification key to the chain
    UploadVk(upload_vk::UploadVkArgs),

    /// Verify a proof on-chain (full workflow)
    Verify(verify::VerifyArgs),

    /// Check verification status
    Status(status::StatusArgs),

    /// Manage verification receipts
    #[command(subcommand)]
    Receipt(receipt::ReceiptCommands),

    /// Close accounts and reclaim rent
    Close(close::CloseArgs),
}

fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .format_target(false)
        .init();

    let cli = Cli::parse();

    // Run command
    let result = match cli.command {
        Commands::Deploy(args) => {
            let config = config::Config::load(&args.common)?;
            deploy::run(&config, args)
        }
        Commands::UploadVk(args) => {
            let config = config::Config::load(&args.common)?;
            upload_vk::run(&config, args)
        }
        Commands::Verify(args) => {
            let config = config::Config::load(&args.common)?;
            verify::run(&config, args)
        }
        Commands::Status(args) => {
            let config = config::Config::load(&args.common)?;
            status::run(&config, args)
        }
        Commands::Receipt(cmd) => {
            let common = cmd.common();
            let config = config::Config::load(common)?;
            receipt::run(&config, cmd)
        }
        Commands::Close(args) => {
            let config = config::Config::load(&args.common)?;
            close::run(&config, args)
        }
    };

    // Handle errors nicely
    if let Err(e) = result {
        eprintln!("{} {}", style("Error:").red().bold(), e);
        std::process::exit(1);
    }

    Ok(())
}
