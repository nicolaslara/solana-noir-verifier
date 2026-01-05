//! Configuration handling for noir-solana CLI
//!
//! Priority: CLI flags > environment variables > config file > defaults

use anyhow::{Context, Result};
use serde::Deserialize;
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair},
};
use std::{collections::HashMap, fs, path::PathBuf, str::FromStr, sync::Arc};

/// Resolved configuration for CLI commands
pub struct Config {
    pub rpc_url: String,
    pub keypair_path: Option<PathBuf>,
    pub program_id: Option<Pubkey>,
    pub quiet: bool,
    pub json_output: bool,
}

impl Config {
    /// Load configuration from file, environment, and CLI args
    pub fn load(common: &super::CommonArgs) -> Result<Self> {
        // Try to load config file
        let file_config = ConfigFile::load().ok();

        // Resolve network to RPC URL
        let rpc_url = resolve_network(&common.network, file_config.as_ref());

        // Resolve keypair path
        let keypair_path = common
            .keypair
            .as_ref()
            .map(PathBuf::from)
            .or_else(|| file_config.as_ref().and_then(|c| c.default_keypair()))
            .or_else(default_keypair_path);

        // Resolve program ID
        let program_id = common
            .program_id
            .as_ref()
            .and_then(|s| Pubkey::from_str(s).ok())
            .or_else(|| {
                file_config
                    .as_ref()
                    .and_then(|c| c.program_id_for_network(&common.network))
            });

        Ok(Self {
            rpc_url,
            keypair_path,
            program_id,
            quiet: common.quiet,
            json_output: common.output == super::OutputFormat::Json,
        })
    }

    /// Get RPC client with confirmed commitment (faster than finalized)
    pub fn rpc_client(&self) -> Arc<RpcClient> {
        Arc::new(RpcClient::new_with_commitment(
            &self.rpc_url,
            CommitmentConfig::confirmed(),
        ))
    }

    /// Load keypair from configured path
    pub fn load_keypair(&self) -> Result<Keypair> {
        let path = self
            .keypair_path
            .as_ref()
            .context("No keypair path configured. Use --keypair or set KEYPAIR_PATH")?;

        read_keypair_file(path)
            .map_err(|e| anyhow::anyhow!("Failed to read keypair from {:?}: {}", path, e))
    }

    /// Get program ID or error
    pub fn require_program_id(&self) -> Result<Pubkey> {
        self.program_id.context(
            "No program ID configured. Use --program-id, set VERIFIER_PROGRAM_ID, or configure in ~/.config/noir-solana/config.toml"
        )
    }
}

/// Configuration file structure
#[derive(Debug, Deserialize)]
struct ConfigFile {
    default: Option<DefaultConfig>,
    networks: Option<HashMap<String, NetworkConfig>>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DefaultConfig {
    network: Option<String>,
    keypair: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NetworkConfig {
    rpc_url: Option<String>,
    program_id: Option<String>,
}

impl ConfigFile {
    fn load() -> Result<Self> {
        let path = config_file_path()?;
        if !path.exists() {
            anyhow::bail!("Config file not found");
        }
        let content = fs::read_to_string(&path)?;
        let config: ConfigFile = toml::from_str(&content)?;
        Ok(config)
    }

    fn default_keypair(&self) -> Option<PathBuf> {
        self.default
            .as_ref()
            .and_then(|d| d.keypair.as_ref())
            .map(|s| expand_tilde(s))
    }

    fn program_id_for_network(&self, network: &str) -> Option<Pubkey> {
        self.networks
            .as_ref()
            .and_then(|n| n.get(network))
            .and_then(|c| c.program_id.as_ref())
            .and_then(|s| Pubkey::from_str(s).ok())
    }

    fn rpc_url_for_network(&self, network: &str) -> Option<String> {
        self.networks
            .as_ref()
            .and_then(|n| n.get(network))
            .and_then(|c| c.rpc_url.clone())
    }
}

/// Resolve network name to RPC URL
fn resolve_network(network: &str, config: Option<&ConfigFile>) -> String {
    // Check if it's already a URL
    if network.starts_with("http://") || network.starts_with("https://") {
        return network.to_string();
    }

    // Check config file first
    if let Some(url) = config.and_then(|c| c.rpc_url_for_network(network)) {
        return url;
    }

    // Built-in network presets
    match network {
        "mainnet" | "mainnet-beta" => "https://api.mainnet-beta.solana.com".to_string(),
        "devnet" => "https://api.devnet.solana.com".to_string(),
        "testnet" => "https://api.testnet.solana.com".to_string(),
        "localnet" | "localhost" => "http://127.0.0.1:8899".to_string(),
        _ => {
            // Assume it's a URL
            network.to_string()
        }
    }
}

/// Get config file path
fn config_file_path() -> Result<PathBuf> {
    let config_dir = dirs::config_dir().context("Could not find config directory")?;
    Ok(config_dir.join("noir-solana").join("config.toml"))
}

/// Get default keypair path
fn default_keypair_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".config").join("solana").join("id.json"))
}

/// Expand ~ to home directory
fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path[2..]);
        }
    }
    PathBuf::from(path)
}
