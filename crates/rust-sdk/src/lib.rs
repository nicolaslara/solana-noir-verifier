//! Rust SDK for verifying Noir UltraHonk proofs on Solana
//!
//! This crate provides a client for submitting and verifying Noir proofs
//! using the UltraHonk verifier program on Solana.
//!
//! # Example
//!
//! ```ignore
//! use solana_noir_verifier_sdk::{SolanaNoirVerifier, VerifierConfig};
//! use solana_sdk::signature::Keypair;
//! use solana_client::rpc_client::RpcClient;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let client = Arc::new(RpcClient::new("http://localhost:8899"));
//!     let payer = Keypair::new();
//!     
//!     let verifier = SolanaNoirVerifier::new(
//!         client,
//!         VerifierConfig::new(program_id),
//!     );
//!     
//!     // Upload VK once per circuit
//!     let vk_result = verifier.upload_vk(&payer, &vk_bytes)?;
//!     
//!     // Verify proofs using the VK account
//!     let result = verifier.verify(
//!         &payer,
//!         &proof_bytes,
//!         &public_inputs,
//!         &vk_result.vk_account,
//!     )?;
//!     
//!     println!("Verified: {}", result.verified);
//! }
//! ```

mod client;
mod error;
mod instructions;
mod types;

pub use client::SolanaNoirVerifier;
pub use error::VerifierError;
pub use instructions::*;
pub use types::*;
