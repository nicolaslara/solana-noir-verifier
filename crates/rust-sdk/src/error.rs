//! Error types for the Solana Noir Verifier SDK

use solana_client::client_error::ClientError;
use thiserror::Error;

/// Errors that can occur during verification
#[derive(Error, Debug)]
pub enum VerifierError {
    #[error("Invalid proof size: expected {expected}, got {actual}")]
    InvalidProofSize { expected: usize, actual: usize },

    #[error("Invalid VK size: expected {expected}, got {actual}")]
    InvalidVkSize { expected: usize, actual: usize },

    #[error("Public inputs too large: {size} bytes (max ~{max_size})")]
    PublicInputsTooLarge { size: usize, max_size: usize },

    #[error("State account not found")]
    StateAccountNotFound,

    #[error("Invalid state account data")]
    InvalidStateData,

    #[error("Receipt not found")]
    ReceiptNotFound,

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Transaction confirmation timeout")]
    ConfirmationTimeout,

    #[error("RPC error: {0}")]
    RpcError(#[from] ClientError),

    #[error("Verification failed")]
    VerificationFailed,
}

pub type Result<T> = std::result::Result<T, VerifierError>;
