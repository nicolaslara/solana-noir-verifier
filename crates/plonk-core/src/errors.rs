//! Error types for the UltraHonk verifier

extern crate alloc;
use alloc::string::String;
use thiserror::Error;

/// Top-level verification error
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("Key error: {0}")]
    Key(#[from] KeyError),

    #[error("Proof error: {0}")]
    Proof(#[from] ProofError),

    #[error("BN254 error: {0}")]
    Bn254(#[from] Bn254Error),

    #[error("Public input error: {0}")]
    PublicInput(String),

    #[error("Transcript error: {0}")]
    Transcript(String),

    #[error("Verification failed")]
    VerificationFailed,
}

/// Verification key parsing errors
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("Invalid VK size: expected {expected}, got {actual}")]
    InvalidSize { expected: usize, actual: usize },

    #[error("Invalid circuit size")]
    InvalidCircuitSize,

    #[error("Invalid domain size")]
    InvalidDomainSize,

    #[error("Invalid field size (expected 32 bytes)")]
    InvalidFieldSize,

    #[error("Field value overflow (should fit in u32)")]
    FieldOverflow,

    #[error("Point not on curve")]
    PointNotOnCurve,
}

/// Proof parsing errors
#[derive(Debug, Error)]
pub enum ProofError {
    #[error("Invalid proof size: expected {expected}, got {actual}")]
    InvalidSize { expected: usize, actual: usize },

    #[error("Invalid G1 point")]
    InvalidG1Point,

    #[error("Invalid scalar")]
    InvalidScalar,
}

/// BN254 operation errors
#[derive(Debug, Error)]
pub enum Bn254Error {
    #[error("Syscall error: {0}")]
    SyscallError(String),

    #[error("Invalid G1 point")]
    InvalidG1,

    #[error("Invalid G2 point")]
    InvalidG2,

    #[error("Pairing check failed")]
    PairingFailed,
}
