//! Sample Integrator Program
//!
//! Demonstrates how to integrate with solana-noir-verifier to require
//! ZK proof verification before executing business logic.
//!
//! ## Use Cases
//! - Private voting: Verify a vote proof before recording
//! - Identity verification: Verify a credential proof before granting access
//! - Private transfers: Verify a balance proof before executing
//!
//! ## How It Works
//! 1. User verifies their proof with solana-noir-verifier
//! 2. User calls CreateReceipt to create a persistent receipt
//! 3. User calls your program, passing the receipt account
//! 4. Your program validates the receipt and executes business logic

use solana_noir_verifier_cpi::{get_verified_slot, is_verified};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    declare_id, entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

// Your program ID (replace with actual deployed ID)
declare_id!("11111111111111111111111111111111");

// ============================================================================
// CONFIGURATION: Set these for your circuit
// ============================================================================

/// The verifier program ID
pub const VERIFIER_PROGRAM: Pubkey =
    solana_program::pubkey!("7sfMWfVs6P1ACjouyvRwWHjiAj6AsFkYARP2v9RBSSoe");

/// Your circuit's VK account (deployed once, reused for all proofs)
/// Replace with your actual VK account after deploying your circuit
pub const MY_CIRCUIT_VK: Pubkey = solana_program::pubkey!("11111111111111111111111111111111");

// ============================================================================
// PROGRAM ENTRYPOINT
// ============================================================================

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // First byte is instruction discriminator, rest is public inputs
    let (&instruction, public_inputs) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match instruction {
        0 => process_protected_action(accounts, public_inputs),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ============================================================================
// INSTRUCTION: Protected Action (requires verified proof)
// ============================================================================

/// Process an action that requires a verified ZK proof
///
/// Accounts:
/// 0. `[]` Receipt account (PDA from verifier, user provides)
/// 1. `[signer]` User
fn process_protected_action(accounts: &[AccountInfo], public_inputs: &[u8]) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let receipt = next_account_info(account_iter)?;
    let user = next_account_info(account_iter)?;

    // User must sign
    if !user.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // =========================================================================
    // STEP 1: Validate the proof receipt
    // =========================================================================

    msg!("Checking proof receipt...");

    if !is_verified(receipt, &MY_CIRCUIT_VK, public_inputs, &VERIFIER_PROGRAM) {
        msg!("❌ Proof not verified!");
        msg!("   User must verify proof and create receipt first");
        return Err(ProgramError::Custom(1)); // NotVerified
    }

    // Optional: Check when it was verified
    if let Some(slot) = get_verified_slot(receipt) {
        msg!("✅ Proof verified at slot {}", slot);
    }

    // =========================================================================
    // STEP 2: Execute business logic (proof is valid!)
    // =========================================================================

    msg!("Executing protected action...");

    // Your business logic here. Examples:
    // - Record a vote
    // - Grant access to a resource
    // - Execute a transfer
    // - Update game state

    msg!("🎉 Action completed!");

    Ok(())
}
