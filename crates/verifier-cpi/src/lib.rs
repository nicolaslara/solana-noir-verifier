//! CPI utilities for verifying Noir proof receipts on Solana
//!
//! This crate provides helper functions for Solana programs that want to
//! check if a Noir proof was verified by the UltraHonk verifier.
//!
//! # Example
//!
//! ```ignore
//! use solana_noir_verifier_cpi::is_verified;
//! use solana_program::pubkey::Pubkey;
//!
//! // Your circuit's VK account (deployed once)
//! const MY_VK: Pubkey = solana_program::pubkey!("...");
//! const VERIFIER: Pubkey = solana_program::pubkey!("...");
//!
//! fn process(accounts: &[AccountInfo], public_inputs: &[u8]) -> ProgramResult {
//!     let receipt = &accounts[0];
//!     
//!     // Check if this proof was verified
//!     if !is_verified(receipt, &MY_VK, public_inputs, &VERIFIER) {
//!         return Err(ProgramError::Custom(1)); // NotVerified
//!     }
//!     
//!     // Proof is valid! Continue with business logic...
//!     Ok(())
//! }
//! ```

#![no_std]

use solana_program::{account_info::AccountInfo, keccak, pubkey::Pubkey};

/// Size of the receipt account data (16 bytes)
pub const RECEIPT_SIZE: usize = 16;

// Internal: PDA seed prefix
const RECEIPT_SEED: &[u8] = b"receipt";

/// Check if a proof was verified
///
/// This is the main function integrators use. It validates that:
/// 1. The receipt account is at the correct PDA address
/// 2. The receipt is owned by the verifier program
/// 3. The receipt has valid data
///
/// # Arguments
/// * `receipt` - The receipt account (user provides this)
/// * `vk_account` - Your circuit's VK account pubkey
/// * `public_inputs` - The public inputs that were proven (raw bytes)
/// * `verifier_program` - The verifier program ID
///
/// # Returns
/// `true` if the proof was verified, `false` otherwise
pub fn is_verified(
    receipt: &AccountInfo,
    vk_account: &Pubkey,
    public_inputs: &[u8],
    verifier_program: &Pubkey,
) -> bool {
    // Hash public inputs
    let pi_hash = keccak::hash(public_inputs).to_bytes();

    // Derive expected PDA
    let (expected_pda, _) = Pubkey::find_program_address(
        &[RECEIPT_SEED, vk_account.as_ref(), &pi_hash],
        verifier_program,
    );

    // Validate receipt
    receipt.key == &expected_pda
        && receipt.owner == verifier_program
        && receipt.data_len() >= RECEIPT_SIZE
}

/// Read the verification slot from a receipt
///
/// Call this after `is_verified` returns true to get when the proof was verified.
///
/// # Returns
/// The slot number when the proof was verified, or None if invalid
pub fn get_verified_slot(receipt: &AccountInfo) -> Option<u64> {
    let data = receipt.try_borrow_data().ok()?;
    if data.len() < 8 {
        return None;
    }
    Some(u64::from_le_bytes(data[0..8].try_into().ok()?))
}

/// Read the verification timestamp from a receipt
///
/// Call this after `is_verified` returns true to get when the proof was verified.
///
/// # Returns
/// The Unix timestamp when the proof was verified, or None if invalid
pub fn get_verified_timestamp(receipt: &AccountInfo) -> Option<i64> {
    let data = receipt.try_borrow_data().ok()?;
    if data.len() < 16 {
        return None;
    }
    Some(i64::from_le_bytes(data[8..16].try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pda_derivation_is_deterministic() {
        let vk = Pubkey::new_unique();
        let public_inputs = [1u8, 2, 3, 4];
        let program = Pubkey::new_unique();

        let pi_hash = keccak::hash(&public_inputs).to_bytes();
        let (pda1, bump1) =
            Pubkey::find_program_address(&[RECEIPT_SEED, vk.as_ref(), &pi_hash], &program);
        let (pda2, bump2) =
            Pubkey::find_program_address(&[RECEIPT_SEED, vk.as_ref(), &pi_hash], &program);

        assert_eq!(pda1, pda2);
        assert_eq!(bump1, bump2);
    }
}
