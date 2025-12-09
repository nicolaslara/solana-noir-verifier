//! UltraHonk Verifier for Solana
//!
//! This program verifies UltraHonk (Noir/Barretenberg) proofs on Solana.
//!
//! ## Account-Based Proof Storage
//!
//! Since UltraHonk proofs are ~16KB (too large for instruction data),
//! we store the proof in an account and verify from there.
//!
//! ## Instructions
//!
//! 0. InitProofBuffer - Create account to store proof
//! 1. UploadChunk - Upload proof data in chunks
//! 2. Verify - Verify the proof from the buffer

use plonk_solana_core::{verify, Fr};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    log::sol_log_compute_units,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

extern crate alloc;
use alloc::vec::Vec;

// Entry point
entrypoint!(process_instruction);

// ============================================================================
// Constants
// ============================================================================

/// ZK proof size for bb 0.87 (fixed size)
pub const PROOF_SIZE: usize = 16224;

/// VK size for bb 0.87
pub const VK_SIZE_NEW: usize = 1760;

/// Maximum chunk size for uploads (to fit in tx)
pub const MAX_CHUNK_SIZE: usize = 900;

/// Header size in proof buffer: status (1) + proof_len (2) + pi_count (2)
pub const BUFFER_HEADER_SIZE: usize = 5;

// ============================================================================
// Embedded VK - loaded from file at compile time
// ============================================================================

/// VK bytes from simple_square circuit
/// Generated with: bb write_vk --scheme ultra_honk --oracle_hash keccak
const VK_BYTES: &[u8] = include_bytes!("../../../test-circuits/simple_square/target/keccak/vk");

// ============================================================================
// Instructions
// ============================================================================

#[repr(u8)]
pub enum Instruction {
    /// Initialize proof buffer account
    /// Accounts: [proof_buffer (writable), payer (signer)]
    InitBuffer = 0,

    /// Upload chunk of proof data
    /// Accounts: [proof_buffer (writable), authority (signer)]
    /// Data: [instruction(1), offset(2), chunk_data(...)]
    UploadChunk = 1,

    /// Verify the proof from buffer
    /// Accounts: [proof_buffer (readonly)]
    /// Data: [instruction(1)]
    Verify = 2,

    /// Set public inputs
    /// Accounts: [proof_buffer (writable)]
    /// Data: [instruction(1), public_inputs...]
    SetPublicInputs = 3,
}

// ============================================================================
// Proof Buffer Layout
// ============================================================================

/// Proof buffer account layout:
/// [0]:       status (0=empty, 1=uploading, 2=ready)
/// [1..3]:    proof_length (u16 LE)
/// [3..5]:    public_inputs_count (u16 LE)
/// [5..5+PI]: public inputs (32 bytes each)
/// [5+PI..]:  proof data

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum BufferStatus {
    Empty = 0,
    Uploading = 1,
    Ready = 2,
}

// ============================================================================
// Instruction Processing
// ============================================================================

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    match instruction_data[0] {
        0 => process_init_buffer(program_id, accounts, &instruction_data[1..]),
        1 => process_upload_chunk(program_id, accounts, &instruction_data[1..]),
        2 => process_verify(program_id, accounts),
        3 => process_set_public_inputs(program_id, accounts, &instruction_data[1..]),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Initialize a proof buffer account
/// Data format: [num_public_inputs (u16 LE)]
fn process_init_buffer(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    msg!("UltraHonk: InitBuffer");

    let account_iter = &mut accounts.iter();
    let buffer_account = next_account_info(account_iter)?;

    if !buffer_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    // Parse number of public inputs
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let num_pi = u16::from_le_bytes([data[0], data[1]]);

    // Initialize buffer header
    let mut buffer_data = buffer_account.try_borrow_mut_data()?;

    // Verify account is large enough
    let required_size = BUFFER_HEADER_SIZE + (num_pi as usize * 32) + PROOF_SIZE;
    if buffer_data.len() < required_size {
        msg!(
            "Buffer too small: {} < {}",
            buffer_data.len(),
            required_size
        );
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Set header
    buffer_data[0] = BufferStatus::Empty as u8;
    buffer_data[1..3].copy_from_slice(&0u16.to_le_bytes()); // proof_len = 0
    buffer_data[3..5].copy_from_slice(&num_pi.to_le_bytes());

    msg!("Buffer initialized for {} public inputs", num_pi);
    Ok(())
}

/// Upload a chunk of proof data
/// Data format: [offset (u16 LE), chunk_data...]
fn process_upload_chunk(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let buffer_account = next_account_info(account_iter)?;

    if !buffer_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let offset = u16::from_le_bytes([data[0], data[1]]) as usize;
    let chunk = &data[2..];

    msg!(
        "UltraHonk: UploadChunk offset={} len={}",
        offset,
        chunk.len()
    );

    let mut buffer_data = buffer_account.try_borrow_mut_data()?;

    // Read header
    let num_pi = u16::from_le_bytes([buffer_data[3], buffer_data[4]]) as usize;
    let data_start = BUFFER_HEADER_SIZE + (num_pi * 32);

    // Write chunk
    let write_start = data_start + offset;
    let write_end = write_start + chunk.len();

    if write_end > buffer_data.len() {
        msg!(
            "Chunk exceeds buffer: {} > {}",
            write_end,
            buffer_data.len()
        );
        return Err(ProgramError::AccountDataTooSmall);
    }

    buffer_data[write_start..write_end].copy_from_slice(chunk);

    // Update status and length
    buffer_data[0] = BufferStatus::Uploading as u8;
    let new_len = (offset + chunk.len()) as u16;
    let current_len = u16::from_le_bytes([buffer_data[1], buffer_data[2]]);
    if new_len > current_len {
        buffer_data[1..3].copy_from_slice(&new_len.to_le_bytes());
    }

    // Mark ready if full proof uploaded
    let proof_len = u16::from_le_bytes([buffer_data[1], buffer_data[2]]) as usize;
    if proof_len >= PROOF_SIZE {
        buffer_data[0] = BufferStatus::Ready as u8;
        msg!("Proof upload complete: {} bytes", proof_len);
    }

    Ok(())
}

/// Verify the proof from buffer
fn process_verify(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("UltraHonk: Verify");
    sol_log_compute_units();

    let account_iter = &mut accounts.iter();
    let buffer_account = next_account_info(account_iter)?;

    let buffer_data = buffer_account.try_borrow_data()?;

    // Check status
    if buffer_data[0] != BufferStatus::Ready as u8 {
        msg!("Buffer not ready for verification");
        return Err(ProgramError::InvalidAccountData);
    }

    // Read header
    let proof_len = u16::from_le_bytes([buffer_data[1], buffer_data[2]]) as usize;
    let num_pi = u16::from_le_bytes([buffer_data[3], buffer_data[4]]) as usize;

    msg!("Proof: {} bytes, Public inputs: {}", proof_len, num_pi);

    // Extract public inputs
    let pi_start = BUFFER_HEADER_SIZE;
    let pi_end = pi_start + (num_pi * 32);
    let mut public_inputs: Vec<Fr> = Vec::with_capacity(num_pi);

    for i in 0..num_pi {
        let start = pi_start + (i * 32);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&buffer_data[start..start + 32]);
        public_inputs.push(arr);
    }

    // Extract proof
    let proof_start = pi_end;
    let proof_end = proof_start + proof_len;
    let proof_bytes = &buffer_data[proof_start..proof_end];

    msg!("CU before verification:");
    sol_log_compute_units();

    // Parse VK
    msg!("Parsing VK...");
    let vk = match plonk_solana_core::key::VerificationKey::from_bytes(VK_BYTES) {
        Ok(v) => v,
        Err(e) => {
            msg!("VK parse error: {:?}", e);
            return Err(ProgramError::InvalidAccountData);
        }
    };
    msg!("CU after VK parse:");
    sol_log_compute_units();

    // Parse Proof
    msg!("Parsing proof...");
    let log_n = vk.log2_circuit_size as usize;
    let is_zk = true;
    let proof = match plonk_solana_core::proof::Proof::from_bytes(proof_bytes, log_n, is_zk) {
        Ok(p) => p,
        Err(e) => {
            msg!("Proof parse error: {:?}", e);
            return Err(ProgramError::InvalidAccountData);
        }
    };
    msg!("CU after proof parse:");
    sol_log_compute_units();

    // Step 1: Generate challenges
    msg!("Step 1: Generate challenges...");
    let challenges = match plonk_solana_core::verify_step1_challenges(&vk, &proof, &public_inputs) {
        Ok(c) => c,
        Err(e) => {
            msg!("Step 1 failed: {:?}", e);
            return Err(ProgramError::InvalidAccountData);
        }
    };
    msg!("CU after step 1:");
    sol_log_compute_units();

    // Step 2: Verify sumcheck
    msg!("Step 2: Verify sumcheck...");
    let sumcheck_ok = match plonk_solana_core::verify_step2_sumcheck(&vk, &proof, &challenges) {
        Ok(ok) => ok,
        Err(e) => {
            msg!("Step 2 failed: {:?}", e);
            return Err(ProgramError::InvalidAccountData);
        }
    };
    if !sumcheck_ok {
        msg!("Sumcheck verification failed");
        return Err(ProgramError::InvalidAccountData);
    }
    msg!("CU after step 2:");
    sol_log_compute_units();

    // Step 3: Compute pairing points
    msg!("Step 3: Compute pairing points...");
    let (p0, p1) = match plonk_solana_core::verify_step3_pairing_points(&vk, &proof, &challenges) {
        Ok(pts) => pts,
        Err(e) => {
            msg!("Step 3 failed: {:?}", e);
            return Err(ProgramError::InvalidAccountData);
        }
    };
    msg!("CU after step 3:");
    sol_log_compute_units();

    // Step 4: Final pairing check
    msg!("Step 4: Final pairing check...");
    let pairing_ok = match plonk_solana_core::verify_step4_pairing_check(&p0, &p1) {
        Ok(ok) => ok,
        Err(e) => {
            msg!("Step 4 failed: {:?}", e);
            return Err(ProgramError::InvalidAccountData);
        }
    };
    msg!("CU after step 4:");
    sol_log_compute_units();

    if pairing_ok {
        msg!("✅ UltraHonk proof verified successfully!");
        Ok(())
    } else {
        msg!("❌ Verification failed: pairing check returned false");
        Err(ProgramError::InvalidAccountData)
    }
}

/// Set public inputs in the buffer
/// Data format: [public_inputs...]
fn process_set_public_inputs(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    msg!("UltraHonk: SetPublicInputs");

    let account_iter = &mut accounts.iter();
    let buffer_account = next_account_info(account_iter)?;

    if !buffer_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut buffer_data = buffer_account.try_borrow_mut_data()?;

    // Read expected PI count from header
    let num_pi = u16::from_le_bytes([buffer_data[3], buffer_data[4]]) as usize;
    let expected_size = num_pi * 32;

    if data.len() != expected_size {
        msg!(
            "PI size mismatch: expected {} bytes, got {}",
            expected_size,
            data.len()
        );
        return Err(ProgramError::InvalidInstructionData);
    }

    // Write PI after header
    let pi_start = BUFFER_HEADER_SIZE;
    buffer_data[pi_start..pi_start + expected_size].copy_from_slice(data);

    msg!("Set {} public inputs ({} bytes)", num_pi, expected_size);
    Ok(())
}

// ============================================================================
// Program ID
// ============================================================================

solana_program::declare_id!("GrBZJ7YpCKijTHwkuWfRF1Jti3xngdEV1geAcgk8aoNk");

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vk_loaded() {
        assert_eq!(
            VK_BYTES.len(),
            VK_SIZE_NEW,
            "VK should be {} bytes",
            VK_SIZE_NEW
        );
    }

    #[test]
    fn test_buffer_layout() {
        // For 1 public input: header(5) + pi(32) + proof(16224) = 16261
        let expected = BUFFER_HEADER_SIZE + 32 + PROOF_SIZE;
        assert_eq!(expected, 16261);
    }
}
