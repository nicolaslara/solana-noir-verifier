//! Groth16 Verifier for Solana
//!
//! This program verifies Groth16 proofs on Solana using the BN254 curve
//! and the groth16-solana library which leverages Solana's alt_bn128 syscalls.
//!
//! Verification costs: ~200,000 compute units
//! Proof size: 256 bytes
//!
//! ## How it works
//!
//! The verification key is loaded from `vk_solana.bin` at compile time.
//! After running `go run .` in the gnark directory, rebuild this program
//! to pick up the new VK automatically.

use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use solana_program::{
    account_info::AccountInfo, declare_id, entrypoint, entrypoint::ProgramResult,
    log::sol_log_compute_units, msg, program_error::ProgramError, pubkey::Pubkey,
};

// Program ID
declare_id!("Groth16111111111111111111111111111111111111");

// Declare entrypoint
entrypoint!(process_instruction);

/// Number of public inputs for our circuit (y = x * x)
const NR_PUBLIC_INPUTS: usize = 1;

// ============================================================================
// Verification Key - loaded from binary file at compile time
// Binary layout: Alpha(64) + Beta(128) + Gamma(128) + Delta(128) + IC[0](64) + IC[1](64)
// ============================================================================

/// Raw VK bytes from gnark output
const VK_BYTES: &[u8] = include_bytes!("../../gnark/output/vk_solana.bin");

/// Parse VK bytes into fixed-size arrays at compile time
const fn parse_vk() -> (
    [u8; 64],  // alpha_g1
    [u8; 128], // beta_g2
    [u8; 128], // gamma_g2
    [u8; 128], // delta_g2
    [u8; 64],  // ic_0
    [u8; 64],  // ic_1
) {
    // Offsets in the binary file
    const ALPHA_START: usize = 0;
    const BETA_START: usize = 64;
    const GAMMA_START: usize = 192;
    const DELTA_START: usize = 320;
    const IC0_START: usize = 448;
    const IC1_START: usize = 512;

    let mut alpha = [0u8; 64];
    let mut beta = [0u8; 128];
    let mut gamma = [0u8; 128];
    let mut delta = [0u8; 128];
    let mut ic_0 = [0u8; 64];
    let mut ic_1 = [0u8; 64];

    // Copy bytes (const fn can't use copy_from_slice)
    let mut i = 0;
    while i < 64 {
        alpha[i] = VK_BYTES[ALPHA_START + i];
        ic_0[i] = VK_BYTES[IC0_START + i];
        ic_1[i] = VK_BYTES[IC1_START + i];
        i += 1;
    }
    i = 0;
    while i < 128 {
        beta[i] = VK_BYTES[BETA_START + i];
        gamma[i] = VK_BYTES[GAMMA_START + i];
        delta[i] = VK_BYTES[DELTA_START + i];
        i += 1;
    }

    (alpha, beta, gamma, delta, ic_0, ic_1)
}

/// Parsed VK components
const VK_PARSED: (
    [u8; 64],
    [u8; 128],
    [u8; 128],
    [u8; 128],
    [u8; 64],
    [u8; 64],
) = parse_vk();

/// IC points (vk_ic) - must be static for lifetime
static VK_IC: [[u8; 64]; 2] = [VK_PARSED.4, VK_PARSED.5];

/// The verification key struct for groth16-solana
pub static VERIFYING_KEY: Groth16Verifyingkey<'static> = Groth16Verifyingkey {
    nr_pubinputs: NR_PUBLIC_INPUTS,
    vk_alpha_g1: VK_PARSED.0,
    vk_beta_g2: VK_PARSED.1,
    vk_gamme_g2: VK_PARSED.2, // Note: typo in groth16-solana
    vk_delta_g2: VK_PARSED.3,
    vk_ic: &VK_IC,
};

// ============================================================================
// Instruction Processing
// ============================================================================

/// Instruction data layout:
/// - [0..256]: Proof (π_A negated || π_B || π_C)
/// - [256..288]: Public input (y = 9, as 32-byte big-endian field element)
pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Groth16 Verifier: Processing instruction");
    sol_log_compute_units();

    // Parse proof and public inputs from instruction data
    if instruction_data.len() < 256 + 32 {
        msg!("Error: Instruction data too short");
        return Err(ProgramError::InvalidInstructionData);
    }

    // gnark outputs proof with Ar already negated
    let proof_a: &[u8; 64] = instruction_data[0..64]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let proof_b: &[u8; 128] = instruction_data[64..192]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let proof_c: &[u8; 64] = instruction_data[192..256]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    // Extract public input as fixed-size array
    let public_input: &[u8; 32] = instruction_data[256..288]
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    // groth16-solana expects public inputs as &[[u8; 32]; N]
    let public_inputs: &[[u8; 32]; NR_PUBLIC_INPUTS] =
        unsafe { &*(public_input as *const [u8; 32] as *const [[u8; 32]; NR_PUBLIC_INPUTS]) };

    msg!("Proof size: 256 bytes");
    msg!("Public inputs: {}", NR_PUBLIC_INPUTS);
    msg!("CU before verification:");
    sol_log_compute_units();

    // Create verifier
    let mut verifier = Groth16Verifier::<NR_PUBLIC_INPUTS>::new(
        proof_a,
        proof_b,
        proof_c,
        public_inputs,
        &VERIFYING_KEY,
    )
    .map_err(|e| {
        msg!("Error creating verifier: {:?}", e);
        ProgramError::InvalidInstructionData
    })?;

    // Verify the proof
    verifier.verify().map_err(|e| {
        msg!("Verification failed: {:?}", e);
        ProgramError::InvalidInstructionData
    })?;

    msg!("CU after verification:");
    sol_log_compute_units();
    msg!("Groth16 proof verified successfully!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vk_structure() {
        assert_eq!(VERIFYING_KEY.nr_pubinputs, 1);
        assert_eq!(VERIFYING_KEY.vk_alpha_g1.len(), 64);
        assert_eq!(VERIFYING_KEY.vk_beta_g2.len(), 128);
        assert_eq!(VERIFYING_KEY.vk_gamme_g2.len(), 128);
        assert_eq!(VERIFYING_KEY.vk_delta_g2.len(), 128);
        assert_eq!(VERIFYING_KEY.vk_ic.len(), 2);
    }

    #[test]
    fn test_vk_loaded_from_file() {
        // Verify the VK was loaded correctly (file should be 576 bytes)
        assert_eq!(VK_BYTES.len(), 576);
    }
}
