//! UltraHonk Verifier for Solana
//!
//! This program verifies UltraHonk (Noir/Barretenberg) proofs on Solana.
//!
//! ## Account-Based Proof Storage
//!
//! Since UltraHonk proofs are ~16KB (too large for instruction data),
//! we store the proof in an account and verify from there.
//!
//! ## Single-TX Instructions (exceeds CU limit)
//!
//! 0. InitProofBuffer - Create account to store proof
//! 1. UploadChunk - Upload proof data in chunks
//! 2. Verify - Verify the proof from the buffer (FAILS: >1.4M CUs)
//!
//! ## Multi-TX Phased Verification
//!
//! 10. InitPhasedVerification - Create state account
//! 11. GenerateChallenges - Phase 1: Fiat-Shamir transcript
//! 12. VerifySumcheck - Phase 2: Sumcheck protocol
//! 13. ComputeMSM - Phase 3: Shplemini P0/P1 computation
//! 14. FinalPairingCheck - Phase 4: Final pairing verification

pub mod phased;

use plonk_solana_core::{
    // Split delta computation
    compute_delta_part1,
    compute_delta_part2,
    // Incremental challenge generation
    generate_challenges_phase1a,
    generate_challenges_phase1b,
    generate_challenges_phase1c,
    generate_challenges_phase1d,
    // Incremental shplemini (MSM) verification
    shplemini_phase3a,
    shplemini_phase3b1,
    shplemini_phase3b2,
    shplemini_phase3c,
    // Incremental sumcheck verification
    sumcheck_rounds_init,
    verify_step1_challenges,
    verify_step2_sumcheck,
    verify_step3_pairing_points,
    verify_step4_pairing_check,
    verify_sumcheck_relations,
    verify_sumcheck_rounds_partial,
    Challenges,
    DeltaPartialResult,
    Fr,
    ShpleminiPhase3aResult,
    ShpleminiPhase3b1Result,
    ShpleminiPhase3bResult,
    SumcheckRoundsState,
};
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
    // === Single-TX verification (exceeds CU limit) ===
    /// Initialize proof buffer account
    /// Accounts: [proof_buffer (writable), payer (signer)]
    InitBuffer = 0,

    /// Upload chunk of proof data
    /// Accounts: [proof_buffer (writable), authority (signer)]
    /// Data: [instruction(1), offset(2), chunk_data(...)]
    UploadChunk = 1,

    /// Verify the proof from buffer (FAILS: >1.4M CUs)
    /// Accounts: [proof_buffer (readonly)]
    /// Data: [instruction(1)]
    Verify = 2,

    /// Set public inputs
    /// Accounts: [proof_buffer (writable)]
    /// Data: [instruction(1), public_inputs...]
    SetPublicInputs = 3,

    // === Multi-TX phased verification (original - exceeds CU) ===
    /// Phase 1: Initialize state + generate challenges (FAILS: >1.4M CUs)
    /// Accounts: [state (writable), proof_data (readonly)]
    PhasedGenerateChallenges = 10,

    /// Phase 2: Verify sumcheck
    /// Accounts: [state (writable), proof_data (readonly)]
    PhasedVerifySumcheck = 11,

    /// Phase 3: Compute P0/P1 (Shplemini MSM)
    /// Accounts: [state (writable), proof_data (readonly)]
    PhasedComputeMSM = 12,

    /// Phase 4: Final pairing check
    /// Accounts: [state (writable)]
    PhasedFinalCheck = 13,

    // === Sub-phased challenge generation (splits Phase 1) ===
    /// Phase 1a: eta, beta/gamma challenges
    /// Accounts: [state (writable), proof_data (readonly)]
    Phase1aEtaBetaGamma = 20,

    /// Phase 1b: alpha + gate challenges
    /// Accounts: [state (writable), proof_data (readonly)]
    Phase1bAlphasGates = 21,

    /// Phase 1c: sumcheck rounds 0-13
    /// Accounts: [state (writable), proof_data (readonly)]  
    Phase1cSumcheckHalf = 22,

    /// Phase 1d: sumcheck rounds 14-27 + final challenges
    /// Accounts: [state (writable), proof_data (readonly)]
    Phase1dSumcheckRest = 23,

    /// Phase 1e1: public_input_delta part 1 (first 9 items)
    /// Accounts: [state (writable), proof_data (readonly)]
    Phase1e1DeltaPart1 = 24,

    /// Phase 1e2: public_input_delta part 2 (remaining 8 items + division)
    /// Accounts: [state (writable), proof_data (readonly)]
    Phase1e2DeltaPart2 = 25,

    // === Unified Phase 1 (after Montgomery optimization) ===
    /// Phase 1 Full: All challenge generation in one TX (~300K CUs)
    /// Accounts: [state (writable), proof_data (readonly)]
    Phase1Full = 30,

    // === Sub-phased sumcheck verification (splits Phase 2) ===
    /// Phase 2 rounds: Verify a batch of sumcheck rounds
    /// Accounts: [state (writable), proof_data (readonly)]
    /// Data: [instruction(1), start_round(1), end_round(1)]
    Phase2Rounds = 40,

    /// Phase 2d: Relations + final check
    /// Accounts: [state (writable), proof_data (readonly)]
    Phase2dRelations = 43,

    // === Sub-phased MSM computation (splits Phase 3) ===
    /// Phase 3a: Weights + scalar accumulation (~870K CUs)
    /// Accounts: [state (writable), proof_data (readonly)]
    Phase3aWeights = 50,

    /// Phase 3b1: Folding rounds only (~870K CUs)
    /// Accounts: [state (writable), proof_data (readonly)]
    Phase3b1Folding = 51,

    /// Phase 3b2: Gemini + libra (~500K CUs)
    /// Accounts: [state (writable), proof_data (readonly)]
    Phase3b2Gemini = 52,

    /// Phase 3c: MSM computation (~500K CUs)
    /// Accounts: [state (writable), proof_data (readonly)]
    Phase3cMsm = 53,
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
        // Single-TX verification
        0 => process_init_buffer(program_id, accounts, &instruction_data[1..]),
        1 => process_upload_chunk(program_id, accounts, &instruction_data[1..]),
        2 => process_verify(program_id, accounts),
        3 => process_set_public_inputs(program_id, accounts, &instruction_data[1..]),

        // Multi-TX phased verification (original - may exceed CU)
        10 => process_phased_generate_challenges(program_id, accounts),
        11 => process_phased_verify_sumcheck(program_id, accounts),
        12 => process_phased_compute_msm(program_id, accounts),
        13 => process_phased_final_check(program_id, accounts),

        // Sub-phased challenge generation
        20 => process_phase1a_eta_beta_gamma(program_id, accounts),
        21 => process_phase1b_alphas_gates(program_id, accounts),
        22 => process_phase1c_sumcheck_half(program_id, accounts),
        23 => process_phase1d_sumcheck_rest(program_id, accounts),
        24 => process_phase1e1_delta_part1(program_id, accounts),
        25 => process_phase1e2_delta_part2(program_id, accounts),

        // Unified Phase 1 (after Montgomery optimization - ~300K CUs)
        30 => process_phase1_full(program_id, accounts),

        // Sub-phased sumcheck verification
        40 => process_phase2_rounds(program_id, accounts, instruction_data),
        43 => process_phase2d_relations(program_id, accounts),

        // Sub-phased MSM computation
        50 => process_phase3a_weights(program_id, accounts),
        51 => process_phase3b1_folding(program_id, accounts),
        52 => process_phase3b2_gemini(program_id, accounts),
        53 => process_phase3c_msm(program_id, accounts),

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
// Phased Verification Instructions
// ============================================================================

/// Phase 1: Generate challenges from transcript
/// This is the most expensive step (~1.4M CUs)
fn process_phased_generate_challenges(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    msg!("Phased: Generate Challenges");
    sol_log_compute_units();

    let account_iter = &mut accounts.iter();
    let state_account = next_account_info(account_iter)?;
    let proof_account = next_account_info(account_iter)?;

    // Verify state account is writable
    if !state_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state_data = state_account.try_borrow_mut_data()?;
    let state = phased::VerificationState::from_bytes_mut(&mut state_data)
        .ok_or(ProgramError::InvalidAccountData)?;

    // Check we're in the right phase (Uninitialized or can restart)
    let current_phase = state.get_phase();
    if current_phase != phased::Phase::Uninitialized && current_phase != phased::Phase::Failed {
        msg!("Invalid phase: {:?}", current_phase);
        return Err(ProgramError::InvalidAccountData);
    }

    // Read proof data from proof account
    let proof_data = proof_account.try_borrow_data()?;

    // Parse proof buffer header
    let status = proof_data[0];
    if status != BufferStatus::Ready as u8 {
        msg!("Proof buffer not ready");
        return Err(ProgramError::InvalidAccountData);
    }

    let proof_len = u16::from_le_bytes([proof_data[1], proof_data[2]]) as usize;
    let num_pi = u16::from_le_bytes([proof_data[3], proof_data[4]]) as usize;

    // Extract public inputs and proof
    let pi_start = BUFFER_HEADER_SIZE;
    let pi_end = pi_start + (num_pi * 32);
    let proof_start = pi_end;
    let proof_end = proof_start + proof_len;

    let pi_bytes = &proof_data[pi_start..pi_end];
    let proof_bytes = &proof_data[proof_start..proof_end];

    // Parse public inputs
    let mut public_inputs: Vec<Fr> = Vec::with_capacity(num_pi);
    for i in 0..num_pi {
        let start = i * 32;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&pi_bytes[start..start + 32]);
        public_inputs.push(arr);
    }

    msg!("Parsing VK and Proof...");
    sol_log_compute_units();

    // Parse VK
    let vk = plonk_solana_core::key::VerificationKey::from_bytes(VK_BYTES)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // Parse proof
    let log_n = vk.log2_circuit_size as usize;
    let is_zk = true;
    let proof = plonk_solana_core::proof::Proof::from_bytes(proof_bytes, log_n, is_zk)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    msg!("Generating challenges...");
    sol_log_compute_units();

    // Generate challenges - THIS IS THE EXPENSIVE PART
    let challenges = verify_step1_challenges(&vk, &proof, &public_inputs).map_err(|e| {
        msg!("Challenge generation failed: {:?}", e);
        ProgramError::InvalidAccountData
    })?;

    msg!("Saving challenges to state...");
    sol_log_compute_units();

    // Save challenges to state account
    state.log_n = log_n as u8;
    state.is_zk = if is_zk { 1 } else { 0 };
    state.num_public_inputs = num_pi as u8;

    // RelationParameters
    state.eta = challenges.relation_params.eta;
    state.eta_two = challenges.relation_params.eta_two;
    state.eta_three = challenges.relation_params.eta_three;
    state.beta = challenges.relation_params.beta;
    state.gamma = challenges.relation_params.gamma;
    state.public_input_delta = challenges.relation_params.public_input_delta;

    // Alphas (25)
    for (i, alpha) in challenges.alphas.iter().enumerate() {
        if i < 25 {
            state.alphas[i] = *alpha;
        }
    }

    // Gate challenges (28)
    for (i, gc) in challenges.gate_challenges.iter().enumerate() {
        if i < 28 {
            state.gate_challenges[i] = *gc;
        }
    }

    // Sumcheck challenges (28)
    for (i, sc) in challenges.sumcheck_challenges.iter().enumerate() {
        if i < 28 {
            state.sumcheck_challenges[i] = *sc;
        }
    }

    // Other challenges
    state.libra_challenge = challenges.libra_challenge.unwrap_or([0u8; 32]);
    state.rho = challenges.rho;
    state.gemini_r = challenges.gemini_r;
    state.shplonk_nu = challenges.shplonk_nu;
    state.shplonk_z = challenges.shplonk_z;

    // Update phase
    state.set_phase(phased::Phase::ChallengesGenerated);

    msg!("Phase 1 complete: Challenges generated");
    sol_log_compute_units();
    Ok(())
}

/// Phase 2: Verify sumcheck protocol
fn process_phased_verify_sumcheck(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Phased: Verify Sumcheck");
    sol_log_compute_units();

    let account_iter = &mut accounts.iter();
    let state_account = next_account_info(account_iter)?;
    let proof_account = next_account_info(account_iter)?;

    if !state_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state_data = state_account.try_borrow_mut_data()?;
    let state = phased::VerificationState::from_bytes_mut(&mut state_data)
        .ok_or(ProgramError::InvalidAccountData)?;

    // Check we're in the right phase
    if state.get_phase() != phased::Phase::ChallengesGenerated {
        msg!("Invalid phase: expected ChallengesGenerated");
        return Err(ProgramError::InvalidAccountData);
    }

    // Read proof data
    let proof_data = proof_account.try_borrow_data()?;
    let num_pi = state.num_public_inputs as usize;
    let pi_end = BUFFER_HEADER_SIZE + (num_pi * 32);
    let proof_len = u16::from_le_bytes([proof_data[1], proof_data[2]]) as usize;
    let proof_bytes = &proof_data[pi_end..pi_end + proof_len];

    // Parse VK and proof
    let vk = plonk_solana_core::key::VerificationKey::from_bytes(VK_BYTES)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let proof = plonk_solana_core::proof::Proof::from_bytes(
        proof_bytes,
        state.log_n as usize,
        state.is_zk != 0,
    )
    .map_err(|_| ProgramError::InvalidAccountData)?;

    // Reconstruct challenges from state
    let challenges = reconstruct_challenges(state);

    msg!("Running sumcheck verification...");
    sol_log_compute_units();

    // Verify sumcheck
    let sumcheck_ok = verify_step2_sumcheck(&vk, &proof, &challenges).map_err(|e| {
        msg!("Sumcheck failed: {:?}", e);
        state.set_phase(phased::Phase::Failed);
        ProgramError::InvalidAccountData
    })?;

    if !sumcheck_ok {
        msg!("Sumcheck verification returned false");
        state.set_phase(phased::Phase::Failed);
        return Err(ProgramError::InvalidAccountData);
    }

    state.sumcheck_passed = 1;
    state.set_phase(phased::Phase::SumcheckVerified);

    msg!("Phase 2 complete: Sumcheck verified");
    sol_log_compute_units();
    Ok(())
}

/// Phase 3: Compute P0/P1 (Shplemini MSM)
fn process_phased_compute_msm(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Phased: Compute MSM");
    sol_log_compute_units();

    let account_iter = &mut accounts.iter();
    let state_account = next_account_info(account_iter)?;
    let proof_account = next_account_info(account_iter)?;

    if !state_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state_data = state_account.try_borrow_mut_data()?;
    let state = phased::VerificationState::from_bytes_mut(&mut state_data)
        .ok_or(ProgramError::InvalidAccountData)?;

    // Check we're in the right phase
    if state.get_phase() != phased::Phase::SumcheckVerified {
        msg!("Invalid phase: expected SumcheckVerified");
        return Err(ProgramError::InvalidAccountData);
    }

    // Read proof data
    let proof_data = proof_account.try_borrow_data()?;
    let num_pi = state.num_public_inputs as usize;
    let pi_end = BUFFER_HEADER_SIZE + (num_pi * 32);
    let proof_len = u16::from_le_bytes([proof_data[1], proof_data[2]]) as usize;
    let proof_bytes = &proof_data[pi_end..pi_end + proof_len];

    // Parse VK and proof
    let vk = plonk_solana_core::key::VerificationKey::from_bytes(VK_BYTES)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let proof = plonk_solana_core::proof::Proof::from_bytes(
        proof_bytes,
        state.log_n as usize,
        state.is_zk != 0,
    )
    .map_err(|_| ProgramError::InvalidAccountData)?;

    // Reconstruct challenges from state
    let challenges = reconstruct_challenges(state);

    msg!("Computing pairing points (MSM)...");
    sol_log_compute_units();

    // Compute P0/P1
    let (p0, p1) = verify_step3_pairing_points(&vk, &proof, &challenges).map_err(|e| {
        msg!("MSM failed: {:?}", e);
        state.set_phase(phased::Phase::Failed);
        ProgramError::InvalidAccountData
    })?;

    // Save P0/P1 to state
    state.p0 = p0;
    state.p1 = p1;
    state.set_phase(phased::Phase::MsmComputed);

    msg!("Phase 3 complete: P0/P1 computed");
    sol_log_compute_units();
    Ok(())
}

/// Phase 4: Final pairing check
fn process_phased_final_check(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Phased: Final Pairing Check");
    sol_log_compute_units();

    let account_iter = &mut accounts.iter();
    let state_account = next_account_info(account_iter)?;

    if !state_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state_data = state_account.try_borrow_mut_data()?;
    let state = phased::VerificationState::from_bytes_mut(&mut state_data)
        .ok_or(ProgramError::InvalidAccountData)?;

    // Check we're in the right phase
    if state.get_phase() != phased::Phase::MsmComputed {
        msg!("Invalid phase: expected MsmComputed");
        return Err(ProgramError::InvalidAccountData);
    }

    msg!("Running pairing check...");
    sol_log_compute_units();

    // Debug: print first 8 bytes of P0 and P1
    msg!(
        "P0[0..8]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        state.p0[0],
        state.p0[1],
        state.p0[2],
        state.p0[3],
        state.p0[4],
        state.p0[5],
        state.p0[6],
        state.p0[7]
    );
    msg!(
        "P1[0..8]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        state.p1[0],
        state.p1[1],
        state.p1[2],
        state.p1[3],
        state.p1[4],
        state.p1[5],
        state.p1[6],
        state.p1[7]
    );

    // Final pairing check
    let pairing_ok = verify_step4_pairing_check(&state.p0, &state.p1).map_err(|e| {
        msg!("Pairing check failed: {:?}", e);
        state.set_phase(phased::Phase::Failed);
        ProgramError::InvalidAccountData
    })?;

    if pairing_ok {
        state.verified = 1;
        state.set_phase(phased::Phase::Complete);
        msg!("✅ UltraHonk proof verified successfully!");
    } else {
        state.verified = 0;
        state.set_phase(phased::Phase::Failed);
        msg!("❌ Pairing check failed");
        return Err(ProgramError::InvalidAccountData);
    }

    sol_log_compute_units();
    Ok(())
}

// ============================================================================
// Sub-Phased Challenge Generation (splits Phase 1)
// ============================================================================

/// Phase 1 Full: Unified challenge generation (after Montgomery optimization)
/// This does all of Phase 1 in one transaction (~300K CUs with Montgomery)
fn process_phase1_full(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    // Reuse the existing challenge generation function
    process_phased_generate_challenges(program_id, accounts)
}

/// Phase 1a: Generate eta, beta/gamma challenges
fn process_phase1a_eta_beta_gamma(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Phase 1a: eta/beta/gamma");
    sol_log_compute_units();

    let account_iter = &mut accounts.iter();
    let state_account = next_account_info(account_iter)?;
    let proof_account = next_account_info(account_iter)?;

    if !state_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state_data = state_account.try_borrow_mut_data()?;
    let state = phased::VerificationState::from_bytes_mut(&mut state_data)
        .ok_or(ProgramError::InvalidAccountData)?;

    // Check we're at the start
    let sub_phase = state.get_challenge_sub_phase();
    if sub_phase != phased::ChallengeSubPhase::NotStarted {
        msg!("Invalid sub-phase: expected NotStarted");
        return Err(ProgramError::InvalidAccountData);
    }

    // Read proof data
    let proof_data = proof_account.try_borrow_data()?;
    if proof_data[0] != BufferStatus::Ready as u8 {
        msg!("Proof buffer not ready");
        return Err(ProgramError::InvalidAccountData);
    }

    let proof_len = u16::from_le_bytes([proof_data[1], proof_data[2]]) as usize;
    let num_pi = u16::from_le_bytes([proof_data[3], proof_data[4]]) as usize;
    let pi_end = BUFFER_HEADER_SIZE + (num_pi * 32);
    let proof_bytes = &proof_data[pi_end..pi_end + proof_len];

    // Parse public inputs
    let mut public_inputs: Vec<Fr> = Vec::with_capacity(num_pi);
    for i in 0..num_pi {
        let start = BUFFER_HEADER_SIZE + (i * 32);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&proof_data[start..start + 32]);
        public_inputs.push(arr);
    }

    msg!("Parsing VK/Proof...");
    sol_log_compute_units();

    // Parse VK and proof
    let vk = plonk_solana_core::key::VerificationKey::from_bytes(VK_BYTES)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let log_n = vk.log2_circuit_size as usize;
    let is_zk = true;
    let proof = plonk_solana_core::proof::Proof::from_bytes(proof_bytes, log_n, is_zk)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    msg!("Generating eta/beta/gamma...");
    sol_log_compute_units();

    // Generate phase 1a challenges
    let result = generate_challenges_phase1a(&vk, &proof, &public_inputs)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // Save to state
    state.log_n = log_n as u8;
    state.is_zk = 1;
    state.num_public_inputs = num_pi as u8;
    state.eta = result.eta;
    state.eta_two = result.eta_two;
    state.eta_three = result.eta_three;
    state.beta = result.beta;
    state.gamma = result.gamma;
    state.transcript_state = result.transcript_state;

    state.set_phase(phased::Phase::ChallengesInProgress);
    state.set_challenge_sub_phase(phased::ChallengeSubPhase::EtaBetaGammaDone);

    msg!("Phase 1a complete");
    sol_log_compute_units();
    Ok(())
}

/// Phase 1b: Generate alpha and gate challenges
fn process_phase1b_alphas_gates(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Phase 1b: alphas/gates");
    sol_log_compute_units();

    let account_iter = &mut accounts.iter();
    let state_account = next_account_info(account_iter)?;
    let proof_account = next_account_info(account_iter)?;

    if !state_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state_data = state_account.try_borrow_mut_data()?;
    let state = phased::VerificationState::from_bytes_mut(&mut state_data)
        .ok_or(ProgramError::InvalidAccountData)?;

    // Check sub-phase
    if state.get_challenge_sub_phase() != phased::ChallengeSubPhase::EtaBetaGammaDone {
        msg!("Invalid sub-phase: expected EtaBetaGammaDone");
        return Err(ProgramError::InvalidAccountData);
    }

    // Read proof
    let proof_data = proof_account.try_borrow_data()?;
    let num_pi = state.num_public_inputs as usize;
    let pi_end = BUFFER_HEADER_SIZE + (num_pi * 32);
    let proof_len = u16::from_le_bytes([proof_data[1], proof_data[2]]) as usize;
    let proof_bytes = &proof_data[pi_end..pi_end + proof_len];

    let proof = plonk_solana_core::proof::Proof::from_bytes(
        proof_bytes,
        state.log_n as usize,
        state.is_zk != 0,
    )
    .map_err(|_| ProgramError::InvalidAccountData)?;

    msg!("Generating alphas/gates...");
    sol_log_compute_units();

    let result = generate_challenges_phase1b(&proof, &state.transcript_state)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // Save alphas
    for (i, alpha) in result.alphas.iter().enumerate() {
        if i < 25 {
            state.alphas[i] = *alpha;
        }
    }

    // Save gate challenges
    for (i, gc) in result.gate_challenges.iter().enumerate() {
        if i < 28 {
            state.gate_challenges[i] = *gc;
        }
    }

    state.libra_challenge = result.libra_challenge.unwrap_or([0u8; 32]);
    state.transcript_state = result.transcript_state;
    state.set_challenge_sub_phase(phased::ChallengeSubPhase::AlphasGatesDone);

    // Debug: print transcript state after phase 1b
    msg!(
        "1b transcript_state[24..32]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        state.transcript_state[24], state.transcript_state[25], state.transcript_state[26], state.transcript_state[27],
        state.transcript_state[28], state.transcript_state[29], state.transcript_state[30], state.transcript_state[31]
    );

    msg!("Phase 1b complete");
    sol_log_compute_units();
    Ok(())
}

/// Phase 1c: Generate sumcheck challenges (rounds 0-13)
fn process_phase1c_sumcheck_half(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Phase 1c: sumcheck 0-13");
    sol_log_compute_units();

    let account_iter = &mut accounts.iter();
    let state_account = next_account_info(account_iter)?;
    let proof_account = next_account_info(account_iter)?;

    if !state_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state_data = state_account.try_borrow_mut_data()?;
    let state = phased::VerificationState::from_bytes_mut(&mut state_data)
        .ok_or(ProgramError::InvalidAccountData)?;

    if state.get_challenge_sub_phase() != phased::ChallengeSubPhase::AlphasGatesDone {
        msg!("Invalid sub-phase: expected AlphasGatesDone");
        return Err(ProgramError::InvalidAccountData);
    }

    // Read proof
    let proof_data = proof_account.try_borrow_data()?;
    let num_pi = state.num_public_inputs as usize;
    let pi_end = BUFFER_HEADER_SIZE + (num_pi * 32);
    let proof_len = u16::from_le_bytes([proof_data[1], proof_data[2]]) as usize;
    let proof_bytes = &proof_data[pi_end..pi_end + proof_len];

    let proof = plonk_solana_core::proof::Proof::from_bytes(
        proof_bytes,
        state.log_n as usize,
        state.is_zk != 0,
    )
    .map_err(|_| ProgramError::InvalidAccountData)?;

    msg!("Generating sumcheck 0-13...");
    sol_log_compute_units();

    let result = generate_challenges_phase1c(&proof, &state.transcript_state)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // Save sumcheck challenges (first 14)
    for (i, sc) in result.sumcheck_challenges.iter().enumerate() {
        if i < 14 {
            state.sumcheck_challenges[i] = *sc;
        }
    }

    state.transcript_state = result.transcript_state;
    state.set_challenge_sub_phase(phased::ChallengeSubPhase::SumcheckHalfDone);

    // Debug: print transcript state after phase 1c
    msg!(
        "1c transcript_state[24..32]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        state.transcript_state[24], state.transcript_state[25], state.transcript_state[26], state.transcript_state[27],
        state.transcript_state[28], state.transcript_state[29], state.transcript_state[30], state.transcript_state[31]
    );

    msg!("Phase 1c complete");
    sol_log_compute_units();
    Ok(())
}

/// Phase 1d: Generate remaining sumcheck + final challenges
fn process_phase1d_sumcheck_rest(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Phase 1d: sumcheck 14-27 + final");
    sol_log_compute_units();

    let account_iter = &mut accounts.iter();
    let state_account = next_account_info(account_iter)?;
    let proof_account = next_account_info(account_iter)?;

    if !state_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state_data = state_account.try_borrow_mut_data()?;
    let state = phased::VerificationState::from_bytes_mut(&mut state_data)
        .ok_or(ProgramError::InvalidAccountData)?;

    if state.get_challenge_sub_phase() != phased::ChallengeSubPhase::SumcheckHalfDone {
        msg!("Invalid sub-phase: expected SumcheckHalfDone");
        return Err(ProgramError::InvalidAccountData);
    }

    // Read proof
    let proof_data = proof_account.try_borrow_data()?;
    let num_pi = state.num_public_inputs as usize;
    let pi_end = BUFFER_HEADER_SIZE + (num_pi * 32);
    let proof_len = u16::from_le_bytes([proof_data[1], proof_data[2]]) as usize;
    let proof_bytes = &proof_data[pi_end..pi_end + proof_len];

    let proof = plonk_solana_core::proof::Proof::from_bytes(
        proof_bytes,
        state.log_n as usize,
        state.is_zk != 0,
    )
    .map_err(|_| ProgramError::InvalidAccountData)?;

    msg!("Generating sumcheck 14-27 + final...");
    sol_log_compute_units();

    // Debug: print transcript state
    msg!(
        "transcript_state[24..32]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        state.transcript_state[24],
        state.transcript_state[25],
        state.transcript_state[26],
        state.transcript_state[27],
        state.transcript_state[28],
        state.transcript_state[29],
        state.transcript_state[30],
        state.transcript_state[31]
    );

    let result = generate_challenges_phase1d(&proof, &state.transcript_state, state.is_zk != 0)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // Save remaining sumcheck challenges (14-27)
    for (i, sc) in result.sumcheck_challenges.iter().enumerate() {
        state.sumcheck_challenges[14 + i] = *sc;
    }

    state.rho = result.rho;
    state.gemini_r = result.gemini_r;
    state.shplonk_nu = result.shplonk_nu;
    state.shplonk_z = result.shplonk_z;
    state.set_challenge_sub_phase(phased::ChallengeSubPhase::AllChallengesDone);

    msg!("Phase 1d complete");
    sol_log_compute_units();
    Ok(())
}

/// Phase 1e1: Compute public_input_delta part 1 (first 9 items)
fn process_phase1e1_delta_part1(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Phase 1e1: delta part1");
    sol_log_compute_units();

    let account_iter = &mut accounts.iter();
    let state_account = next_account_info(account_iter)?;
    let proof_account = next_account_info(account_iter)?;

    if !state_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state_data = state_account.try_borrow_mut_data()?;
    let state = phased::VerificationState::from_bytes_mut(&mut state_data)
        .ok_or(ProgramError::InvalidAccountData)?;

    if state.get_challenge_sub_phase() != phased::ChallengeSubPhase::AllChallengesDone {
        msg!("Invalid sub-phase: expected AllChallengesDone");
        return Err(ProgramError::InvalidAccountData);
    }

    // Read proof and public inputs
    let proof_data = proof_account.try_borrow_data()?;
    let num_pi = state.num_public_inputs as usize;
    let pi_end = BUFFER_HEADER_SIZE + (num_pi * 32);
    let proof_len = u16::from_le_bytes([proof_data[1], proof_data[2]]) as usize;
    let proof_bytes = &proof_data[pi_end..pi_end + proof_len];

    // Parse public inputs
    let mut public_inputs: Vec<Fr> = Vec::with_capacity(num_pi);
    for i in 0..num_pi {
        let start = BUFFER_HEADER_SIZE + (i * 32);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&proof_data[start..start + 32]);
        public_inputs.push(arr);
    }

    let vk = plonk_solana_core::key::VerificationKey::from_bytes(VK_BYTES)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let proof = plonk_solana_core::proof::Proof::from_bytes(
        proof_bytes,
        state.log_n as usize,
        state.is_zk != 0,
    )
    .map_err(|_| ProgramError::InvalidAccountData)?;

    msg!("Computing delta part1...");
    sol_log_compute_units();

    let partial = compute_delta_part1(
        &public_inputs,
        &proof,
        &state.beta,
        &state.gamma,
        vk.circuit_size(),
    );

    // Save partial result
    state.delta_numerator = partial.numerator;
    state.delta_denominator = partial.denominator;
    state.delta_numerator_acc = partial.numerator_acc;
    state.delta_denominator_acc = partial.denominator_acc;
    state.set_challenge_sub_phase(phased::ChallengeSubPhase::DeltaPart1Done);

    msg!("Phase 1e1 complete");
    sol_log_compute_units();
    Ok(())
}

/// Phase 1e2: Compute public_input_delta part 2 (remaining items + division)
fn process_phase1e2_delta_part2(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Phase 1e2: delta part2");
    sol_log_compute_units();

    let account_iter = &mut accounts.iter();
    let state_account = next_account_info(account_iter)?;
    let proof_account = next_account_info(account_iter)?;

    if !state_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state_data = state_account.try_borrow_mut_data()?;
    let state = phased::VerificationState::from_bytes_mut(&mut state_data)
        .ok_or(ProgramError::InvalidAccountData)?;

    if state.get_challenge_sub_phase() != phased::ChallengeSubPhase::DeltaPart1Done {
        msg!("Invalid sub-phase: expected DeltaPart1Done");
        return Err(ProgramError::InvalidAccountData);
    }

    // Read proof
    let proof_data = proof_account.try_borrow_data()?;
    let num_pi = state.num_public_inputs as usize;
    let pi_end = BUFFER_HEADER_SIZE + (num_pi * 32);
    let proof_len = u16::from_le_bytes([proof_data[1], proof_data[2]]) as usize;
    let proof_bytes = &proof_data[pi_end..pi_end + proof_len];

    let proof = plonk_solana_core::proof::Proof::from_bytes(
        proof_bytes,
        state.log_n as usize,
        state.is_zk != 0,
    )
    .map_err(|_| ProgramError::InvalidAccountData)?;

    // Reconstruct partial result
    let partial = DeltaPartialResult {
        numerator: state.delta_numerator,
        denominator: state.delta_denominator,
        numerator_acc: state.delta_numerator_acc,
        denominator_acc: state.delta_denominator_acc,
        items_processed: 9, // 1 public input + 8 ppo elements
    };

    msg!("Computing delta part2...");
    sol_log_compute_units();

    let delta = compute_delta_part2(&proof, &state.beta, &partial);

    state.public_input_delta = delta;
    state.set_challenge_sub_phase(phased::ChallengeSubPhase::DeltaComputed);
    state.set_phase(phased::Phase::ChallengesGenerated);

    msg!("Phase 1e2 complete - all challenges generated!");
    sol_log_compute_units();
    Ok(())
}

// ============================================================================
// Sumcheck Sub-Phase Handlers (Phase 2)
// ============================================================================

/// Phase 2 rounds: Verify a batch of sumcheck rounds
/// Data format: [instruction(1), start_round(1), end_round(1)]
fn process_phase2_rounds(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // Parse round range from instruction data
    if instruction_data.len() < 3 {
        msg!("Missing round range in instruction data");
        return Err(ProgramError::InvalidInstructionData);
    }
    let start_round = instruction_data[1] as usize;
    let end_round = instruction_data[2] as usize;

    msg!("Phase 2: rounds {}-{}", start_round, end_round);
    sol_log_compute_units();

    let account_iter = &mut accounts.iter();
    let state_account = next_account_info(account_iter)?;
    let proof_account = next_account_info(account_iter)?;

    if !state_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state_data = state_account.try_borrow_mut_data()?;
    let state = phased::VerificationState::from_bytes_mut(&mut state_data)
        .ok_or(ProgramError::InvalidAccountData)?;

    // Check phase - must be ChallengesGenerated or SumcheckInProgress
    let phase = state.get_phase();
    if phase != phased::Phase::ChallengesGenerated && phase != phased::Phase::SumcheckInProgress {
        msg!("Invalid phase: expected ChallengesGenerated or SumcheckInProgress");
        return Err(ProgramError::InvalidAccountData);
    }

    // Check rounds continuity
    let rounds_completed = state.sumcheck_rounds_completed as usize;
    if start_round != rounds_completed {
        msg!(
            "Invalid round range: start {} but {} rounds completed",
            start_round,
            rounds_completed
        );
        return Err(ProgramError::InvalidAccountData);
    }

    // Read proof
    let proof_data = proof_account.try_borrow_data()?;
    let num_pi = state.num_public_inputs as usize;
    let pi_end = BUFFER_HEADER_SIZE + (num_pi * 32);
    let proof_len = u16::from_le_bytes([proof_data[1], proof_data[2]]) as usize;
    let proof_bytes = &proof_data[pi_end..pi_end + proof_len];

    let proof = plonk_solana_core::proof::Proof::from_bytes(
        proof_bytes,
        state.log_n as usize,
        state.is_zk != 0,
    )
    .map_err(|_| ProgramError::InvalidAccountData)?;

    // Get or initialize sumcheck state
    let prev_state = if start_round == 0 {
        // Initialize sumcheck state
        let libra_challenge = if state.libra_challenge == [0u8; 32] {
            None
        } else {
            Some(state.libra_challenge)
        };
        sumcheck_rounds_init(&proof, libra_challenge.as_ref())
    } else {
        // Reconstruct from saved state
        SumcheckRoundsState {
            target: state.sumcheck_target,
            pow_partial: state.sumcheck_pow_partial,
            rounds_completed,
        }
    };

    let challenges = reconstruct_sumcheck_challenges(state);

    msg!("Running rounds...");
    sol_log_compute_units();

    // Verify rounds
    let new_state =
        verify_sumcheck_rounds_partial(&proof, &challenges, &prev_state, start_round, end_round)
            .map_err(|e| {
                msg!("Rounds {}-{} failed: {}", start_round, end_round, e);
                ProgramError::InvalidAccountData
            })?;

    // Save intermediate state
    state.sumcheck_target = new_state.target;
    state.sumcheck_pow_partial = new_state.pow_partial;
    state.sumcheck_rounds_completed = new_state.rounds_completed as u8;
    state.set_phase(phased::Phase::SumcheckInProgress);

    // Mark all rounds done if we've completed all log_n rounds
    if new_state.rounds_completed >= proof.log_n {
        state.set_sumcheck_sub_phase(phased::SumcheckSubPhase::AllRoundsDone);
    }

    msg!(
        "Rounds {}-{} complete ({} total)",
        start_round,
        end_round,
        new_state.rounds_completed
    );
    sol_log_compute_units();
    Ok(())
}

/// Phase 2d: Verify relations and final check
fn process_phase2d_relations(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Phase 2d: relations");
    sol_log_compute_units();

    let account_iter = &mut accounts.iter();
    let state_account = next_account_info(account_iter)?;
    let proof_account = next_account_info(account_iter)?;

    if !state_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state_data = state_account.try_borrow_mut_data()?;
    let state = phased::VerificationState::from_bytes_mut(&mut state_data)
        .ok_or(ProgramError::InvalidAccountData)?;

    // Check we're in SumcheckInProgress with all rounds done
    if state.get_phase() != phased::Phase::SumcheckInProgress {
        msg!("Invalid phase: expected SumcheckInProgress");
        return Err(ProgramError::InvalidAccountData);
    }
    // Verify all rounds are completed (rounds_completed >= log_n)
    let log_n = state.log_n as usize;
    if (state.sumcheck_rounds_completed as usize) < log_n {
        msg!(
            "Not all rounds completed: {} < {}",
            state.sumcheck_rounds_completed,
            log_n
        );
        return Err(ProgramError::InvalidAccountData);
    }

    // Read proof
    let proof_data = proof_account.try_borrow_data()?;
    let num_pi = state.num_public_inputs as usize;
    let pi_end = BUFFER_HEADER_SIZE + (num_pi * 32);
    let proof_len = u16::from_le_bytes([proof_data[1], proof_data[2]]) as usize;
    let proof_bytes = &proof_data[pi_end..pi_end + proof_len];

    let proof = plonk_solana_core::proof::Proof::from_bytes(
        proof_bytes,
        state.log_n as usize,
        state.is_zk != 0,
    )
    .map_err(|_| ProgramError::InvalidAccountData)?;

    // Reconstruct sumcheck state
    let sumcheck_state = SumcheckRoundsState {
        target: state.sumcheck_target,
        pow_partial: state.sumcheck_pow_partial,
        rounds_completed: state.sumcheck_rounds_completed as usize,
    };

    // Reconstruct relation params
    let relation_params = plonk_solana_core::RelationParameters {
        eta: state.eta,
        eta_two: state.eta_two,
        eta_three: state.eta_three,
        beta: state.beta,
        gamma: state.gamma,
        public_input_delta: state.public_input_delta,
    };

    let libra_challenge = if state.libra_challenge == [0u8; 32] {
        None
    } else {
        Some(state.libra_challenge)
    };

    msg!("Running relations...");
    sol_log_compute_units();

    // Verify relations (need sumcheck_u_challenges for ZK adjustment)
    let sumcheck_u_challenges: Vec<Fr> = state.sumcheck_challenges.to_vec();
    verify_sumcheck_relations(
        &proof,
        &relation_params,
        &state.alphas,
        &sumcheck_u_challenges,
        &sumcheck_state,
        libra_challenge.as_ref(),
    )
    .map_err(|e| {
        msg!("Relations failed: {}", e);
        ProgramError::InvalidAccountData
    })?;

    state.sumcheck_passed = 1;
    state.set_sumcheck_sub_phase(phased::SumcheckSubPhase::RelationsDone);
    state.set_phase(phased::Phase::SumcheckVerified);

    msg!("Phase 2d complete - sumcheck verified!");
    sol_log_compute_units();
    Ok(())
}

// ============================================================================
// Sub-Phased MSM Computation (splits Phase 3)
// ============================================================================

/// Phase 3a: Compute weights and scalar accumulation (~870K CUs)
fn process_phase3a_weights(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Phase 3a: weights + scalar accum");
    sol_log_compute_units();

    let account_iter = &mut accounts.iter();
    let state_account = next_account_info(account_iter)?;
    let proof_account = next_account_info(account_iter)?;

    if !state_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state_data = state_account.try_borrow_mut_data()?;
    let state = phased::VerificationState::from_bytes_mut(&mut state_data)
        .ok_or(ProgramError::InvalidAccountData)?;

    // Check phase - we can start from SumcheckVerified or MsmInProgress with Phase3a not done
    let phase = state.get_phase();
    if phase != phased::Phase::SumcheckVerified
        && !(phase == phased::Phase::MsmInProgress
            && state.get_shplemini_sub_phase() == phased::ShpleminiSubPhase::NotStarted)
    {
        msg!("Invalid phase: expected SumcheckVerified or MsmInProgress(NotStarted)");
        return Err(ProgramError::InvalidAccountData);
    }

    // Read proof data
    let proof_data = proof_account.try_borrow_data()?;
    let num_pi = state.num_public_inputs as usize;
    let pi_end = BUFFER_HEADER_SIZE + (num_pi * 32);
    let proof_len = u16::from_le_bytes([proof_data[1], proof_data[2]]) as usize;
    let proof_bytes = &proof_data[pi_end..pi_end + proof_len];

    // Parse proof
    let proof = plonk_solana_core::proof::Proof::from_bytes(
        proof_bytes,
        state.log_n as usize,
        state.is_zk != 0,
    )
    .map_err(|_| ProgramError::InvalidAccountData)?;

    // Reconstruct challenges from state
    let challenges = reconstruct_challenges(state);

    msg!("Computing shplemini phase 3a...");
    sol_log_compute_units();

    // Compute Phase 3a
    let result = shplemini_phase3a(&proof, &challenges, state.log_n as usize).map_err(|e| {
        msg!("Phase 3a failed: {}", e);
        state.set_phase(phased::Phase::Failed);
        ProgramError::InvalidAccountData
    })?;

    // Save intermediate state
    for (i, r) in result.r_pows.iter().enumerate() {
        if i < 28 {
            state.shplemini_r_pows[i] = *r;
        }
    }
    state.shplemini_pos0 = result.pos0;
    state.shplemini_neg0 = result.neg0;
    state.shplemini_unshifted = result.unshifted;
    state.shplemini_shifted = result.shifted;
    state.shplemini_eval_acc = result.eval_acc;

    state.set_phase(phased::Phase::MsmInProgress);
    state.set_shplemini_sub_phase(phased::ShpleminiSubPhase::Phase3aDone);

    msg!("Phase 3a complete!");
    sol_log_compute_units();
    Ok(())
}

/// Phase 3b1: Folding rounds only (~870K CUs)
fn process_phase3b1_folding(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Phase 3b1: folding");
    sol_log_compute_units();

    let account_iter = &mut accounts.iter();
    let state_account = next_account_info(account_iter)?;
    let proof_account = next_account_info(account_iter)?;

    if !state_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state_data = state_account.try_borrow_mut_data()?;
    let state = phased::VerificationState::from_bytes_mut(&mut state_data)
        .ok_or(ProgramError::InvalidAccountData)?;

    // Check phase
    if state.get_phase() != phased::Phase::MsmInProgress
        || state.get_shplemini_sub_phase() != phased::ShpleminiSubPhase::Phase3aDone
    {
        msg!("Invalid phase: expected MsmInProgress(Phase3aDone)");
        return Err(ProgramError::InvalidAccountData);
    }

    // Read proof data
    let proof_data = proof_account.try_borrow_data()?;
    let num_pi = state.num_public_inputs as usize;
    let pi_end = BUFFER_HEADER_SIZE + (num_pi * 32);
    let proof_len = u16::from_le_bytes([proof_data[1], proof_data[2]]) as usize;
    let proof_bytes = &proof_data[pi_end..pi_end + proof_len];

    // Parse proof
    let proof = plonk_solana_core::proof::Proof::from_bytes(
        proof_bytes,
        state.log_n as usize,
        state.is_zk != 0,
    )
    .map_err(|_| ProgramError::InvalidAccountData)?;

    // Reconstruct challenges and Phase 3a result from state
    let challenges = reconstruct_challenges(state);
    let phase3a_result = ShpleminiPhase3aResult {
        r_pows: state.shplemini_r_pows.to_vec(),
        pos0: state.shplemini_pos0,
        neg0: state.shplemini_neg0,
        unshifted: state.shplemini_unshifted,
        shifted: state.shplemini_shifted,
        eval_acc: state.shplemini_eval_acc,
    };

    msg!("Computing shplemini phase 3b1 (folding)...");
    sol_log_compute_units();

    // Compute Phase 3b1 (folding only)
    let result = shplemini_phase3b1(&proof, &challenges, &phase3a_result, state.log_n as usize)
        .map_err(|e| {
            msg!("Phase 3b1 failed: {}", e);
            state.set_phase(phased::Phase::Failed);
            ProgramError::InvalidAccountData
        })?;

    // Save fold_pos and const_acc
    for (i, f) in result.fold_pos.iter().enumerate() {
        if i < 28 {
            state.shplemini_fold_pos[i] = *f;
        }
    }
    state.shplemini_const_acc = result.const_acc;

    state.set_shplemini_sub_phase(phased::ShpleminiSubPhase::Phase3b1Done);

    msg!("Phase 3b1 complete!");
    sol_log_compute_units();
    Ok(())
}

/// Phase 3b2: Gemini + libra (~500K CUs)
fn process_phase3b2_gemini(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Phase 3b2: gemini + libra");
    sol_log_compute_units();

    let account_iter = &mut accounts.iter();
    let state_account = next_account_info(account_iter)?;
    let proof_account = next_account_info(account_iter)?;

    if !state_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state_data = state_account.try_borrow_mut_data()?;
    let state = phased::VerificationState::from_bytes_mut(&mut state_data)
        .ok_or(ProgramError::InvalidAccountData)?;

    // Check phase
    if state.get_phase() != phased::Phase::MsmInProgress
        || state.get_shplemini_sub_phase() != phased::ShpleminiSubPhase::Phase3b1Done
    {
        msg!("Invalid phase: expected MsmInProgress(Phase3b1Done)");
        return Err(ProgramError::InvalidAccountData);
    }

    // Read proof data
    let proof_data = proof_account.try_borrow_data()?;
    let num_pi = state.num_public_inputs as usize;
    let pi_end = BUFFER_HEADER_SIZE + (num_pi * 32);
    let proof_len = u16::from_le_bytes([proof_data[1], proof_data[2]]) as usize;
    let proof_bytes = &proof_data[pi_end..pi_end + proof_len];

    // Parse proof
    let proof = plonk_solana_core::proof::Proof::from_bytes(
        proof_bytes,
        state.log_n as usize,
        state.is_zk != 0,
    )
    .map_err(|_| ProgramError::InvalidAccountData)?;

    // Reconstruct from state
    let challenges = reconstruct_challenges(state);
    let phase3a_result = ShpleminiPhase3aResult {
        r_pows: state.shplemini_r_pows.to_vec(),
        pos0: state.shplemini_pos0,
        neg0: state.shplemini_neg0,
        unshifted: state.shplemini_unshifted,
        shifted: state.shplemini_shifted,
        eval_acc: state.shplemini_eval_acc,
    };
    let phase3b1_result = ShpleminiPhase3b1Result {
        fold_pos: state.shplemini_fold_pos.to_vec(),
        const_acc: state.shplemini_const_acc,
    };

    msg!("Computing shplemini phase 3b2 (gemini+libra)...");
    sol_log_compute_units();

    // Compute Phase 3b2 (gemini + libra)
    let result = shplemini_phase3b2(
        &proof,
        &challenges,
        &phase3a_result,
        &phase3b1_result,
        state.log_n as usize,
    )
    .map_err(|e| {
        msg!("Phase 3b2 failed: {}", e);
        state.set_phase(phased::Phase::Failed);
        ProgramError::InvalidAccountData
    })?;

    // Save intermediate state
    state.shplemini_const_acc = result.const_acc;
    for (i, s) in result.gemini_scalars.iter().enumerate() {
        if i < 27 {
            state.shplemini_gemini_scalars[i] = *s;
        }
    }
    for (i, s) in result.libra_scalars.iter().enumerate() {
        if i < 3 {
            state.shplemini_libra_scalars[i] = *s;
        }
    }

    state.set_shplemini_sub_phase(phased::ShpleminiSubPhase::Phase3b2Done);

    msg!("Phase 3b2 complete!");
    sol_log_compute_units();
    Ok(())
}

/// Phase 3c: MSM computation (~500K CUs)
fn process_phase3c_msm(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    msg!("Phase 3c: MSM");
    sol_log_compute_units();

    let account_iter = &mut accounts.iter();
    let state_account = next_account_info(account_iter)?;
    let proof_account = next_account_info(account_iter)?;

    if !state_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut state_data = state_account.try_borrow_mut_data()?;
    let state = phased::VerificationState::from_bytes_mut(&mut state_data)
        .ok_or(ProgramError::InvalidAccountData)?;

    // Check phase
    if state.get_phase() != phased::Phase::MsmInProgress
        || state.get_shplemini_sub_phase() != phased::ShpleminiSubPhase::Phase3b2Done
    {
        msg!("Invalid phase: expected MsmInProgress(Phase3b2Done)");
        return Err(ProgramError::InvalidAccountData);
    }

    // Read proof data
    let proof_data = proof_account.try_borrow_data()?;
    let num_pi = state.num_public_inputs as usize;
    let pi_end = BUFFER_HEADER_SIZE + (num_pi * 32);
    let proof_len = u16::from_le_bytes([proof_data[1], proof_data[2]]) as usize;
    let proof_bytes = &proof_data[pi_end..pi_end + proof_len];

    // Parse VK and proof
    let vk = plonk_solana_core::key::VerificationKey::from_bytes(VK_BYTES)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let proof = plonk_solana_core::proof::Proof::from_bytes(
        proof_bytes,
        state.log_n as usize,
        state.is_zk != 0,
    )
    .map_err(|_| ProgramError::InvalidAccountData)?;

    // Reconstruct challenges and Phase 3b result from state
    let challenges = reconstruct_challenges(state);

    // Debug: print key challenge values
    msg!(
        "rho[0..8]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        challenges.rho[0],
        challenges.rho[1],
        challenges.rho[2],
        challenges.rho[3],
        challenges.rho[4],
        challenges.rho[5],
        challenges.rho[6],
        challenges.rho[7]
    );
    msg!(
        "const_acc[0..8]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        state.shplemini_const_acc[0],
        state.shplemini_const_acc[1],
        state.shplemini_const_acc[2],
        state.shplemini_const_acc[3],
        state.shplemini_const_acc[4],
        state.shplemini_const_acc[5],
        state.shplemini_const_acc[6],
        state.shplemini_const_acc[7]
    );
    msg!(
        "unshifted[0..8]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        state.shplemini_unshifted[0],
        state.shplemini_unshifted[1],
        state.shplemini_unshifted[2],
        state.shplemini_unshifted[3],
        state.shplemini_unshifted[4],
        state.shplemini_unshifted[5],
        state.shplemini_unshifted[6],
        state.shplemini_unshifted[7]
    );

    let phase3b_result = ShpleminiPhase3bResult {
        const_acc: state.shplemini_const_acc,
        gemini_scalars: state.shplemini_gemini_scalars.to_vec(),
        libra_scalars: state.shplemini_libra_scalars.to_vec(),
        r_pows: state.shplemini_r_pows.to_vec(),
        unshifted: state.shplemini_unshifted,
        shifted: state.shplemini_shifted,
    };

    msg!("Computing shplemini phase 3c (MSM)...");
    sol_log_compute_units();

    // Compute Phase 3c (final MSM)
    let (p0, p1) = shplemini_phase3c(&proof, &vk, &challenges, &phase3b_result).map_err(|e| {
        msg!("Phase 3c failed: {}", e);
        state.set_phase(phased::Phase::Failed);
        ProgramError::InvalidAccountData
    })?;

    // Debug: print first 8 bytes of computed P0 and P1
    msg!(
        "Computed P0[0..8]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        p0[0],
        p0[1],
        p0[2],
        p0[3],
        p0[4],
        p0[5],
        p0[6],
        p0[7]
    );
    msg!(
        "Computed P1[0..8]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        p1[0],
        p1[1],
        p1[2],
        p1[3],
        p1[4],
        p1[5],
        p1[6],
        p1[7]
    );

    // Save P0/P1 to state
    state.p0 = p0;
    state.p1 = p1;
    state.set_shplemini_sub_phase(phased::ShpleminiSubPhase::Complete);
    state.set_phase(phased::Phase::MsmComputed);

    msg!("Phase 3c complete - P0/P1 computed!");
    sol_log_compute_units();
    Ok(())
}

/// Reconstruct SumcheckChallenges from state account
fn reconstruct_sumcheck_challenges(
    state: &phased::VerificationState,
) -> plonk_solana_core::sumcheck::SumcheckChallenges {
    plonk_solana_core::sumcheck::SumcheckChallenges {
        gate_challenges: state.gate_challenges.to_vec(),
        sumcheck_u_challenges: state.sumcheck_challenges.to_vec(),
        alphas: state.alphas.to_vec(),
    }
}

/// Reconstruct Challenges struct from state account
fn reconstruct_challenges(state: &phased::VerificationState) -> Challenges {
    use plonk_solana_core::RelationParameters;

    Challenges {
        relation_params: RelationParameters {
            eta: state.eta,
            eta_two: state.eta_two,
            eta_three: state.eta_three,
            beta: state.beta,
            gamma: state.gamma,
            public_input_delta: state.public_input_delta,
        },
        alpha: state.alphas[0],
        alphas: state.alphas.to_vec(),
        libra_challenge: if state.libra_challenge == [0u8; 32] {
            None
        } else {
            Some(state.libra_challenge)
        },
        gate_challenges: state.gate_challenges.to_vec(),
        sumcheck_challenges: state.sumcheck_challenges.to_vec(),
        rho: state.rho,
        gemini_r: state.gemini_r,
        shplonk_nu: state.shplonk_nu,
        shplonk_z: state.shplonk_z,
    }
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
