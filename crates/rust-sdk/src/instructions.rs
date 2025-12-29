//! Instruction builders for the UltraHonk verifier program

use crate::types::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};
use solana_system_interface::program as system_program;

/// Create instruction to initialize a VK buffer
pub fn init_vk_buffer(program_id: &Pubkey, vk_account: &Pubkey) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[IX_INIT_VK_BUFFER],
        vec![AccountMeta::new(*vk_account, false)],
    )
}

/// Create instruction to upload a VK chunk
pub fn upload_vk_chunk(
    program_id: &Pubkey,
    vk_account: &Pubkey,
    offset: u16,
    chunk: &[u8],
) -> Instruction {
    let mut data = Vec::with_capacity(3 + chunk.len());
    data.push(IX_UPLOAD_VK_CHUNK);
    data.extend_from_slice(&offset.to_le_bytes());
    data.extend_from_slice(chunk);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![AccountMeta::new(*vk_account, false)],
    )
}

/// Create instruction to initialize a proof buffer
pub fn init_buffer(
    program_id: &Pubkey,
    proof_account: &Pubkey,
    num_public_inputs: u16,
) -> Instruction {
    let mut data = [0u8; 3];
    data[0] = IX_INIT_BUFFER;
    data[1..3].copy_from_slice(&num_public_inputs.to_le_bytes());

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![AccountMeta::new(*proof_account, false)],
    )
}

/// Create instruction to upload a proof chunk
pub fn upload_chunk(
    program_id: &Pubkey,
    proof_account: &Pubkey,
    offset: u16,
    chunk: &[u8],
) -> Instruction {
    let mut data = Vec::with_capacity(3 + chunk.len());
    data.push(IX_UPLOAD_CHUNK);
    data.extend_from_slice(&offset.to_le_bytes());
    data.extend_from_slice(chunk);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![AccountMeta::new(*proof_account, false)],
    )
}

/// Create instruction to set public inputs
pub fn set_public_inputs(
    program_id: &Pubkey,
    proof_account: &Pubkey,
    public_inputs: &[u8],
) -> Instruction {
    let mut data = Vec::with_capacity(1 + public_inputs.len());
    data.push(IX_SET_PUBLIC_INPUTS);
    data.extend_from_slice(public_inputs);

    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![AccountMeta::new(*proof_account, false)],
    )
}

/// Create Phase 1 instruction (challenge generation)
pub fn phase1_full(
    program_id: &Pubkey,
    state_account: &Pubkey,
    proof_account: &Pubkey,
    vk_account: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[IX_PHASE1_FULL],
        vec![
            AccountMeta::new(*state_account, false),
            AccountMeta::new_readonly(*proof_account, false),
            AccountMeta::new_readonly(*vk_account, false),
        ],
    )
}

/// Create Phase 2 sumcheck rounds instruction
pub fn phase2_rounds(
    program_id: &Pubkey,
    state_account: &Pubkey,
    proof_account: &Pubkey,
    start_round: u8,
    end_round: u8,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[IX_PHASE2_ROUNDS, start_round, end_round],
        vec![
            AccountMeta::new(*state_account, false),
            AccountMeta::new_readonly(*proof_account, false),
        ],
    )
}

/// Create Phase 2d relations instruction
pub fn phase2d_relations(
    program_id: &Pubkey,
    state_account: &Pubkey,
    proof_account: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[IX_PHASE2D_RELATIONS],
        vec![
            AccountMeta::new(*state_account, false),
            AccountMeta::new_readonly(*proof_account, false),
        ],
    )
}

/// Create Phase 3a weights instruction
pub fn phase3a_weights(
    program_id: &Pubkey,
    state_account: &Pubkey,
    proof_account: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[IX_PHASE3A_WEIGHTS],
        vec![
            AccountMeta::new(*state_account, false),
            AccountMeta::new_readonly(*proof_account, false),
        ],
    )
}

/// Create Phase 3b1 folding instruction
pub fn phase3b1_folding(
    program_id: &Pubkey,
    state_account: &Pubkey,
    proof_account: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[IX_PHASE3B1_FOLDING],
        vec![
            AccountMeta::new(*state_account, false),
            AccountMeta::new_readonly(*proof_account, false),
        ],
    )
}

/// Create Phase 3b2 gemini instruction
pub fn phase3b2_gemini(
    program_id: &Pubkey,
    state_account: &Pubkey,
    proof_account: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[IX_PHASE3B2_GEMINI],
        vec![
            AccountMeta::new(*state_account, false),
            AccountMeta::new_readonly(*proof_account, false),
        ],
    )
}

/// Create Phase 3c + 4 combined (MSM + Pairing) instruction
pub fn phase3c_and_pairing(
    program_id: &Pubkey,
    state_account: &Pubkey,
    proof_account: &Pubkey,
    vk_account: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[IX_PHASE3C_AND_PAIRING],
        vec![
            AccountMeta::new(*state_account, false),
            AccountMeta::new_readonly(*proof_account, false),
            AccountMeta::new_readonly(*vk_account, false),
        ],
    )
}

/// Create combined Phase 2d+3a instruction (Relations + Weights)
pub fn phase2d_and_3a(
    program_id: &Pubkey,
    state_account: &Pubkey,
    proof_account: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[IX_PHASE2D_AND_3A],
        vec![
            AccountMeta::new(*state_account, false),
            AccountMeta::new_readonly(*proof_account, false),
        ],
    )
}

/// Create combined Phase 3b instruction (Folding + Gemini)
pub fn phase3b_combined(
    program_id: &Pubkey,
    state_account: &Pubkey,
    proof_account: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[IX_PHASE3B_COMBINED],
        vec![
            AccountMeta::new(*state_account, false),
            AccountMeta::new_readonly(*proof_account, false),
        ],
    )
}

/// Create verification receipt PDA instruction
pub fn create_receipt(
    program_id: &Pubkey,
    state_account: &Pubkey,
    proof_account: &Pubkey,
    vk_account: &Pubkey,
    receipt_pda: &Pubkey,
    payer: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[IX_CREATE_RECEIPT],
        vec![
            AccountMeta::new_readonly(*state_account, false),
            AccountMeta::new_readonly(*proof_account, false),
            AccountMeta::new_readonly(*vk_account, false),
            AccountMeta::new(*receipt_pda, false),
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
    )
}

/// Create close accounts instruction to recover rent
pub fn close_accounts(
    program_id: &Pubkey,
    state_account: &Pubkey,
    proof_account: &Pubkey,
    payer: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[IX_CLOSE_ACCOUNTS],
        vec![
            AccountMeta::new(*state_account, false),
            AccountMeta::new(*proof_account, false),
            AccountMeta::new(*payer, true),
        ],
    )
}
