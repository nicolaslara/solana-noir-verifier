import {
  PublicKey,
  TransactionInstruction,
  SystemProgram,
} from '@solana/web3.js';
import {
  IX_INIT_BUFFER,
  IX_UPLOAD_CHUNK,
  IX_SET_PUBLIC_INPUTS,
  IX_INIT_VK_BUFFER,
  IX_UPLOAD_VK_CHUNK,
  IX_PHASE1_FULL,
  IX_PHASE2_ROUNDS,
  IX_PHASE2D_RELATIONS,
  IX_PHASE3A_WEIGHTS,
  IX_PHASE3B1_FOLDING,
  IX_PHASE3B2_GEMINI,
  IX_PHASE3C_AND_PAIRING,
  IX_PHASE2D_AND_3A,
  IX_PHASE3B_COMBINED,
  IX_CREATE_RECEIPT,
  IX_CLOSE_ACCOUNTS,
} from './types.js';

/**
 * Create instruction to initialize a VK buffer
 */
export function createInitVKBufferInstruction(
  programId: PublicKey,
  vkAccount: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    keys: [{ pubkey: vkAccount, isSigner: false, isWritable: true }],
    programId,
    data: Buffer.from([IX_INIT_VK_BUFFER]),
  });
}

/**
 * Create instruction to upload a VK chunk
 */
export function createUploadVKChunkInstruction(
  programId: PublicKey,
  vkAccount: PublicKey,
  offset: number,
  chunk: Buffer
): TransactionInstruction {
  const data = Buffer.alloc(3 + chunk.length);
  data[0] = IX_UPLOAD_VK_CHUNK;
  data.writeUInt16LE(offset, 1);
  chunk.copy(data, 3);

  return new TransactionInstruction({
    keys: [{ pubkey: vkAccount, isSigner: false, isWritable: true }],
    programId,
    data,
  });
}

/**
 * Create instruction to initialize a proof buffer
 */
export function createInitBufferInstruction(
  programId: PublicKey,
  proofAccount: PublicKey,
  numPublicInputs: number
): TransactionInstruction {
  const data = Buffer.alloc(3);
  data[0] = IX_INIT_BUFFER;
  data.writeUInt16LE(numPublicInputs, 1);

  return new TransactionInstruction({
    keys: [{ pubkey: proofAccount, isSigner: false, isWritable: true }],
    programId,
    data,
  });
}

/**
 * Create instruction to upload a proof chunk
 */
export function createUploadChunkInstruction(
  programId: PublicKey,
  proofAccount: PublicKey,
  offset: number,
  chunk: Buffer
): TransactionInstruction {
  const data = Buffer.alloc(3 + chunk.length);
  data[0] = IX_UPLOAD_CHUNK;
  data.writeUInt16LE(offset, 1);
  chunk.copy(data, 3);

  return new TransactionInstruction({
    keys: [{ pubkey: proofAccount, isSigner: false, isWritable: true }],
    programId,
    data,
  });
}

/**
 * Create instruction to set public inputs
 */
export function createSetPublicInputsInstruction(
  programId: PublicKey,
  proofAccount: PublicKey,
  publicInputs: Buffer
): TransactionInstruction {
  const data = Buffer.alloc(1 + publicInputs.length);
  data[0] = IX_SET_PUBLIC_INPUTS;
  publicInputs.copy(data, 1);

  return new TransactionInstruction({
    keys: [{ pubkey: proofAccount, isSigner: false, isWritable: true }],
    programId,
    data,
  });
}

/**
 * Create Phase 1 instruction (challenge generation)
 */
export function createPhase1Instruction(
  programId: PublicKey,
  stateAccount: PublicKey,
  proofAccount: PublicKey,
  vkAccount: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    keys: [
      { pubkey: stateAccount, isSigner: false, isWritable: true },
      { pubkey: proofAccount, isSigner: false, isWritable: false },
      { pubkey: vkAccount, isSigner: false, isWritable: false },
    ],
    programId,
    data: Buffer.from([IX_PHASE1_FULL]),
  });
}

/**
 * Create Phase 2 sumcheck rounds instruction
 */
export function createPhase2RoundsInstruction(
  programId: PublicKey,
  stateAccount: PublicKey,
  proofAccount: PublicKey,
  startRound: number,
  endRound: number
): TransactionInstruction {
  return new TransactionInstruction({
    keys: [
      { pubkey: stateAccount, isSigner: false, isWritable: true },
      { pubkey: proofAccount, isSigner: false, isWritable: false },
    ],
    programId,
    data: Buffer.from([IX_PHASE2_ROUNDS, startRound, endRound]),
  });
}

/**
 * Create Phase 2d relations instruction
 */
export function createPhase2RelationsInstruction(
  programId: PublicKey,
  stateAccount: PublicKey,
  proofAccount: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    keys: [
      { pubkey: stateAccount, isSigner: false, isWritable: true },
      { pubkey: proofAccount, isSigner: false, isWritable: false },
    ],
    programId,
    data: Buffer.from([IX_PHASE2D_RELATIONS]),
  });
}

/**
 * Create Phase 3a weights instruction
 */
export function createPhase3aInstruction(
  programId: PublicKey,
  stateAccount: PublicKey,
  proofAccount: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    keys: [
      { pubkey: stateAccount, isSigner: false, isWritable: true },
      { pubkey: proofAccount, isSigner: false, isWritable: false },
    ],
    programId,
    data: Buffer.from([IX_PHASE3A_WEIGHTS]),
  });
}

/**
 * Create Phase 3b1 folding instruction
 */
export function createPhase3b1Instruction(
  programId: PublicKey,
  stateAccount: PublicKey,
  proofAccount: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    keys: [
      { pubkey: stateAccount, isSigner: false, isWritable: true },
      { pubkey: proofAccount, isSigner: false, isWritable: false },
    ],
    programId,
    data: Buffer.from([IX_PHASE3B1_FOLDING]),
  });
}

/**
 * Create Phase 3b2 gemini instruction
 */
export function createPhase3b2Instruction(
  programId: PublicKey,
  stateAccount: PublicKey,
  proofAccount: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    keys: [
      { pubkey: stateAccount, isSigner: false, isWritable: true },
      { pubkey: proofAccount, isSigner: false, isWritable: false },
    ],
    programId,
    data: Buffer.from([IX_PHASE3B2_GEMINI]),
  });
}

/**
 * Create Phase 3c + 4 combined (MSM + Pairing) instruction
 */
export function createPhase3cAndPairingInstruction(
  programId: PublicKey,
  stateAccount: PublicKey,
  proofAccount: PublicKey,
  vkAccount: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    keys: [
      { pubkey: stateAccount, isSigner: false, isWritable: true },
      { pubkey: proofAccount, isSigner: false, isWritable: false },
      { pubkey: vkAccount, isSigner: false, isWritable: false },
    ],
    programId,
    data: Buffer.from([IX_PHASE3C_AND_PAIRING]),
  });
}

/**
 * Create combined Phase 2d+3a instruction (Relations + Weights)
 * Saves 1 TX by combining relations check with weight computation
 */
export function createPhase2dAnd3aInstruction(
  programId: PublicKey,
  stateAccount: PublicKey,
  proofAccount: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    keys: [
      { pubkey: stateAccount, isSigner: false, isWritable: true },
      { pubkey: proofAccount, isSigner: false, isWritable: false },
    ],
    programId,
    data: Buffer.from([IX_PHASE2D_AND_3A]),
  });
}

/**
 * Create combined Phase 3b instruction (Folding + Gemini)
 * Saves 1 TX by combining folding with gemini computation
 */
export function createPhase3bCombinedInstruction(
  programId: PublicKey,
  stateAccount: PublicKey,
  proofAccount: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    keys: [
      { pubkey: stateAccount, isSigner: false, isWritable: true },
      { pubkey: proofAccount, isSigner: false, isWritable: false },
    ],
    programId,
    data: Buffer.from([IX_PHASE3B_COMBINED]),
  });
}

/**
 * Create account with rent exemption
 */
export function createAccountInstruction(
  payer: PublicKey,
  newAccount: PublicKey,
  lamports: number,
  space: number,
  programId: PublicKey
): TransactionInstruction {
  return SystemProgram.createAccount({
    fromPubkey: payer,
    newAccountPubkey: newAccount,
    lamports,
    space,
    programId,
  });
}

/**
 * Create verification receipt PDA instruction
 * 
 * Accounts:
 * 0. state_account (readonly) - Must be in Complete phase
 * 1. proof_account (readonly) - For extracting public inputs hash
 * 2. vk_account (readonly) - For PDA derivation
 * 3. receipt_pda (writable) - PDA to create
 * 4. payer (signer) - Pays for account creation
 * 5. system_program - For CPI
 */
export function createReceiptInstruction(
  programId: PublicKey,
  stateAccount: PublicKey,
  proofAccount: PublicKey,
  vkAccount: PublicKey,
  receiptPda: PublicKey,
  payer: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    keys: [
      { pubkey: stateAccount, isSigner: false, isWritable: false },
      { pubkey: proofAccount, isSigner: false, isWritable: false },
      { pubkey: vkAccount, isSigner: false, isWritable: false },
      { pubkey: receiptPda, isSigner: false, isWritable: true },
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId,
    data: Buffer.from([IX_CREATE_RECEIPT]),
  });
}

/**
 * Create close accounts instruction to recover rent
 * 
 * Accounts:
 * 0. state_account (writable) - Must be Complete or Failed
 * 1. proof_account (writable) - Proof buffer to close
 * 2. payer (signer, writable) - Receives recovered lamports
 */
export function createCloseAccountsInstruction(
  programId: PublicKey,
  stateAccount: PublicKey,
  proofAccount: PublicKey,
  payer: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    keys: [
      { pubkey: stateAccount, isSigner: false, isWritable: true },
      { pubkey: proofAccount, isSigner: false, isWritable: true },
      { pubkey: payer, isSigner: true, isWritable: true },
    ],
    programId,
    data: Buffer.from([IX_CLOSE_ACCOUNTS]),
  });
}


