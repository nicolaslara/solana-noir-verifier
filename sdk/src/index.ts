/**
 * @solana-noir-verifier/sdk
 *
 * TypeScript SDK for verifying Noir UltraHonk proofs on Solana
 *
 * @example
 * ```typescript
 * import { SolanaNoirVerifier } from '@solana-noir-verifier/sdk';
 * import { Connection, Keypair, PublicKey } from '@solana/web3.js';
 * import fs from 'fs';
 *
 * const connection = new Connection('http://127.0.0.1:8899');
 * const payer = Keypair.generate();
 *
 * const verifier = new SolanaNoirVerifier(connection, {
 *   programId: new PublicKey('YOUR_PROGRAM_ID'),
 * });
 *
 * // Upload VK once per circuit
 * const vk = fs.readFileSync('./target/keccak/vk');
 * const { vkAccount } = await verifier.uploadVK(payer, vk);
 * console.log('VK Account:', vkAccount.toBase58());
 *
 * // Verify proofs
 * const proof = fs.readFileSync('./target/keccak/proof');
 * const publicInputs = [Buffer.alloc(32)]; // your public inputs
 *
 * const result = await verifier.verify(payer, proof, publicInputs, vkAccount);
 * console.log('Verified:', result.verified);
 * console.log('Total CUs:', result.totalCUs);
 * ```
 *
 * @packageDocumentation
 */

export { SolanaNoirVerifier } from './client.js';

export type {
  // Config types
  VerifierConfig,
  VKUploadResult,
  VerificationResult,
  VerifyOptions,
  ProgressCallback,
  VerificationState,
  PhaseResult,
} from './types.js';

export {
  // Enums
  VerificationPhase,
  // Constants
  PROOF_SIZE,
  VK_SIZE,
  BUFFER_HEADER_SIZE,
  VK_HEADER_SIZE,
  STATE_SIZE,
  DEFAULT_CHUNK_SIZE,
  DEFAULT_COMPUTE_UNIT_LIMIT,
  RECEIPT_SEED,
  RECEIPT_SIZE,
  // Instruction codes (for advanced use)
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
  IX_CREATE_RECEIPT,
} from './types.js';

export {
  // Instruction builders (for custom transaction building)
  createInitVKBufferInstruction,
  createUploadVKChunkInstruction,
  createInitBufferInstruction,
  createUploadChunkInstruction,
  createSetPublicInputsInstruction,
  createPhase1Instruction,
  createPhase2RoundsInstruction,
  createPhase2RelationsInstruction,
  createPhase3aInstruction,
  createPhase3b1Instruction,
  createPhase3b2Instruction,
  createPhase3cAndPairingInstruction,
  createAccountInstruction,
  // Receipt instructions
  createReceiptInstruction,
} from './instructions.js';

