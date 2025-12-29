import { PublicKey, TransactionSignature } from '@solana/web3.js';

/**
 * Configuration for the Solana Noir Verifier client
 */
export interface VerifierConfig {
  /** The deployed verifier program ID */
  programId: PublicKey;
  /** Optional: Compute unit limit per transaction (default: 1,400,000) */
  computeUnitLimit?: number;
  /** Optional: Chunk size for proof uploads (default: 1020 bytes) */
  chunkSize?: number;
}

/**
 * Result of uploading a VK to the chain
 */
export interface VKUploadResult {
  /** The VK account public key (save this for proof verification) */
  vkAccount: PublicKey;
  /** Transaction signatures for the upload */
  signatures: TransactionSignature[];
  /** Number of chunks uploaded */
  numChunks: number;
}

/**
 * Result of a proof verification
 */
export interface VerificationResult {
  /** Whether the proof was successfully verified */
  verified: boolean;
  /** The state account containing verification status */
  stateAccount: PublicKey;
  /** The proof buffer account */
  proofAccount: PublicKey;
  /** Total compute units consumed across verification phases */
  totalCUs: number;
  /** Number of transactions for this proof (setup + upload + phases) */
  numTransactions: number;
  /** Number of sequential steps (parallel uploads count as 1) */
  numSteps: number;
  /** All transaction signatures */
  signatures: TransactionSignature[];
  /** Per-phase CU breakdown (only if verbose: true) */
  phases?: PhaseResult[];
  /** Lamports recovered from closing accounts (if autoClose was enabled) */
  recoveredLamports?: number;
  /** Whether accounts were closed (if autoClose was enabled) */
  accountsClosed?: boolean;
}

/**
 * Progress callback for long-running operations
 */
export interface ProgressCallback {
  (phase: string, current: number, total: number): void;
}

/**
 * Per-phase CU breakdown
 */
export interface PhaseResult {
  name: string;
  cus: number;
}

/**
 * Options for proof verification
 */
export interface VerifyOptions {
  /** Optional progress callback for UI updates */
  onProgress?: ProgressCallback;
  /** Skip preflight simulation (faster but less safe) */
  skipPreflight?: boolean;
  /** Enable verbose mode - returns detailed per-phase CU breakdown */
  verbose?: boolean;
  /** Automatically close accounts after verification to reclaim rent (default: true) */
  autoClose?: boolean;
}

/**
 * Verification phase status (from on-chain state)
 */
export enum VerificationPhase {
  NotStarted = 0,
  ChallengesGenerated = 1,
  SumcheckComplete = 2,
  MSMComplete = 3,
  PairingComplete = 4,
  Verified = 5,
  Failed = 255,
}

/**
 * Parsed verification state from on-chain account
 */
export interface VerificationState {
  phase: VerificationPhase;
  logN: number;
  verified: boolean;
}

// Constants matching the on-chain program
export const PROOF_SIZE = 16224;
export const VK_SIZE = 1760;
export const BUFFER_HEADER_SIZE = 9; // status(1) + proof_len(2) + pi_count(2) + chunk_bitmap(4)
export const VK_HEADER_SIZE = 3;
export const STATE_SIZE = 6408;
export const DEFAULT_CHUNK_SIZE = 1020;
export const DEFAULT_COMPUTE_UNIT_LIMIT = 1_400_000;

// Instruction codes
export const IX_INIT_BUFFER = 0;
export const IX_UPLOAD_CHUNK = 1;
export const IX_SET_PUBLIC_INPUTS = 3;
export const IX_INIT_VK_BUFFER = 4;
export const IX_UPLOAD_VK_CHUNK = 5;
export const IX_PHASE1_FULL = 30;
export const IX_PHASE2_ROUNDS = 40;
export const IX_PHASE2D_RELATIONS = 43;
export const IX_PHASE3A_WEIGHTS = 50;
export const IX_PHASE3B1_FOLDING = 51;
export const IX_PHASE3B2_GEMINI = 52;
export const IX_PHASE3C_AND_PAIRING = 54;
export const IX_PHASE2D_AND_3A = 55; // Combined: Relations + Weights
export const IX_PHASE3B_COMBINED = 56; // Combined: Folding + Gemini
export const IX_CREATE_RECEIPT = 60;
export const IX_CLOSE_ACCOUNTS = 70;

// Receipt PDA constants
export const RECEIPT_SEED = 'receipt';
export const RECEIPT_SIZE = 16; // slot (8) + timestamp (8)

