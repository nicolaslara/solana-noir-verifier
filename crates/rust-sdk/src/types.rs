//! Types and constants for the Solana Noir Verifier SDK

use solana_sdk::{pubkey::Pubkey, signature::Signature};

/// Configuration for the Solana Noir Verifier client
#[derive(Clone)]
pub struct VerifierConfig {
    /// The deployed verifier program ID
    pub program_id: Pubkey,
    /// Compute unit limit per transaction (default: 1,400,000)
    pub compute_unit_limit: u32,
    /// Chunk size for proof uploads (default: 1020 bytes)
    pub chunk_size: usize,
}

impl VerifierConfig {
    /// Create a new config with default values
    pub fn new(program_id: Pubkey) -> Self {
        Self {
            program_id,
            compute_unit_limit: DEFAULT_COMPUTE_UNIT_LIMIT,
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }

    /// Set custom compute unit limit
    pub fn with_compute_unit_limit(mut self, limit: u32) -> Self {
        self.compute_unit_limit = limit;
        self
    }

    /// Set custom chunk size
    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }
}

/// Result of uploading a VK to the chain
#[derive(Debug, Clone)]
pub struct VkUploadResult {
    /// The VK account public key (save this for proof verification)
    pub vk_account: Pubkey,
    /// Transaction signatures for the upload
    pub signatures: Vec<Signature>,
    /// Number of chunks uploaded
    pub num_chunks: usize,
}

/// Result of a proof verification
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the proof was successfully verified
    pub verified: bool,
    /// The state account containing verification status
    pub state_account: Pubkey,
    /// The proof buffer account
    pub proof_account: Pubkey,
    /// Total compute units consumed across verification phases
    pub total_cus: u64,
    /// Number of transactions for this proof (setup + upload + phases)
    pub num_transactions: usize,
    /// Number of sequential steps (parallel uploads count as 1)
    pub num_steps: usize,
    /// All transaction signatures
    pub signatures: Vec<Signature>,
    /// Lamports recovered from closing accounts (if auto_close was enabled)
    pub recovered_lamports: Option<u64>,
    /// Whether accounts were closed (if auto_close was enabled)
    pub accounts_closed: bool,
}

/// Options for proof verification
#[derive(Clone)]
pub struct VerifyOptions {
    /// Skip preflight simulation (faster but less safe)
    pub skip_preflight: bool,
    /// Automatically close accounts after verification to reclaim rent (default: true)
    pub auto_close: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            skip_preflight: false,
            auto_close: true, // Default is to auto-close and reclaim rent
        }
    }
}

impl VerifyOptions {
    /// Create default options (auto_close = true)
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable auto-close
    pub fn without_auto_close(mut self) -> Self {
        self.auto_close = false;
        self
    }

    /// Enable skip preflight
    pub fn with_skip_preflight(mut self) -> Self {
        self.skip_preflight = true;
        self
    }
}

/// Verification phase status (from on-chain state)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VerificationPhase {
    NotStarted = 0,
    ChallengesGenerated = 1,
    SumcheckComplete = 2,
    MsmComplete = 3,
    PairingComplete = 4,
    Verified = 5,
    Failed = 255,
}

/// Parsed verification state from on-chain account
#[derive(Debug, Clone)]
pub struct VerificationState {
    pub phase: VerificationPhase,
    pub log_n: u8,
    pub verified: bool,
}

/// Receipt information
#[derive(Debug, Clone)]
pub struct ReceiptInfo {
    /// The receipt PDA public key
    pub receipt_pda: Pubkey,
    /// Slot when the proof was verified
    pub verified_slot: u64,
    /// Unix timestamp when the proof was verified
    pub verified_timestamp: i64,
}

// =============================================================================
// Constants matching the on-chain program
// =============================================================================

/// ZK proof size for bb 0.87 (fixed size)
pub const PROOF_SIZE: usize = 16224;

/// VK size for bb 0.87
pub const VK_SIZE: usize = 1760;

/// Header size in proof buffer: status(1) + proof_len(2) + pi_count(2) + chunk_bitmap(4)
pub const BUFFER_HEADER_SIZE: usize = 9;

/// Header size in VK buffer: status(1) + vk_len(2)
pub const VK_HEADER_SIZE: usize = 3;

/// Verification state account size
/// Includes: header + challenges + sumcheck state + vk_account field
pub const STATE_SIZE: usize = 6408;

/// Default chunk size for uploads
pub const DEFAULT_CHUNK_SIZE: usize = 1020;

/// Default compute unit limit per transaction
pub const DEFAULT_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

/// Receipt size (slot + timestamp)
pub const RECEIPT_SIZE: usize = 16;

/// Receipt PDA seed
pub const RECEIPT_SEED: &[u8] = b"receipt";

// =============================================================================
// Instruction codes
// =============================================================================

pub const IX_INIT_BUFFER: u8 = 0;
pub const IX_UPLOAD_CHUNK: u8 = 1;
pub const IX_SET_PUBLIC_INPUTS: u8 = 3;
pub const IX_INIT_VK_BUFFER: u8 = 4;
pub const IX_UPLOAD_VK_CHUNK: u8 = 5;
pub const IX_PHASE1_FULL: u8 = 30;
pub const IX_PHASE2_ROUNDS: u8 = 40;
pub const IX_PHASE2D_RELATIONS: u8 = 43;
pub const IX_PHASE3A_WEIGHTS: u8 = 50;
pub const IX_PHASE3B1_FOLDING: u8 = 51;
pub const IX_PHASE3B2_GEMINI: u8 = 52;
pub const IX_PHASE3C_AND_PAIRING: u8 = 54;
pub const IX_PHASE2D_AND_3A: u8 = 55;
pub const IX_PHASE3B_COMBINED: u8 = 56;
pub const IX_CREATE_RECEIPT: u8 = 60;
pub const IX_CLOSE_ACCOUNTS: u8 = 70;
