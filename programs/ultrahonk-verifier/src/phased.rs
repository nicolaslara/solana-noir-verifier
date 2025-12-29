//! Phased verification for UltraHonk proofs
//!
//! Splits verification across multiple transactions to fit within Solana's 1.4M CU limit.
//!
//! ## Challenge Generation Sub-Phases (each ~100-150K CUs after Montgomery)
//! - **1a**: eta, beta/gamma challenges
//! - **1b**: alpha + gate challenges  
//! - **1c**: sumcheck rounds 0-13
//! - **1d**: sumcheck rounds 14-27 + remaining challenges
//! - **1e1/1e2**: public_input_delta computation
//!
//! ## Sumcheck Sub-Phases (each ~500K CUs)
//! - **2a**: Rounds 0-9
//! - **2b**: Rounds 10-19
//! - **2c**: Rounds 20-27
//! - **2d**: Relations + final check
//!
//! ## Main Phases
//! 3. **ComputeMSM**: Shplemini MSM to get P0/P1
//! 4. **FinalCheck**: Pairing verification

/// Verification phase
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Phase {
    Uninitialized = 0,
    /// Challenge generation in progress (check challenge_sub_phase)
    ChallengesInProgress = 1,
    ChallengesGenerated = 2,
    /// Sumcheck rounds in progress (check sumcheck_sub_phase)
    SumcheckInProgress = 3,
    SumcheckVerified = 4,
    /// MSM computation in progress (check shplemini_sub_phase)
    MsmInProgress = 5,
    MsmComputed = 6,
    Complete = 7,
    Failed = 255,
}

/// Sub-phases for Shplemini MSM computation
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ShpleminiSubPhase {
    /// Not started
    NotStarted = 0,
    /// Phase 3a done: weights + scalar accumulation
    Phase3aDone = 1,
    /// Phase 3b1 done: folding only
    Phase3b1Done = 2,
    /// Phase 3b2 done: gemini + libra
    Phase3b2Done = 3,
    /// Phase 3c done: MSM complete
    Complete = 4,
}

/// Sub-phases for challenge generation
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ChallengeSubPhase {
    /// Ready to start (no challenges generated yet)
    NotStarted = 0,
    /// eta, beta/gamma done
    EtaBetaGammaDone = 1,
    /// alphas + gate challenges done
    AlphasGatesDone = 2,
    /// sumcheck rounds 0-13 done
    SumcheckHalfDone = 3,
    /// all sumcheck + remaining challenges done
    AllChallengesDone = 4,
    /// delta part 1 done (partial accumulators saved)
    DeltaPart1Done = 5,
    /// public_input_delta computed, ready for next phase
    DeltaComputed = 6,
}

impl From<u8> for Phase {
    fn from(v: u8) -> Self {
        match v {
            0 => Phase::Uninitialized,
            1 => Phase::ChallengesInProgress,
            2 => Phase::ChallengesGenerated,
            3 => Phase::SumcheckInProgress,
            4 => Phase::SumcheckVerified,
            5 => Phase::MsmInProgress,
            6 => Phase::MsmComputed,
            7 => Phase::Complete,
            _ => Phase::Failed,
        }
    }
}

impl From<u8> for ShpleminiSubPhase {
    fn from(v: u8) -> Self {
        match v {
            0 => ShpleminiSubPhase::NotStarted,
            1 => ShpleminiSubPhase::Phase3aDone,
            2 => ShpleminiSubPhase::Phase3b1Done,
            3 => ShpleminiSubPhase::Phase3b2Done,
            4 => ShpleminiSubPhase::Complete,
            _ => ShpleminiSubPhase::NotStarted,
        }
    }
}

impl From<u8> for ChallengeSubPhase {
    fn from(v: u8) -> Self {
        match v {
            0 => ChallengeSubPhase::NotStarted,
            1 => ChallengeSubPhase::EtaBetaGammaDone,
            2 => ChallengeSubPhase::AlphasGatesDone,
            3 => ChallengeSubPhase::SumcheckHalfDone,
            4 => ChallengeSubPhase::AllChallengesDone,
            5 => ChallengeSubPhase::DeltaPart1Done,
            6 => ChallengeSubPhase::DeltaComputed,
            _ => ChallengeSubPhase::NotStarted,
        }
    }
}

/// Sub-phases for sumcheck verification (Phase 2)
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SumcheckSubPhase {
    /// Ready to start (no rounds verified yet)
    NotStarted = 0,
    /// Rounds 0-9 verified
    Rounds0to9Done = 1,
    /// Rounds 10-19 verified
    Rounds10to19Done = 2,
    /// All rounds (0-27) verified
    AllRoundsDone = 3,
    /// Relations accumulated, verification complete
    RelationsDone = 4,
}

impl From<u8> for SumcheckSubPhase {
    fn from(v: u8) -> Self {
        match v {
            0 => SumcheckSubPhase::NotStarted,
            1 => SumcheckSubPhase::Rounds0to9Done,
            2 => SumcheckSubPhase::Rounds10to19Done,
            3 => SumcheckSubPhase::AllRoundsDone,
            4 => SumcheckSubPhase::RelationsDone,
            _ => SumcheckSubPhase::NotStarted,
        }
    }
}

/// State account layout for phased verification
///
/// Total size: ~6.4 KB
#[repr(C)]
pub struct VerificationState {
    /// Current phase (1 byte)
    pub phase: u8,

    /// Challenge sub-phase (1 byte)
    pub challenge_sub_phase: u8,

    /// Sumcheck sub-phase (1 byte)
    pub sumcheck_sub_phase: u8,

    /// Log2 of circuit size (1 byte)
    pub log_n: u8,

    /// Is ZK proof (1 byte)
    pub is_zk: u8,

    /// Number of public inputs (1 byte) - max 255
    pub num_public_inputs: u8,

    /// Reserved (2 bytes)
    pub _reserved: u16,

    /// VK account pubkey - stored in Phase 1, validated in Phase 3c
    /// This prevents using different VKs across phases (security critical!)
    pub vk_account: [u8; 32],

    /// Transcript state - the "previous challenge" from Fiat-Shamir chain (32 bytes)
    /// This allows resuming challenge generation across transactions
    pub transcript_state: [u8; 32],

    // === Challenges (Phase 2 output) ===
    // RelationParameters: 6 × 32 = 192 bytes
    pub eta: [u8; 32],
    pub eta_two: [u8; 32],
    pub eta_three: [u8; 32],
    pub beta: [u8; 32],
    pub gamma: [u8; 32],
    pub public_input_delta: [u8; 32],

    // Alphas: 25 × 32 = 800 bytes
    pub alphas: [[u8; 32]; 25],

    // Gate challenges: 28 × 32 = 896 bytes (CONST_PROOF_SIZE_LOG_N)
    pub gate_challenges: [[u8; 32]; 28],

    // Sumcheck challenges: 28 × 32 = 896 bytes
    pub sumcheck_challenges: [[u8; 32]; 28],

    // Other challenges: 5 × 32 = 160 bytes
    pub libra_challenge: [u8; 32],
    pub rho: [u8; 32],
    pub gemini_r: [u8; 32],
    pub shplonk_nu: [u8; 32],
    pub shplonk_z: [u8; 32],

    // === Partial delta computation (between 1e1 and 1e2) ===
    // 4 × 32 = 128 bytes
    pub delta_numerator: [u8; 32],
    pub delta_denominator: [u8; 32],
    pub delta_numerator_acc: [u8; 32],
    pub delta_denominator_acc: [u8; 32],

    // === Sumcheck rounds intermediate state ===
    // 2 × 32 + 1 = 65 bytes (padded to 96)
    pub sumcheck_target: [u8; 32],
    pub sumcheck_pow_partial: [u8; 32],
    pub sumcheck_rounds_completed: u8,
    pub _sumcheck_rounds_padding: [u8; 31],

    // === Sumcheck result (Phase 3 output) ===
    pub sumcheck_passed: u8,
    pub _sumcheck_padding: [u8; 31],

    // === Shplemini intermediate state (Phase 3a output) ===
    /// r^(2^i) powers - 28 Fr = 896 bytes
    pub shplemini_r_pows: [[u8; 32]; 28],
    /// pos0 = 1/(z - r)
    pub shplemini_pos0: [u8; 32],
    /// neg0 = 1/(z + r)
    pub shplemini_neg0: [u8; 32],
    /// unshifted scalar
    pub shplemini_unshifted: [u8; 32],
    /// shifted scalar
    pub shplemini_shifted: [u8; 32],
    /// eval_acc accumulator
    pub shplemini_eval_acc: [u8; 32],

    // === Shplemini intermediate state (Phase 3b1 output) ===
    /// fold_pos - up to 28 Fr (log_n max) = 896 bytes
    pub shplemini_fold_pos: [[u8; 32]; 28],
    /// const_acc accumulator (from Phase 3b1)
    pub shplemini_const_acc: [u8; 32],

    // === Shplemini intermediate state (Phase 3b2 output) ===
    /// gemini_scalars - 27 Fr = 864 bytes
    pub shplemini_gemini_scalars: [[u8; 32]; 27],
    /// libra_scalars - 3 Fr = 96 bytes  
    pub shplemini_libra_scalars: [[u8; 32]; 3],
    /// Shplemini sub-phase tracker
    pub shplemini_sub_phase: u8,
    pub _shplemini_padding: [u8; 31],

    // === P0/P1 (Phase 3c output) ===
    pub p0: [u8; 64], // G1 point
    pub p1: [u8; 64], // G1 point

    // === Final result (Phase 4 output) ===
    pub verified: u8,
    pub _final_padding: [u8; 31],
}

impl VerificationState {
    /// Size of the state account in bytes
    pub const SIZE: usize = 8 +           // header (phase, challenge_sub_phase, sumcheck_sub_phase, log_n, is_zk, num_pi, reserved)
        32 +          // vk_account (stored in Phase 1, validated in Phase 3c)
        32 +          // transcript_state
        192 +         // relation_params (eta, eta_two, eta_three, beta, gamma, public_input_delta)
        800 +         // alphas (25 × 32)
        896 +         // gate_challenges (28 × 32)
        896 +         // sumcheck_challenges (28 × 32)
        160 +         // other challenges (libra, rho, gemini_r, shplonk_nu, shplonk_z)
        128 +         // partial delta (4 × 32)
        96 +          // sumcheck rounds intermediate (target, pow_partial, rounds_completed + padding)
        32 +          // sumcheck_passed + padding
        // Shplemini Phase 3a intermediate state:
        896 +         // r_pows (28 × 32)
        32 +          // pos0
        32 +          // neg0
        32 +          // unshifted
        32 +          // shifted
        32 +          // eval_acc
        // Shplemini Phase 3b1 intermediate state:
        896 +         // fold_pos (28 × 32)
        32 +          // const_acc
        // Shplemini Phase 3b2 intermediate state:
        864 +         // gemini_scalars (27 × 32)
        96 +          // libra_scalars (3 × 32)
        32 +          // shplemini_sub_phase + padding
        // Final outputs:
        128 +         // P0 + P1
        32; // verified + padding
            // Total: 6408 bytes

    /// Initialize state from account data
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        // SAFETY: We've verified the size and the struct is repr(C)
        Some(unsafe { &*(data.as_ptr() as *const Self) })
    }

    /// Get mutable reference to state from account data
    pub fn from_bytes_mut(data: &mut [u8]) -> Option<&mut Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        // SAFETY: We've verified the size and the struct is repr(C)
        Some(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    /// Get current phase
    pub fn get_phase(&self) -> Phase {
        Phase::from(self.phase)
    }

    /// Set phase
    pub fn set_phase(&mut self, phase: Phase) {
        self.phase = phase as u8;
    }

    /// Get current challenge sub-phase
    pub fn get_challenge_sub_phase(&self) -> ChallengeSubPhase {
        ChallengeSubPhase::from(self.challenge_sub_phase)
    }

    /// Set challenge sub-phase
    pub fn set_challenge_sub_phase(&mut self, sub_phase: ChallengeSubPhase) {
        self.challenge_sub_phase = sub_phase as u8;
    }

    /// Get current sumcheck sub-phase
    pub fn get_sumcheck_sub_phase(&self) -> SumcheckSubPhase {
        SumcheckSubPhase::from(self.sumcheck_sub_phase)
    }

    /// Set sumcheck sub-phase
    pub fn set_sumcheck_sub_phase(&mut self, sub_phase: SumcheckSubPhase) {
        self.sumcheck_sub_phase = sub_phase as u8;
    }

    /// Get current shplemini sub-phase
    pub fn get_shplemini_sub_phase(&self) -> ShpleminiSubPhase {
        ShpleminiSubPhase::from(self.shplemini_sub_phase)
    }

    /// Set shplemini sub-phase
    pub fn set_shplemini_sub_phase(&mut self, sub_phase: ShpleminiSubPhase) {
        self.shplemini_sub_phase = sub_phase as u8;
    }
}

// Verify the size at compile time
const _: () = assert!(VerificationState::SIZE == 6408);

/// Account indices for phased verification instructions
pub mod accounts {
    /// State account (writable)
    pub const STATE: usize = 0;
    /// Proof data account (read-only)  
    pub const PROOF_DATA: usize = 1;
    /// VK account (read-only) - optional if VK is embedded
    pub const VK: usize = 2;
}

// ============================================================================
// Verification Receipt (PDA for proof identification)
// ============================================================================

/// PDA seed for verification receipts
pub const RECEIPT_SEED: &[u8] = b"receipt";

/// Verification Receipt - persistent record that a proof was verified
///
/// PDA derivation: `["receipt", vk_account, keccak(public_inputs)]`
///
/// The VK account and PI hash are encoded in the PDA address itself,
/// so we only store timing information in the account data.
///
/// To check if a proof was verified:
/// 1. Compute the expected PDA from (vk_account, pi_hash)
/// 2. Check if the account exists at that address
/// 3. Read the timing data if needed
#[repr(C)]
pub struct VerificationReceipt {
    /// Slot when verification completed
    pub verified_slot: u64,
    /// Unix timestamp when verification completed
    pub verified_timestamp: i64,
}

impl VerificationReceipt {
    /// Size of the receipt account in bytes (16 bytes)
    pub const SIZE: usize = 8 + 8; // slot + timestamp

    /// Initialize from account data
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(unsafe { &*(data.as_ptr() as *const Self) })
    }

    /// Get mutable reference from account data
    pub fn from_bytes_mut(data: &mut [u8]) -> Option<&mut Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }
}

// Verify the size at compile time
const _: () = assert!(VerificationReceipt::SIZE == 16);
