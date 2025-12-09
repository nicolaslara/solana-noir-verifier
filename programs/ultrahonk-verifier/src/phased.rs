//! Phased verification for UltraHonk proofs
//!
//! Splits verification across multiple transactions to fit within Solana's 1.4M CU limit.
//!
//! ## Challenge Generation Sub-Phases (each ~200-400K CUs)
//! - **1a**: eta, beta/gamma challenges
//! - **1b**: alpha + gate challenges  
//! - **1c**: sumcheck rounds 0-13
//! - **1d**: sumcheck rounds 14-27 + remaining challenges
//! - **1e**: public_input_delta computation
//!
//! ## Main Phases
//! 2. **VerifySumcheck**: Verify sumcheck protocol
//! 3. **ComputeMSM**: Shplemini MSM to get P0/P1
//! 4. **FinalCheck**: Pairing verification

/// Verification phase
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Phase {
    Uninitialized = 0,
    /// Challenge generation in progress (check sub_phase)
    ChallengesInProgress = 1,
    ChallengesGenerated = 2,
    SumcheckVerified = 3,
    MsmComputed = 4,
    Complete = 5,
    Failed = 255,
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
    /// public_input_delta computed, ready for next phase
    DeltaComputed = 5,
}

impl From<u8> for Phase {
    fn from(v: u8) -> Self {
        match v {
            0 => Phase::Uninitialized,
            1 => Phase::ChallengesInProgress,
            2 => Phase::ChallengesGenerated,
            3 => Phase::SumcheckVerified,
            4 => Phase::MsmComputed,
            5 => Phase::Complete,
            _ => Phase::Failed,
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
            5 => ChallengeSubPhase::DeltaComputed,
            _ => ChallengeSubPhase::NotStarted,
        }
    }
}

/// State account layout for phased verification
///
/// Total size: ~4 KB
#[repr(C)]
pub struct VerificationState {
    /// Current phase (1 byte)
    pub phase: u8,

    /// Challenge sub-phase (1 byte)
    pub challenge_sub_phase: u8,

    /// Log2 of circuit size (1 byte)
    pub log_n: u8,

    /// Is ZK proof (1 byte)
    pub is_zk: u8,

    /// Number of public inputs (2 bytes)
    pub num_public_inputs: u16,

    /// Reserved (2 bytes)
    pub _reserved: u16,

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

    // === Sumcheck result (Phase 3 output) ===
    pub sumcheck_passed: u8,
    pub _sumcheck_padding: [u8; 31],

    // === P0/P1 (Phase 4 output) ===
    pub p0: [u8; 64], // G1 point
    pub p1: [u8; 64], // G1 point

    // === Final result (Phase 5 output) ===
    pub verified: u8,
    pub _final_padding: [u8; 31],
}

impl VerificationState {
    /// Size of the state account in bytes
    pub const SIZE: usize = 
        8 +           // header (phase, challenge_sub_phase, log_n, is_zk, num_pi, reserved)
        32 +          // transcript_state
        192 +         // relation_params (eta, eta_two, eta_three, beta, gamma, public_input_delta)
        800 +         // alphas (25 × 32)
        896 +         // gate_challenges (28 × 32)
        896 +         // sumcheck_challenges (28 × 32)
        160 +         // other challenges (libra, rho, gemini_r, shplonk_nu, shplonk_z)
        32 +          // sumcheck_passed + padding
        128 +         // P0 + P1
        32;           // verified + padding
                      // Total: 3176 bytes

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
}

// Verify the size at compile time
const _: () = assert!(VerificationState::SIZE == 3176);

/// Account indices for phased verification instructions
pub mod accounts {
    /// State account (writable)
    pub const STATE: usize = 0;
    /// Proof data account (read-only)  
    pub const PROOF_DATA: usize = 1;
    /// VK account (read-only) - optional if VK is embedded
    pub const VK: usize = 2;
}
