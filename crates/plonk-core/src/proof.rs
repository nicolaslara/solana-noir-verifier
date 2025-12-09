//! Proof parsing for bb v0.87.0+ UltraHonk (Keccak)
//!
//! ## Key Discovery - bb 0.87 Format Changes
//!
//! bb 0.87.0 produces **fixed-size proofs** with these characteristics:
//! - G1 points are 128 bytes (4 × 32 limbed format: x_0, x_1, y_0, y_1)
//! - Arrays are padded to CONST_PROOF_SIZE_LOG_N = 28
//! - NUMBER_OF_ENTITIES = 40 (not 41)
//! - NUMBER_OF_ALPHAS = 25 (not 27)
//!
//! ## Binary Proof Format for ZK proofs (bb 0.87):
//!
//! 1. Pairing point object: 16 Fr = 512 bytes
//! 2. w1, w2, w3: 3 × 128 = 384 bytes
//! 3. lookupReadCounts, lookupReadTags, w4, lookupInverses, zPerm: 5 × 128 = 640 bytes
//! 4. libraCommitments[0]: 128 bytes
//! 5. libraSum: 32 bytes
//! 6. sumcheckUnivariates: 28 × 9 × 32 = 8064 bytes
//! 7. sumcheckEvaluations: 40 × 32 = 1280 bytes
//! 8. libraEvaluation: 32 bytes
//! 9. libraCommitments[1], libraCommitments[2]: 2 × 128 = 256 bytes
//! 10. geminiMaskingPoly: 128 bytes
//! 11. geminiMaskingEval: 32 bytes
//! 12. geminiFoldComms: 27 × 128 = 3456 bytes
//! 13. geminiAEvaluations: 28 × 32 = 896 bytes
//! 14. libraPolyEvals: 4 × 32 = 128 bytes
//! 15. shplonkQ: 128 bytes
//! 16. kzgQuotient: 128 bytes
//!
//! Total ZK proof size: 16224 bytes

use crate::errors::ProofError;
use crate::types::{Fr, G1};

extern crate alloc;
use alloc::vec::Vec;

/// Fixed proof size parameter - proofs are padded to support circuits up to 2^28 gates
pub const CONST_PROOF_SIZE_LOG_N: usize = 28;

/// Number of Fr values in pairing point object (for recursion support)
pub const NUM_PAIRING_POINT_FRS: usize = 16;

/// Number of witness commitments (w1, w2, w3, lookupReadCounts, lookupReadTags, w4, lookupInverses, zPerm)
pub const NUM_WITNESS_COMMS: usize = 8;

/// Number of all entities for sumcheck evaluations (bb 0.87)
/// Matches Solidity's NUMBER_OF_ENTITIES = 40
pub const NUM_ALL_ENTITIES: usize = 40;

/// Batched relation partial length for ZK proofs (bb 0.87)
pub const ZK_BATCHED_RELATION_PARTIAL_LENGTH: usize = 9;

/// Batched relation partial length for non-ZK proofs (bb 0.87)
pub const BATCHED_RELATION_PARTIAL_LENGTH: usize = 8;

/// Size of a limbed G1 point in bytes (4 × 32 = 128)
pub const G1_LIMBED_SIZE: usize = 128;

/// Size of Fr in bytes
pub const FR_SIZE: usize = 32;

/// Expected ZK proof size for bb 0.87 (fixed size for all circuits)
pub const EXPECTED_ZK_PROOF_SIZE: usize = 16224;

/// Expected non-ZK proof size for bb 0.87 (fixed size for all circuits)
pub const EXPECTED_NON_ZK_PROOF_SIZE: usize = 14592;

/// Convert a limbed G1 point (128 bytes) to standard G1 format (64 bytes)
///
/// Limbed format: x_0 (32) || x_1 (32) || y_0 (32) || y_1 (32)
/// Standard format: x (32) || y (32)
///
/// Reconstruction: x = x_0 | (x_1 << 136), y = y_0 | (y_1 << 136)
pub fn g1_from_limbed(limbed: &[u8; G1_LIMBED_SIZE]) -> G1 {
    let mut result = [0u8; 64];

    // x_0 is the lower 136 bits of x (stored in first 32 bytes, but only lower 17 bytes matter)
    // x_1 is the upper 120 bits of x (stored in second 32 bytes, but only lower 15 bytes matter)
    // Reconstruction: x = x_0 | (x_1 << 136)
    //
    // Since we're dealing with BN254 where coordinates are 254 bits:
    // - x_0 contains bits 0-135 (but padded to 256 bits)
    // - x_1 contains bits 136-253 (but padded to 256 bits)

    // For x coordinate:
    // The limbed representation stores x_0 and x_1 as big-endian 256-bit integers
    // x_0 = limbed[0..32], x_1 = limbed[32..64]
    // x = x_0 + (x_1 << 136)
    //
    // In big-endian bytes, this means:
    // - x_0's significant bytes are at the END (bytes 15-31 for 136 bits = 17 bytes)
    // - x_1's significant bytes are at the END (bytes 17-31 for 120 bits = 15 bytes)

    // Reconstruct x = x_0 | (x_1 << 136)
    let x = reconstruct_coordinate(&limbed[0..64]);
    result[0..32].copy_from_slice(&x);

    // Reconstruct y = y_0 | (y_1 << 136)
    let y = reconstruct_coordinate(&limbed[64..128]);
    result[32..64].copy_from_slice(&y);

    result
}

/// Reconstruct a 256-bit coordinate from limbed representation
/// Input: 64 bytes = x_0 (32 bytes) || x_1 (32 bytes)
/// Output: 32 bytes = x_0 | (x_1 << 136)
fn reconstruct_coordinate(limbs: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];

    // limbs[0..32] = x_0 (lower 136 bits, big-endian padded to 256 bits)
    // limbs[32..64] = x_1 (upper 120 bits, big-endian padded to 256 bits)

    // The shift by 136 bits = 17 bytes
    // x = x_0 + (x_1 << 136)
    //
    // In big-endian, x_1 << 136 means the lower 15 bytes of x_1 become the upper 15 bytes of x
    // and x_0's lower 17 bytes become the lower 17 bytes of x

    // Start with x_0 (copy lower 17 bytes which contain bits 0-135)
    // Big-endian: bytes 15-31 of x_0 contain the significant bits
    result[15..32].copy_from_slice(&limbs[15..32]);

    // Add x_1 << 136 (copy lower 15 bytes which contain bits 136-253)
    // Big-endian: bytes 17-31 of x_1 contain the significant bits
    // These go to bytes 0-14 of result
    for i in 0..15 {
        result[i] = limbs[32 + 17 + i];
    }

    result
}

/// Parsed UltraHonk proof with semantic structure (bb 0.87 format)
///
/// Uses zero-copy design: references account data directly instead of copying
/// to heap. This saves ~16KB of heap allocation per proof.
#[derive(Debug, Clone, Copy)]
pub struct Proof<'a> {
    /// Raw proof data as bytes (zero-copy reference to account data)
    pub raw_data: &'a [u8],

    /// log2 of circuit size (from VK, actual circuit size)
    pub log_n: usize,

    /// Whether this is a ZK proof
    pub is_zk: bool,
}

impl<'a> Proof<'a> {
    /// Calculate expected proof size in bytes for bb 0.87
    ///
    /// bb 0.87 produces fixed-size proofs padded to CONST_PROOF_SIZE_LOG_N = 28
    pub fn expected_size_bytes(is_zk: bool) -> usize {
        if is_zk {
            EXPECTED_ZK_PROOF_SIZE
        } else {
            EXPECTED_NON_ZK_PROOF_SIZE
        }
    }

    /// Calculate expected proof size in Fr elements
    pub fn expected_size(log_n: usize, is_zk: bool) -> usize {
        // For bb 0.87, the proof size is fixed regardless of log_n
        let _ = log_n; // Unused, kept for API compatibility
        Self::expected_size_bytes(is_zk) / FR_SIZE
    }

    /// Parse proof from bb 0.87 binary format (zero-copy)
    ///
    /// # Arguments
    /// * `bytes` - Raw proof bytes (borrowed, not copied!)
    /// * `log_n` - Circuit's log2 size (from VK)
    /// * `is_zk` - Whether this is a ZK proof
    ///
    /// # Zero-Copy Design
    /// This method borrows the input bytes instead of copying them to heap.
    /// The returned Proof has a lifetime tied to the input slice.
    /// This saves ~16KB of heap allocation per proof.
    pub fn from_bytes(bytes: &'a [u8], log_n: usize, is_zk: bool) -> Result<Self, ProofError> {
        let expected = Self::expected_size_bytes(is_zk);

        if bytes.len() != expected {
            return Err(ProofError::InvalidSize {
                expected,
                actual: bytes.len(),
            });
        }

        Ok(Proof {
            raw_data: bytes, // Zero-copy: just store the reference
            log_n,
            is_zk,
        })
    }

    // ========== Byte offset calculations for bb 0.87 format ==========

    /// Offset where pairing point object starts
    fn pairing_point_offset(&self) -> usize {
        0
    }

    /// Offset where witness commitments start
    fn witness_comms_offset(&self) -> usize {
        self.pairing_point_offset() + NUM_PAIRING_POINT_FRS * FR_SIZE
    }

    /// Offset where libraCommitments[0] starts (ZK only)
    fn libra_comm0_offset(&self) -> usize {
        self.witness_comms_offset() + NUM_WITNESS_COMMS * G1_LIMBED_SIZE
    }

    /// Offset where libraSum starts (ZK only)
    fn libra_sum_offset(&self) -> usize {
        self.libra_comm0_offset() + G1_LIMBED_SIZE
    }

    /// Offset where sumcheck univariates start
    fn sumcheck_univariates_offset(&self) -> usize {
        if self.is_zk {
            self.libra_sum_offset() + FR_SIZE
        } else {
            self.witness_comms_offset() + NUM_WITNESS_COMMS * G1_LIMBED_SIZE
        }
    }

    /// Offset where sumcheck evaluations start
    fn sumcheck_evals_offset(&self) -> usize {
        let univariate_len = if self.is_zk {
            ZK_BATCHED_RELATION_PARTIAL_LENGTH
        } else {
            BATCHED_RELATION_PARTIAL_LENGTH
        };
        self.sumcheck_univariates_offset() + CONST_PROOF_SIZE_LOG_N * univariate_len * FR_SIZE
    }

    /// Offset where libraEvaluation starts (ZK only)
    fn libra_eval_offset(&self) -> usize {
        self.sumcheck_evals_offset() + NUM_ALL_ENTITIES * FR_SIZE
    }

    /// Offset where libraCommitments[1] starts (ZK only)
    fn libra_comm1_offset(&self) -> usize {
        self.libra_eval_offset() + FR_SIZE
    }

    /// Offset where libraCommitments[2] starts (ZK only)
    fn libra_comm2_offset(&self) -> usize {
        self.libra_comm1_offset() + G1_LIMBED_SIZE
    }

    /// Offset where geminiMaskingPoly starts (ZK only)
    fn gemini_masking_poly_offset(&self) -> usize {
        self.libra_comm2_offset() + G1_LIMBED_SIZE
    }

    /// Offset where geminiMaskingEval starts (ZK only)
    fn gemini_masking_eval_offset(&self) -> usize {
        self.gemini_masking_poly_offset() + G1_LIMBED_SIZE
    }

    /// Offset where gemini fold commitments start
    fn gemini_fold_comms_offset(&self) -> usize {
        if self.is_zk {
            self.gemini_masking_eval_offset() + FR_SIZE
        } else {
            self.sumcheck_evals_offset() + NUM_ALL_ENTITIES * FR_SIZE
        }
    }

    /// Offset where gemini A evaluations start
    fn gemini_a_evals_offset(&self) -> usize {
        self.gemini_fold_comms_offset() + (CONST_PROOF_SIZE_LOG_N - 1) * G1_LIMBED_SIZE
    }

    /// Offset where libraPolyEvals start (ZK only)
    fn libra_poly_evals_offset(&self) -> usize {
        self.gemini_a_evals_offset() + CONST_PROOF_SIZE_LOG_N * FR_SIZE
    }

    /// Offset where shplonkQ starts
    fn shplonk_q_offset(&self) -> usize {
        if self.is_zk {
            self.libra_poly_evals_offset() + 4 * FR_SIZE
        } else {
            self.gemini_a_evals_offset() + CONST_PROOF_SIZE_LOG_N * FR_SIZE
        }
    }

    /// Offset where kzgQuotient starts
    fn kzg_quotient_offset(&self) -> usize {
        self.shplonk_q_offset() + G1_LIMBED_SIZE
    }

    // ========== Accessor methods ==========

    /// Get pairing point object (16 Fr elements)
    pub fn pairing_point_object(&self) -> [Fr; NUM_PAIRING_POINT_FRS] {
        let mut result = [[0u8; FR_SIZE]; NUM_PAIRING_POINT_FRS];
        let offset = self.pairing_point_offset();
        for i in 0..NUM_PAIRING_POINT_FRS {
            result[i]
                .copy_from_slice(&self.raw_data[offset + i * FR_SIZE..offset + (i + 1) * FR_SIZE]);
        }
        result
    }

    /// Get witness commitment by index (0-7)
    /// Order: w1, w2, w3, lookupReadCounts, lookupReadTags, w4, lookupInverses, zPerm
    pub fn witness_commitment(&self, index: usize) -> G1 {
        assert!(
            index < NUM_WITNESS_COMMS,
            "Invalid witness commitment index"
        );
        let offset = self.witness_comms_offset() + index * G1_LIMBED_SIZE;
        let mut limbed = [0u8; G1_LIMBED_SIZE];
        limbed.copy_from_slice(&self.raw_data[offset..offset + G1_LIMBED_SIZE]);
        g1_from_limbed(&limbed)
    }

    /// Get witness commitment in raw limbed format (4 Fr elements)
    /// Used for transcript where Solidity uses the limbed format
    pub fn witness_commitment_limbed(&self, index: usize) -> [Fr; 4] {
        assert!(
            index < NUM_WITNESS_COMMS,
            "Invalid witness commitment index"
        );
        let offset = self.witness_comms_offset() + index * G1_LIMBED_SIZE;
        let mut result = [[0u8; FR_SIZE]; 4];
        for i in 0..4 {
            result[i]
                .copy_from_slice(&self.raw_data[offset + i * FR_SIZE..offset + (i + 1) * FR_SIZE]);
        }
        result
    }

    /// Get W1 commitment
    pub fn w1(&self) -> G1 {
        self.witness_commitment(0)
    }

    /// Get W2 commitment
    pub fn w2(&self) -> G1 {
        self.witness_commitment(1)
    }

    /// Get W3 commitment
    pub fn w3(&self) -> G1 {
        self.witness_commitment(2)
    }

    /// Get W4 commitment (note: index 5 in proof order)
    pub fn w4(&self) -> G1 {
        self.witness_commitment(5)
    }

    /// Get lookupReadCounts commitment (index 3)
    pub fn lookup_read_counts(&self) -> G1 {
        self.witness_commitment(3)
    }

    /// Get lookupReadTags commitment (index 4)
    pub fn lookup_read_tags(&self) -> G1 {
        self.witness_commitment(4)
    }

    /// Get lookupInverses commitment (index 6)
    pub fn lookup_inverses(&self) -> G1 {
        self.witness_commitment(6)
    }

    /// Get zPerm commitment (index 7)
    pub fn z_perm(&self) -> G1 {
        self.witness_commitment(7)
    }

    /// Get libraCommitments[0] (ZK only)
    pub fn libra_commitment_0(&self) -> G1 {
        assert!(
            self.is_zk,
            "libra_commitment_0 only available for ZK proofs"
        );
        let offset = self.libra_comm0_offset();
        let mut limbed = [0u8; G1_LIMBED_SIZE];
        limbed.copy_from_slice(&self.raw_data[offset..offset + G1_LIMBED_SIZE]);
        g1_from_limbed(&limbed)
    }

    /// Get libraCommitments[0] in raw limbed format (ZK only)
    /// Returns [x_0, x_1, y_0, y_1] as 4 Fr elements
    /// Used for transcript where Solidity uses the limbed format
    pub fn libra_commitment_0_limbed(&self) -> [Fr; 4] {
        assert!(
            self.is_zk,
            "libra_commitment_0_limbed only available for ZK proofs"
        );
        let offset = self.libra_comm0_offset();
        let mut result = [[0u8; FR_SIZE]; 4];
        for i in 0..4 {
            result[i]
                .copy_from_slice(&self.raw_data[offset + i * FR_SIZE..offset + (i + 1) * FR_SIZE]);
        }
        result
    }

    /// Get libraSum (ZK only)
    pub fn libra_sum(&self) -> Fr {
        assert!(self.is_zk, "libra_sum only available for ZK proofs");
        let offset = self.libra_sum_offset();
        let mut result = [0u8; FR_SIZE];
        result.copy_from_slice(&self.raw_data[offset..offset + FR_SIZE]);
        result
    }

    /// Get sumcheck univariate for a specific round and coefficient
    pub fn sumcheck_univariate(&self, round: usize, coeff: usize) -> Fr {
        let univariate_len = if self.is_zk {
            ZK_BATCHED_RELATION_PARTIAL_LENGTH
        } else {
            BATCHED_RELATION_PARTIAL_LENGTH
        };
        assert!(round < CONST_PROOF_SIZE_LOG_N, "Invalid round index");
        assert!(coeff < univariate_len, "Invalid coefficient index");

        let offset =
            self.sumcheck_univariates_offset() + round * univariate_len * FR_SIZE + coeff * FR_SIZE;
        let mut result = [0u8; FR_SIZE];
        result.copy_from_slice(&self.raw_data[offset..offset + FR_SIZE]);
        result
    }

    /// Get all sumcheck univariates for a round
    pub fn sumcheck_univariates_for_round(&self, round: usize) -> Vec<Fr> {
        let univariate_len = if self.is_zk {
            ZK_BATCHED_RELATION_PARTIAL_LENGTH
        } else {
            BATCHED_RELATION_PARTIAL_LENGTH
        };
        (0..univariate_len)
            .map(|i| self.sumcheck_univariate(round, i))
            .collect()
    }

    /// Get sumcheck evaluation by index
    pub fn sumcheck_evaluation(&self, index: usize) -> Fr {
        assert!(index < NUM_ALL_ENTITIES, "Invalid evaluation index");
        let offset = self.sumcheck_evals_offset() + index * FR_SIZE;
        let mut result = [0u8; FR_SIZE];
        result.copy_from_slice(&self.raw_data[offset..offset + FR_SIZE]);
        result
    }

    /// Get all sumcheck evaluations
    pub fn sumcheck_evaluations(&self) -> Vec<Fr> {
        (0..NUM_ALL_ENTITIES)
            .map(|i| self.sumcheck_evaluation(i))
            .collect()
    }

    /// Get libraEvaluation (ZK only)
    pub fn libra_evaluation(&self) -> Fr {
        assert!(self.is_zk, "libra_evaluation only available for ZK proofs");
        let offset = self.libra_eval_offset();
        let mut result = [0u8; FR_SIZE];
        result.copy_from_slice(&self.raw_data[offset..offset + FR_SIZE]);
        result
    }

    /// Get libraCommitments[1] (ZK only)
    pub fn libra_commitment_1(&self) -> G1 {
        assert!(
            self.is_zk,
            "libra_commitment_1 only available for ZK proofs"
        );
        let offset = self.libra_comm1_offset();
        let mut limbed = [0u8; G1_LIMBED_SIZE];
        limbed.copy_from_slice(&self.raw_data[offset..offset + G1_LIMBED_SIZE]);
        g1_from_limbed(&limbed)
    }

    /// Get libraCommitments[1] in limbed format [x_0, x_1, y_0, y_1] (ZK only)
    pub fn libra_commitment_1_limbed(&self) -> [Fr; 4] {
        assert!(
            self.is_zk,
            "libra_commitment_1_limbed only available for ZK proofs"
        );
        let offset = self.libra_comm1_offset();
        let mut result = [[0u8; FR_SIZE]; 4];
        for i in 0..4 {
            result[i]
                .copy_from_slice(&self.raw_data[offset + i * FR_SIZE..offset + (i + 1) * FR_SIZE]);
        }
        result
    }

    /// Get libraCommitments[2] (ZK only)
    pub fn libra_commitment_2(&self) -> G1 {
        assert!(
            self.is_zk,
            "libra_commitment_2 only available for ZK proofs"
        );
        let offset = self.libra_comm2_offset();
        let mut limbed = [0u8; G1_LIMBED_SIZE];
        limbed.copy_from_slice(&self.raw_data[offset..offset + G1_LIMBED_SIZE]);
        g1_from_limbed(&limbed)
    }

    /// Get libraCommitments[2] in limbed format [x_0, x_1, y_0, y_1] (ZK only)
    pub fn libra_commitment_2_limbed(&self) -> [Fr; 4] {
        assert!(
            self.is_zk,
            "libra_commitment_2_limbed only available for ZK proofs"
        );
        let offset = self.libra_comm2_offset();
        let mut result = [[0u8; FR_SIZE]; 4];
        for i in 0..4 {
            result[i]
                .copy_from_slice(&self.raw_data[offset + i * FR_SIZE..offset + (i + 1) * FR_SIZE]);
        }
        result
    }

    /// Get geminiMaskingPoly commitment (ZK only)
    pub fn gemini_masking_poly(&self) -> G1 {
        assert!(
            self.is_zk,
            "gemini_masking_poly only available for ZK proofs"
        );
        let offset = self.gemini_masking_poly_offset();
        let mut limbed = [0u8; G1_LIMBED_SIZE];
        limbed.copy_from_slice(&self.raw_data[offset..offset + G1_LIMBED_SIZE]);
        g1_from_limbed(&limbed)
    }

    /// Get geminiMaskingPoly in limbed format [x_0, x_1, y_0, y_1] (ZK only)
    pub fn gemini_masking_poly_limbed(&self) -> [Fr; 4] {
        assert!(
            self.is_zk,
            "gemini_masking_poly_limbed only available for ZK proofs"
        );
        let offset = self.gemini_masking_poly_offset();
        let mut result = [[0u8; FR_SIZE]; 4];
        for i in 0..4 {
            result[i]
                .copy_from_slice(&self.raw_data[offset + i * FR_SIZE..offset + (i + 1) * FR_SIZE]);
        }
        result
    }

    /// Get geminiMaskingEval (ZK only)
    pub fn gemini_masking_eval(&self) -> Fr {
        assert!(
            self.is_zk,
            "gemini_masking_eval only available for ZK proofs"
        );
        let offset = self.gemini_masking_eval_offset();
        let mut result = [0u8; FR_SIZE];
        result.copy_from_slice(&self.raw_data[offset..offset + FR_SIZE]);
        result
    }

    /// Get gemini fold commitment by index (0 to CONST_PROOF_SIZE_LOG_N - 2)
    pub fn gemini_fold_commitment(&self, index: usize) -> G1 {
        assert!(
            index < CONST_PROOF_SIZE_LOG_N - 1,
            "Invalid gemini fold index"
        );
        let offset = self.gemini_fold_comms_offset() + index * G1_LIMBED_SIZE;
        let mut limbed = [0u8; G1_LIMBED_SIZE];
        limbed.copy_from_slice(&self.raw_data[offset..offset + G1_LIMBED_SIZE]);
        g1_from_limbed(&limbed)
    }

    /// Get gemini fold commitment in limbed format [x_0, x_1, y_0, y_1]
    pub fn gemini_fold_commitment_limbed(&self, index: usize) -> [Fr; 4] {
        assert!(
            index < CONST_PROOF_SIZE_LOG_N - 1,
            "Invalid gemini fold index"
        );
        let offset = self.gemini_fold_comms_offset() + index * G1_LIMBED_SIZE;
        let mut result = [[0u8; FR_SIZE]; 4];
        for i in 0..4 {
            result[i]
                .copy_from_slice(&self.raw_data[offset + i * FR_SIZE..offset + (i + 1) * FR_SIZE]);
        }
        result
    }

    /// Get all gemini fold commitments (only first log_n - 1 are meaningful)
    pub fn gemini_fold_commitments(&self) -> Vec<G1> {
        // Return only the meaningful ones based on actual circuit size
        (0..self.log_n.saturating_sub(1))
            .map(|i| self.gemini_fold_commitment(i))
            .collect()
    }

    /// Get gemini A evaluation by index
    pub fn gemini_a_evaluation(&self, index: usize) -> Fr {
        assert!(
            index < CONST_PROOF_SIZE_LOG_N,
            "Invalid gemini A eval index"
        );
        let offset = self.gemini_a_evals_offset() + index * FR_SIZE;
        let mut result = [0u8; FR_SIZE];
        result.copy_from_slice(&self.raw_data[offset..offset + FR_SIZE]);
        result
    }

    /// Get all gemini A evaluations (only first log_n are meaningful)
    pub fn gemini_a_evaluations(&self) -> Vec<Fr> {
        (0..self.log_n)
            .map(|i| self.gemini_a_evaluation(i))
            .collect()
    }

    /// Get libraPolyEvals (ZK only, 4 Fr elements)
    pub fn libra_poly_evals(&self) -> [Fr; 4] {
        assert!(self.is_zk, "libra_poly_evals only available for ZK proofs");
        let offset = self.libra_poly_evals_offset();
        let mut result = [[0u8; FR_SIZE]; 4];
        for i in 0..4 {
            result[i]
                .copy_from_slice(&self.raw_data[offset + i * FR_SIZE..offset + (i + 1) * FR_SIZE]);
        }
        result
    }

    /// Get shplonkQ commitment
    pub fn shplonk_q(&self) -> G1 {
        let offset = self.shplonk_q_offset();
        let mut limbed = [0u8; G1_LIMBED_SIZE];
        limbed.copy_from_slice(&self.raw_data[offset..offset + G1_LIMBED_SIZE]);
        g1_from_limbed(&limbed)
    }

    /// Get shplonkQ in limbed format [x_0, x_1, y_0, y_1]
    pub fn shplonk_q_limbed(&self) -> [Fr; 4] {
        let offset = self.shplonk_q_offset();
        let mut result = [[0u8; FR_SIZE]; 4];
        for i in 0..4 {
            result[i]
                .copy_from_slice(&self.raw_data[offset + i * FR_SIZE..offset + (i + 1) * FR_SIZE]);
        }
        result
    }

    /// Get KZG quotient commitment
    pub fn kzg_quotient(&self) -> G1 {
        let offset = self.kzg_quotient_offset();
        let mut limbed = [0u8; G1_LIMBED_SIZE];
        limbed.copy_from_slice(&self.raw_data[offset..offset + G1_LIMBED_SIZE]);
        g1_from_limbed(&limbed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expected_size_zk() {
        assert_eq!(Proof::expected_size_bytes(true), 16224);
    }

    #[test]
    fn test_expected_size_non_zk() {
        assert_eq!(Proof::expected_size_bytes(false), 14592);
    }

    #[test]
    fn test_g1_from_limbed_identity() {
        // Identity point should remain identity
        let limbed = [0u8; G1_LIMBED_SIZE];
        let g1 = g1_from_limbed(&limbed);
        assert_eq!(g1, [0u8; 64]);
    }

    #[test]
    fn test_g1_from_limbed_generator() {
        // G1 generator: x=1, y=2
        // In limbed format: x_0=1, x_1=0, y_0=2, y_1=0
        let mut limbed = [0u8; G1_LIMBED_SIZE];
        limbed[31] = 1; // x_0 = 1 (big-endian)
        limbed[95] = 2; // y_0 = 2 (big-endian)

        let g1 = g1_from_limbed(&limbed);
        assert_eq!(g1[31], 1, "x should be 1");
        assert_eq!(g1[63], 2, "y should be 2");
    }

    #[test]
    fn test_proof_parse_zk() {
        // Create a minimal ZK proof of correct size
        let proof_bytes = vec![0u8; EXPECTED_ZK_PROOF_SIZE];
        let proof = Proof::from_bytes(&proof_bytes, 12, true).expect("Should parse ZK proof");
        assert!(proof.is_zk);
        assert_eq!(proof.log_n, 12);
    }

    #[test]
    fn test_proof_parse_non_zk() {
        // Create a minimal non-ZK proof of correct size
        let proof_bytes = vec![0u8; EXPECTED_NON_ZK_PROOF_SIZE];
        let proof = Proof::from_bytes(&proof_bytes, 12, false).expect("Should parse non-ZK proof");
        assert!(!proof.is_zk);
        assert_eq!(proof.log_n, 12);
    }

    #[test]
    fn test_proof_wrong_size() {
        let proof_bytes = vec![0u8; 1000];
        let result = Proof::from_bytes(&proof_bytes, 12, true);
        assert!(result.is_err());
    }
}
