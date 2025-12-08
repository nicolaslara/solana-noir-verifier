//! Proof parsing for bb 3.0 UltraHonk (Keccak)
//!
//! ## Key Discovery
//!
//! The proof size is VARIABLE based on `log_circuit_size` (log_n).
//! It contains sumcheck data sized for the actual circuit, not CONST_PROOF_SIZE_LOG_N=28.
//!
//! ## Binary Proof Format (stored as contiguous Fr elements, 32 bytes each)
//!
//! For ZK proofs (UltraKeccakZKFlavor):
//! 1. Pairing point object: 16 Fr
//! 2. Wire commitments: 8 G1 = 16 Fr
//! 3. Libra concat commitment: 1 G1 = 2 Fr (ZK only)
//! 4. Libra sum: 1 Fr (ZK only)
//! 5. Sumcheck univariates: log_n × 8 Fr
//! 6. Sumcheck evaluations: NUM_ALL_ENTITIES Fr (41 for ZK, 40 for non-ZK)
//! 7. Libra claimed evaluation: 1 Fr (ZK only)
//! 8. Libra grand sum commitment: 1 G1 = 2 Fr (ZK only)
//! 9. Libra quotient commitment: 1 G1 = 2 Fr (ZK only)
//! 10. Gemini masking commitment: 1 G1 = 2 Fr (ZK only)
//! 11. Gemini masking evaluation: 1 Fr (ZK only)
//! 12. Gemini fold commitments: (log_n - 1) G1 = (log_n - 1) × 2 Fr
//! 13. Gemini A evaluations: log_n Fr
//! 14. Small IPA evaluations: 2 Fr (ZK only)
//! 15. Shplonk Q commitment: 1 G1 = 2 Fr
//! 16. KZG W commitment: 1 G1 = 2 Fr

use crate::errors::ProofError;
use crate::types::{Fr, G1};

extern crate alloc;
use alloc::vec::Vec;

/// Number of Fr values in pairing point object
pub const NUM_PAIRING_POINT_FRS: usize = 16;

/// Number of witness commitments
pub const NUM_WITNESS_COMMS: usize = 8;

/// Number of all entities for sumcheck evaluations
/// Matches Solidity's NUMBER_OF_ENTITIES = 41
/// Wire enum has 41 entries (0-40: Q_M through Z_PERM_SHIFT)
pub const NUM_ALL_ENTITIES: usize = 41;

/// Batched relation partial length (sumcheck univariate degree + 1)
pub const BATCHED_RELATION_PARTIAL_LENGTH: usize = 8;

/// ZK-specific extras (Libra-related)
/// ZK adds: libra_concat(2) + libra_sum(1) + libra_eval(1) + libra_grand_sum(2) +
///          libra_quotient(2) + gemini_masking(2) + gemini_masking_eval(1) + small_ipa(2) = 13 Fr
/// Note: ZK also uses BATCHED_RELATION_PARTIAL_LENGTH = 9 instead of 8
pub const ZK_EXTRA_FRS: usize = 13;

/// Batched relation partial length for ZK proofs
pub const BATCHED_RELATION_PARTIAL_LENGTH_ZK: usize = 9;

/// Additional Fr elements observed in actual proofs (likely protocol-specific metadata)
/// Non-ZK proofs have 1 extra Fr, ZK proofs have 2 extra Fr
/// TODO: Investigate exact source of these in bb proof serialization
pub const PROOF_EXTRA_FR_NON_ZK: usize = 1;
pub const PROOF_EXTRA_FR_ZK: usize = 2;

/// Parsed UltraHonk proof with semantic structure
#[derive(Debug, Clone)]
pub struct Proof {
    /// Raw proof data as Fr elements
    pub data: Vec<Fr>,

    /// log2 of circuit size (from VK)
    pub log_n: usize,

    /// Whether this is a ZK proof
    pub is_zk: bool,
}

impl Proof {
    /// Calculate expected proof size in Fr elements
    pub fn expected_size(log_n: usize, is_zk: bool) -> usize {
        let mut size = 0;

        // Pairing point object
        size += NUM_PAIRING_POINT_FRS;

        // Wire commitments (8 G1 = 16 Fr)
        size += NUM_WITNESS_COMMS * 2;

        if is_zk {
            // Libra concat commitment (1 G1 = 2 Fr)
            size += 2;
            // Libra sum (1 Fr)
            size += 1;
        }

        // Sumcheck univariates
        // ZK uses 9 coefficients per round, non-ZK uses 8
        let univariate_len = if is_zk {
            BATCHED_RELATION_PARTIAL_LENGTH_ZK
        } else {
            BATCHED_RELATION_PARTIAL_LENGTH
        };
        size += log_n * univariate_len;

        // Sumcheck evaluations (41 entities for both ZK and non-ZK)
        size += NUM_ALL_ENTITIES;

        if is_zk {
            // Libra claimed evaluation (1 Fr)
            size += 1;
            // Libra grand sum commitment (1 G1 = 2 Fr)
            size += 2;
            // Libra quotient commitment (1 G1 = 2 Fr)
            size += 2;
            // Gemini masking commitment (1 G1 = 2 Fr)
            size += 2;
            // Gemini masking evaluation (1 Fr)
            size += 1;
        }

        // Gemini fold commitments ((log_n - 1) G1)
        size += (log_n - 1) * 2;

        // Gemini A evaluations (log_n Fr)
        size += log_n;

        if is_zk {
            // Small IPA evaluations (2 Fr)
            size += 2;
        }

        // Shplonk Q commitment (1 G1 = 2 Fr)
        size += 2;

        // KZG W commitment (1 G1 = 2 Fr)
        size += 2;

        // Add extra Fr observed in actual proofs
        // TODO: Investigate exact source in bb proof serialization
        size += if is_zk {
            PROOF_EXTRA_FR_ZK
        } else {
            PROOF_EXTRA_FR_NON_ZK
        };

        size
    }

    /// Parse proof from bb 3.0 binary format
    ///
    /// # Arguments
    /// * `bytes` - Raw proof bytes (must be multiple of 32)
    /// * `log_n` - log2 of circuit size from VK
    /// * `is_zk` - Whether this is a ZK proof (default true for Keccak)
    pub fn from_bytes(bytes: &[u8], log_n: usize, is_zk: bool) -> Result<Self, ProofError> {
        if bytes.len() % 32 != 0 {
            return Err(ProofError::InvalidSize {
                expected: bytes.len() - (bytes.len() % 32),
                actual: bytes.len(),
            });
        }

        let expected_fr = Self::expected_size(log_n, is_zk);
        let actual_fr = bytes.len() / 32;

        if actual_fr != expected_fr {
            return Err(ProofError::InvalidSize {
                expected: expected_fr * 32,
                actual: bytes.len(),
            });
        }

        // Parse as vector of Fr elements
        let mut data = Vec::with_capacity(actual_fr);
        for i in 0..actual_fr {
            let mut fr = [0u8; 32];
            fr.copy_from_slice(&bytes[i * 32..(i + 1) * 32]);
            data.push(fr);
        }

        Ok(Proof { data, log_n, is_zk })
    }

    /// Get pairing point object (16 Fr values)
    pub fn pairing_point_object(&self) -> &[Fr] {
        &self.data[0..NUM_PAIRING_POINT_FRS]
    }

    /// Get the gemini masking commitment (ZK only)
    /// This is AFTER sumcheck evaluations: pairing(16) + wires(16) + libra(3) + univariates + evals + libra_post(5)
    pub fn gemini_masking_commitment(&self) -> Option<G1> {
        if !self.is_zk {
            return None;
        }
        // ZK structure: pairing(16) + wires(16) + libra_concat(2) + libra_sum(1) + univariates + evals + libra_eval(1) + grand_sum(2) + quotient(2)
        let base_offset = NUM_PAIRING_POINT_FRS + NUM_WITNESS_COMMS * 2;
        let zk_libra_start = 3; // libra_concat(2) + libra_sum(1)
        let univariates_size = self.log_n * BATCHED_RELATION_PARTIAL_LENGTH_ZK;
        let evals_size = NUM_ALL_ENTITIES;
        let zk_libra_eval_and_comms = 5; // libra_eval(1) + grand_sum(2) + quotient(2)

        let offset =
            base_offset + zk_libra_start + univariates_size + evals_size + zk_libra_eval_and_comms;
        let mut g1 = [0u8; 64];
        g1[0..32].copy_from_slice(&self.data[offset]);
        g1[32..64].copy_from_slice(&self.data[offset + 1]);
        Some(g1)
    }

    /// Get wire commitment at index (0-7)
    /// Returns G1 point as 2 Fr values (x, y)
    /// Wire commitments come right after pairing point object (no ZK shift!)
    /// Order: w1, w2, w3, lookupReadCounts, lookupReadTags, w4, lookupInverses, zPerm
    pub fn wire_commitment(&self, idx: usize) -> G1 {
        assert!(
            idx < NUM_WITNESS_COMMS,
            "Wire commitment index out of range"
        );
        // Wire commitments start at offset 16 (after pairing point object)
        // NO ZK shift - gemini_masking is much later in the proof!
        let offset = NUM_PAIRING_POINT_FRS + idx * 2;
        let mut g1 = [0u8; 64];
        g1[0..32].copy_from_slice(&self.data[offset]);
        g1[32..64].copy_from_slice(&self.data[offset + 1]);
        g1
    }

    /// Get the libra sum for ZK proofs
    /// This is the initial target for sumcheck in ZK mode
    /// Returns None for non-ZK proofs
    pub fn libra_sum(&self) -> Option<Fr> {
        if !self.is_zk {
            return None;
        }
        // ZK structure: pairing(16) + wire_comms(16) + libra_concat(2) + libra_sum(1)
        // libra_sum is at offset 34
        let offset = NUM_PAIRING_POINT_FRS + NUM_WITNESS_COMMS * 2 + 2;
        Some(self.data[offset])
    }

    /// Get the libra concatenation commitment (ZK only)
    /// This is libraCommitments[0] in the Solidity verifier
    pub fn libra_concat_commitment(&self) -> Option<G1> {
        if !self.is_zk {
            return None;
        }
        // ZK structure: pairing(16) + wire_comms(16) = offset 32
        let offset = NUM_PAIRING_POINT_FRS + NUM_WITNESS_COMMS * 2;
        let mut g1 = [0u8; 64];
        g1[0..32].copy_from_slice(&self.data[offset]);
        g1[32..64].copy_from_slice(&self.data[offset + 1]);
        Some(g1)
    }

    /// Get sumcheck univariates for a specific round
    /// Returns 8 Fr values for non-ZK or 9 Fr values for ZK
    pub fn sumcheck_univariate(&self, round: usize) -> &[Fr] {
        assert!(round < self.log_n, "Round index out of range");

        // Non-ZK: pairing(16) + wire_comms(16) = 32
        // ZK: pairing(16) + wire_comms(16) + libra_concat(2) + libra_sum(1) = 35
        let base_offset = NUM_PAIRING_POINT_FRS + NUM_WITNESS_COMMS * 2;
        let zk_libra = if self.is_zk { 3 } else { 0 }; // libra_concat(2) + libra_sum(1)

        let univariate_len = if self.is_zk {
            BATCHED_RELATION_PARTIAL_LENGTH_ZK
        } else {
            BATCHED_RELATION_PARTIAL_LENGTH
        };

        let offset = base_offset + zk_libra + round * univariate_len;
        &self.data[offset..offset + univariate_len]
    }

    /// Get sumcheck evaluations
    pub fn sumcheck_evaluations(&self) -> &[Fr] {
        // Offset after: pairing + wire_comms + ZK_libra + sumcheck_univariates
        let base_offset = NUM_PAIRING_POINT_FRS + NUM_WITNESS_COMMS * 2;
        let zk_libra = if self.is_zk { 3 } else { 0 }; // libra_concat(2) + libra_sum(1)
        let univariate_len = if self.is_zk {
            BATCHED_RELATION_PARTIAL_LENGTH_ZK
        } else {
            BATCHED_RELATION_PARTIAL_LENGTH
        };
        let univariates_size = self.log_n * univariate_len;

        let offset = base_offset + zk_libra + univariates_size;

        #[cfg(feature = "debug")]
        {
            crate::trace!(
                "sumcheck_evaluations offset: {} (base={}, zk_libra={}, univariates={})",
                offset,
                base_offset,
                zk_libra,
                univariates_size
            );
        }

        &self.data[offset..offset + NUM_ALL_ENTITIES]
    }

    /// Get libra evaluation (ZK only)
    /// This is the libraEvaluation used in the ZK adjustment:
    /// grandHonkRelationSum = grandHonkRelationSum * (1 - evaluation) + libraEvaluation * libraChallenge
    pub fn libra_evaluation(&self) -> Option<Fr> {
        if !self.is_zk {
            return None;
        }
        // ZK structure after sumcheck_evaluations:
        // libra_eval(1) + grand_sum(2) + quotient(2) + masking_comm(2) + masking_eval(1) = 8
        let base_offset = NUM_PAIRING_POINT_FRS + NUM_WITNESS_COMMS * 2;
        let zk_libra_start = 3; // libra_concat(2) + libra_sum(1)
        let univariates_size = self.log_n * BATCHED_RELATION_PARTIAL_LENGTH_ZK;
        let evals_size = NUM_ALL_ENTITIES;

        let offset = base_offset + zk_libra_start + univariates_size + evals_size;

        #[cfg(feature = "debug")]
        {
            crate::trace!(
                "libra_evaluation offset: {} (base={}, zk_start={}, univs={}, evals={})",
                offset,
                base_offset,
                zk_libra_start,
                univariates_size,
                evals_size
            );
        }

        Some(self.data[offset])
    }

    /// Get gemini fold commitment at index (0 to log_n-2)
    pub fn gemini_fold_comm(&self, idx: usize) -> G1 {
        assert!(idx < self.log_n - 1, "Gemini fold index out of range");

        // Calculate offset (after all prior elements)
        // ZK: pairing(16) + wires(16) + libra_concat(2) + libra_sum(1) + univariates + evals
        //     + libra_eval(1) + libra_grand_sum(2) + libra_quotient(2) + gemini_masking(2) + masking_eval(1)
        let base_offset = NUM_PAIRING_POINT_FRS + NUM_WITNESS_COMMS * 2;
        let zk_libra_start = if self.is_zk { 3 } else { 0 }; // libra_concat(2) + libra_sum(1)
        let univariate_len = if self.is_zk {
            BATCHED_RELATION_PARTIAL_LENGTH_ZK
        } else {
            BATCHED_RELATION_PARTIAL_LENGTH
        };
        let univariates_size = self.log_n * univariate_len;
        let evals_size = NUM_ALL_ENTITIES;
        // ZK post-evals: libra_eval(1) + grand_sum(2) + quotient(2) + masking_comm(2) + masking_eval(1) = 8
        let zk_post_evals = if self.is_zk { 8 } else { 0 };

        let offset =
            base_offset + zk_libra_start + univariates_size + evals_size + zk_post_evals + idx * 2;

        let mut g1 = [0u8; 64];
        g1[0..32].copy_from_slice(&self.data[offset]);
        g1[32..64].copy_from_slice(&self.data[offset + 1]);
        g1
    }

    /// Get gemini A evaluation at index (0 to log_n-1)
    pub fn gemini_a_eval(&self, idx: usize) -> &Fr {
        assert!(idx < self.log_n, "Gemini A eval index out of range");

        // After gemini fold comms
        let base_offset = NUM_PAIRING_POINT_FRS + NUM_WITNESS_COMMS * 2;
        let zk_libra_start = if self.is_zk { 3 } else { 0 }; // libra_concat(2) + libra_sum(1)
        let univariate_len = if self.is_zk {
            BATCHED_RELATION_PARTIAL_LENGTH_ZK
        } else {
            BATCHED_RELATION_PARTIAL_LENGTH
        };
        let univariates_size = self.log_n * univariate_len;
        let evals_size = NUM_ALL_ENTITIES;
        // ZK post-evals: libra_eval(1) + grand_sum(2) + quotient(2) + masking_comm(2) + masking_eval(1) = 8
        let zk_post_evals = if self.is_zk { 8 } else { 0 };
        let gemini_fold_size = (self.log_n - 1) * 2;

        let offset = base_offset
            + zk_libra_start
            + univariates_size
            + evals_size
            + zk_post_evals
            + gemini_fold_size
            + idx;

        &self.data[offset]
    }

    /// Get all gemini A evaluations (log_n values)
    pub fn gemini_a_evaluations(&self) -> &[Fr] {
        // After gemini fold comms
        let base_offset = NUM_PAIRING_POINT_FRS + NUM_WITNESS_COMMS * 2;
        let zk_libra_start = if self.is_zk { 3 } else { 0 }; // libra_concat(2) + libra_sum(1)
        let univariate_len = if self.is_zk {
            BATCHED_RELATION_PARTIAL_LENGTH_ZK
        } else {
            BATCHED_RELATION_PARTIAL_LENGTH
        };
        let univariates_size = self.log_n * univariate_len;
        let evals_size = NUM_ALL_ENTITIES;
        // ZK post-evals: libra_eval(1) + grand_sum(2) + quotient(2) + masking_comm(2) + masking_eval(1) = 8
        let zk_post_evals = if self.is_zk { 8 } else { 0 };
        let gemini_fold_size = (self.log_n - 1) * 2;

        let offset = base_offset
            + zk_libra_start
            + univariates_size
            + evals_size
            + zk_post_evals
            + gemini_fold_size;

        &self.data[offset..offset + self.log_n]
    }

    /// Get shplonk Q commitment
    pub fn shplonk_q(&self) -> G1 {
        // Second to last G1 point
        let offset = self.data.len() - 4;
        let mut g1 = [0u8; 64];
        g1[0..32].copy_from_slice(&self.data[offset]);
        g1[32..64].copy_from_slice(&self.data[offset + 1]);
        g1
    }

    /// Get KZG quotient commitment
    pub fn kzg_quotient(&self) -> G1 {
        // Last G1 point
        let offset = self.data.len() - 2;
        let mut g1 = [0u8; 64];
        g1[0..32].copy_from_slice(&self.data[offset]);
        g1[32..64].copy_from_slice(&self.data[offset + 1]);
        g1
    }

    /// Serialize proof back to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.data.len() * 32);
        for fr in &self.data {
            bytes.extend_from_slice(fr);
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expected_size_log6_zk() {
        // For our test circuit with log_n=6 and ZK
        let expected = Proof::expected_size(6, true);
        // 162 Fr elements = 5184 bytes
        assert_eq!(expected, 162);
    }

    #[test]
    fn test_expected_size_log6_non_zk() {
        // For our test circuit with log_n=6 and non-ZK
        let expected = Proof::expected_size(6, false);
        // Non-ZK is smaller
        assert_eq!(expected, 141);
    }

    #[test]
    fn test_expected_size_scales_with_log_n() {
        // Proof size should increase with log_n
        let size_6 = Proof::expected_size(6, true);
        let size_10 = Proof::expected_size(10, true);
        let size_20 = Proof::expected_size(20, true);

        assert!(size_6 < size_10);
        assert!(size_10 < size_20);
    }

    #[test]
    fn test_parse_proof_zk() {
        // Create a proof with the right size for log_n=6, ZK
        let log_n = 6;
        let is_zk = true;
        let expected_fr = Proof::expected_size(log_n, is_zk);
        let bytes = vec![0u8; expected_fr * 32];

        let proof = Proof::from_bytes(&bytes, log_n, is_zk).unwrap();
        assert_eq!(proof.data.len(), expected_fr);
        assert_eq!(proof.log_n, log_n);
        assert!(proof.is_zk);
    }

    #[test]
    fn test_parse_proof_non_zk() {
        // Create a proof with the right size for log_n=6, non-ZK
        let log_n = 6;
        let is_zk = false;
        let expected_fr = Proof::expected_size(log_n, is_zk);
        let bytes = vec![0u8; expected_fr * 32];

        let proof = Proof::from_bytes(&bytes, log_n, is_zk).unwrap();
        assert_eq!(proof.data.len(), expected_fr);
        assert_eq!(proof.log_n, log_n);
        assert!(!proof.is_zk);
    }

    #[test]
    fn test_accessors() {
        let log_n = 6;
        let is_zk = true;
        let expected_fr = Proof::expected_size(log_n, is_zk);
        let mut bytes = vec![0u8; expected_fr * 32];

        // Put marker in pairing point object
        bytes[31] = 0x42;

        let proof = Proof::from_bytes(&bytes, log_n, is_zk).unwrap();

        // Check pairing point object
        assert_eq!(proof.pairing_point_object()[0][31], 0x42);

        // Check we can access sumcheck univariates
        let _uni = proof.sumcheck_univariate(0);

        // Check we can access sumcheck evaluations
        let evals = proof.sumcheck_evaluations();
        assert_eq!(evals.len(), NUM_ALL_ENTITIES);

        // Check we can access shplonk and kzg
        let _shplonk = proof.shplonk_q();
        let _kzg = proof.kzg_quotient();
    }
}
