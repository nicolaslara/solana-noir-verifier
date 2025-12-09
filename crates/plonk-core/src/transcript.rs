//! Fiat-Shamir transcript using Keccak256
//!
//! Matches bb's transcript with --oracle_hash keccak.
//! Challenge generation follows the UltraHonk protocol.
//!
//! On Solana, uses the sol_keccak256 syscall (~100 CUs).
//! Off-chain, uses pure Rust sha3 implementation.

use crate::field::limbs_to_fr;
use crate::types::{Fr, G1, SCALAR_ZERO};

extern crate alloc;
use alloc::vec::Vec;

/// Transcript for Fiat-Shamir challenge generation
/// Uses a buffer to accumulate data, then hashes it all at once
pub struct Transcript {
    buffer: Vec<u8>,
}

impl Transcript {
    /// Create a new empty transcript
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(4096), // Pre-allocate for typical usage
        }
    }

    /// Create a transcript initialized with a previous challenge (for resuming)
    /// This matches the state after a challenge_split() call
    pub fn from_previous_challenge(prev_challenge: &Fr) -> Self {
        let mut buffer = Vec::with_capacity(4096);
        buffer.extend_from_slice(prev_challenge);
        Self { buffer }
    }

    /// Get the current transcript state (the buffer contents)
    /// After a challenge_split(), this is the 32-byte challenge used for chaining
    pub fn get_state(&self) -> Vec<u8> {
        self.buffer.clone()
    }

    /// Check if transcript is in "fresh challenge" state (32-byte buffer)
    pub fn is_at_challenge_boundary(&self) -> bool {
        self.buffer.len() == 32
    }

    /// Append a u64 value (as 32-byte big-endian)
    pub fn append_u64(&mut self, val: u64) {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&val.to_be_bytes());
        self.buffer.extend_from_slice(&bytes);
    }

    /// Append a G1 point to the transcript.
    /// For Keccak (U256Codec): G1 = 2 × uint256_t = 64 bytes (x || y), big-endian.
    pub fn append_g1(&mut self, point: &G1) {
        self.buffer.extend_from_slice(point);
    }

    /// Append a scalar/field element to the transcript (32 bytes big-endian)
    pub fn append_scalar(&mut self, scalar: &Fr) {
        self.buffer.extend_from_slice(scalar);
    }

    /// Append raw bytes to the transcript
    pub fn append_bytes(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Hash the current buffer contents
    #[inline(always)]
    fn hash_buffer(&self) -> [u8; 32] {
        // Use syscall on Solana (target_os=solana, target_arch=bpf or sbpf)
        #[cfg(any(target_os = "solana", target_arch = "bpf", target_arch = "sbpf"))]
        {
            let hash = solana_keccak_hasher::hash(&self.buffer);
            hash.to_bytes()
        }

        // Use pure Rust sha3 off-chain
        #[cfg(not(any(target_os = "solana", target_arch = "bpf", target_arch = "sbpf")))]
        {
            use sha3::{Digest, Keccak256};
            let mut hasher = Keccak256::new();
            hasher.update(&self.buffer);
            let result = hasher.finalize();
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(&result);
            hash_bytes
        }
    }

    /// Internal: Generate a raw challenge and update transcript state.
    /// Returns the FULL Fr value (before splitting).
    /// The buffer is cleared and the full challenge is appended for chaining.
    fn raw_challenge(&mut self) -> Fr {
        let hash_bytes = self.hash_buffer();

        #[cfg(all(feature = "debug", not(target_family = "solana")))]
        {
            crate::trace!("transcript raw_hash = {:02x?}", &hash_bytes[0..8]);
        }

        // Reduce mod r using our field arithmetic
        let full_challenge = reduce_hash_to_fr(&hash_bytes);

        // Clear buffer and re-initialize with the FULL challenge for the next round
        self.buffer.clear();
        self.buffer.extend_from_slice(&full_challenge);

        full_challenge
    }

    /// Generate a single challenge scalar from current transcript state.
    /// In bb, get_challenge(single_label) returns only the LOWER 127 bits.
    /// This is because internally it calls get_challenges which does split_challenge,
    /// and for odd count (like 1), returns challenge_buffer[0] = lower 127 bits.
    pub fn challenge(&mut self) -> Fr {
        let full = self.raw_challenge();
        let (lower, _) = split_challenge(&full);
        lower
    }

    /// Generate a challenge and split it into two 127-bit values.
    /// This matches the UltraHonk "split_challenge" pattern.
    /// Returns (lower_127_bits, upper_127_bits) as Fr elements.
    pub fn challenge_split(&mut self) -> (Fr, Fr) {
        let full = self.raw_challenge();
        #[cfg(all(feature = "debug", not(target_family = "solana")))]
        {
            crate::dbg_fr!("full_challenge_before_split", &full);
        }
        split_challenge(&full)
    }

    /// Get the current hash state and reset the buffer.
    /// Used for intermediate challenge generation.
    pub fn get_challenge_and_reset(&mut self) -> Fr {
        let hash_bytes = self.hash_buffer();
        self.buffer.clear();
        reduce_hash_to_fr(&hash_bytes)
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

/// Reduce a 32-byte hash to Fr by interpreting as big-endian modular reduction
/// Public version for use by other modules
pub fn reduce_hash_to_fr_public(hash: &[u8; 32]) -> Fr {
    reduce_hash_to_fr(hash)
}

/// Reduce a 32-byte hash to Fr by interpreting as big-endian modular reduction
fn reduce_hash_to_fr(hash: &[u8; 32]) -> Fr {
    // The hash is 256 bits, and Fr modulus is ~254 bits
    // We need to reduce if hash >= modulus
    let limbs = hash_to_limbs(hash);

    // BN254 scalar field modulus r
    const R: [u64; 4] = [
        0x43e1f593f0000001,
        0x2833e84879b97091,
        0xb85045b68181585d,
        0x30644e72e131a029,
    ];

    // Check if hash >= r and reduce by subtraction if needed
    let mut result = limbs;
    loop {
        // Compare result >= R
        let mut ge = true;
        for i in (0..4).rev() {
            if result[i] > R[i] {
                break;
            } else if result[i] < R[i] {
                ge = false;
                break;
            }
        }

        if ge {
            // Subtract R from result
            let mut borrow = 0u64;
            for i in 0..4 {
                let (diff1, b1) = result[i].overflowing_sub(R[i]);
                let (diff2, b2) = diff1.overflowing_sub(borrow);
                result[i] = diff2;
                borrow = if b1 || b2 { 1 } else { 0 };
            }
        } else {
            break;
        }
    }

    limbs_to_fr(&result)
}

/// Convert 32-byte big-endian hash to 4 x u64 limbs (little-endian limbs)
fn hash_to_limbs(hash: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_be_bytes([
            hash[24], hash[25], hash[26], hash[27], hash[28], hash[29], hash[30], hash[31],
        ]),
        u64::from_be_bytes([
            hash[16], hash[17], hash[18], hash[19], hash[20], hash[21], hash[22], hash[23],
        ]),
        u64::from_be_bytes([
            hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15],
        ]),
        u64::from_be_bytes([
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
        ]),
    ]
}

/// Split a 254-bit challenge into two 128-bit values (lo, hi).
/// Matches Solidity's splitChallenge:
///   lo = challenge & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF (lower 128 bits)
///   hi = challenge >> 128 (upper 128 bits, shifted down)
///
/// The Fr value is stored as big-endian bytes, so:
/// - bytes[16..32] contains the lower 128 bits
/// - bytes[0..16] contains the upper 128 bits
pub fn split_challenge(challenge: &Fr) -> (Fr, Fr) {
    // challenge is 32 bytes big-endian
    // bytes[0..16] = upper 128 bits (hi)
    // bytes[16..32] = lower 128 bits (lo)

    // lo: mask with 128-bit mask (keep bytes[16..32], zero bytes[0..16])
    let mut lo = [0u8; 32];
    lo[16..32].copy_from_slice(&challenge[16..32]);

    // hi: shift right by 128 (move bytes[0..16] to bytes[16..32], zero bytes[0..16])
    let mut hi = [0u8; 32];
    hi[16..32].copy_from_slice(&challenge[0..16]);

    #[cfg(all(feature = "debug", not(target_family = "solana")))]
    {
        crate::dbg_fr!("split_challenge lo", &lo);
        crate::dbg_fr!("split_challenge hi", &hi);
    }

    (lo, hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reduce_hash_to_fr() {
        // Test with a small value (no reduction needed)
        let small = [0u8; 32];
        let result = reduce_hash_to_fr(&small);
        assert_eq!(result, SCALAR_ZERO);

        // Test with a large value (should be reduced mod r)
        let large = [0xffu8; 32];
        let result = reduce_hash_to_fr(&large);
        // Should not be all 0xff after reduction
        assert_ne!(result, large);
}

#[test]
    fn test_split_challenge() {
        // Create a challenge with known pattern
        let mut challenge = [0u8; 32];
        // Set upper 128 bits to 0x01
        challenge[15] = 0x01;
        // Set lower 128 bits to 0x02
        challenge[31] = 0x02;

        let (lo, hi) = split_challenge(&challenge);

        // lo should have only the lower 128 bits
        assert_eq!(lo[31], 0x02);
        assert_eq!(lo[15], 0x00);

        // hi should have the upper 128 bits shifted down
        assert_eq!(hi[31], 0x01);
        assert_eq!(hi[15], 0x00);
}

#[test]
    fn test_transcript_basic() {
        let mut t = Transcript::new();

        // Append some data
        t.append_scalar(&[1u8; 32]);
        t.append_scalar(&[2u8; 32]);

        // Generate challenge
        let c = t.challenge();

        // Challenge should be non-zero
        assert_ne!(c, SCALAR_ZERO);
}

#[test]
    fn test_actual_eta_computation() {
        // Build the same buffer as the Solidity verifier
        let mut t = Transcript::new();

        // These are simplified test values
        let circuit_size: u64 = 64;
        let public_inputs_size: u64 = 1;
        let pub_inputs_offset: u64 = 1;

        t.append_u64(circuit_size);
        t.append_u64(public_inputs_size);
        t.append_u64(pub_inputs_offset);

        // For a real test, we'd need to add all the proof elements...
        // Just verify we can generate a challenge without crashing
        let _ = t.challenge_split();
    }
}
