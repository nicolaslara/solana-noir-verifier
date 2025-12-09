//! Fiat-Shamir transcript using Keccak256
//!
//! Matches bb's transcript with --oracle_hash keccak.
//! Challenge generation follows the UltraHonk protocol.

use crate::field::limbs_to_fr;
use crate::types::{Fr, G1, SCALAR_ZERO};
use sha3::{Digest, Keccak256};

/// Transcript for Fiat-Shamir challenge generation
pub struct Transcript {
    hasher: Keccak256,
}

impl Transcript {
    /// Create a new empty transcript
    pub fn new() -> Self {
        Self {
            hasher: Keccak256::new(),
        }
    }

    /// Append a u64 value (as 32-byte big-endian)
    pub fn append_u64(&mut self, val: u64) {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&val.to_be_bytes());
        self.hasher.update(&bytes);
    }

    /// Append a G1 point to the transcript.
    /// For Keccak (U256Codec): G1 = 2 × uint256_t = 64 bytes (x || y), big-endian.
    pub fn append_g1(&mut self, point: &G1) {
        self.hasher.update(point);
    }

    /// Append a scalar/field element to the transcript (32 bytes big-endian)
    pub fn append_scalar(&mut self, scalar: &Fr) {
        self.hasher.update(scalar);
    }

    /// Append raw bytes to the transcript
    pub fn append_bytes(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    /// Internal: Generate a raw challenge and update transcript state.
    /// Returns the FULL Fr value (before splitting).
    /// The hasher is reset and the full challenge is absorbed for chaining.
    fn raw_challenge(&mut self) -> Fr {
        let hash = self.hasher.finalize_reset();

        // Convert hash to Fr by interpreting as big-endian and reducing mod r
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&hash);

        #[cfg(all(feature = "debug", not(target_family = "solana")))]
        {
            crate::trace!("transcript raw_hash = {:02x?}", &hash_bytes[0..8]);
        }

        // Reduce mod r using our field arithmetic
        let full_challenge = reduce_hash_to_fr(&hash_bytes);

        // Re-initialize with the FULL challenge for the next round (this is what bb does)
        self.hasher.update(&full_challenge);

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

    /// Get the current hash state and reset the hasher.
    /// Used for intermediate challenge generation.
    pub fn get_challenge_and_reset(&mut self) -> Fr {
        let hash = self.hasher.finalize_reset();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&hash);
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
    // We need to reduce mod r
    // For values < r, this is a no-op
    // For values >= r, we subtract r

    let limbs = hash_to_limbs(hash);
    let reduced = reduce_to_fr(&limbs);
    limbs_to_fr(&reduced)
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

/// Reduce a 256-bit value mod r
fn reduce_to_fr(limbs: &[u64; 4]) -> [u64; 4] {
    use crate::field::R;

    // Check if limbs >= R
    let mut result = *limbs;
    while gte(&result, &R) {
        result = sub_no_borrow(&result, &R);
    }
    result
}

/// Check if a >= b (little-endian limbs)
fn gte(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

/// Subtract b from a (assumes a >= b)
fn sub_no_borrow(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        result[i] = d2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    result
}
/// Split a 256-bit challenge into two 128-bit values.
/// Matches Solidity: lo = challengeU256 & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF (128 bits)
///                   hi = challengeU256 >> 128
/// Returns (lower_128_bits, upper_128_bits) as Fr elements.
fn split_challenge(challenge: &Fr) -> (Fr, Fr) {
    // Challenge is 32 bytes big-endian
    // lo = lower 16 bytes (bytes 16..32), hi = upper 16 bytes (bytes 0..16)

    // Lower 128 bits: bytes 16..32 of the big-endian representation
    let mut lower = SCALAR_ZERO;
    lower[16..32].copy_from_slice(&challenge[16..32]);

    // Upper 128 bits: bytes 0..16 of the big-endian representation
    let mut upper = SCALAR_ZERO;
    upper[16..32].copy_from_slice(&challenge[0..16]);

    (lower, upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transcript_deterministic() {
        let mut t1 = Transcript::new();
        let mut t2 = Transcript::new();

        t1.append_bytes(b"hello");
        t2.append_bytes(b"hello");

        assert_eq!(t1.challenge(), t2.challenge());
    }

    #[test]
    fn test_transcript_different_inputs() {
        let mut t1 = Transcript::new();
        let mut t2 = Transcript::new();

        t1.append_bytes(b"hello");
        t2.append_bytes(b"world");

        assert_ne!(t1.challenge(), t2.challenge());
    }

    #[test]
    fn test_challenge_split() {
        let mut t = Transcript::new();
        t.append_bytes(b"test");

        let (lower, upper) = t.challenge_split();

        // Both should be valid Fr elements (< r)
        // Lower should have zeros in upper 16 bytes
        assert!(lower[0..16].iter().all(|&b| b == 0));
        // Upper should have zeros in upper 16 bytes (after moving from lower position)
        assert!(upper[0..16].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_append_u64() {
        let mut t1 = Transcript::new();
        let mut t2 = Transcript::new();

        t1.append_u64(12345);

        // Should be equivalent to appending 32 bytes with value in last 8
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&12345u64.to_be_bytes());
        t2.append_bytes(&bytes);

        assert_eq!(t1.challenge(), t2.challenge());
    }

    #[test]
    fn test_reduce_hash_to_fr() {
        // Test with a value that's definitely < r
        let small = [0u8; 32];
        let result = reduce_hash_to_fr(&small);
        assert_eq!(result, [0u8; 32]);

        // Test with a value that's > r (all 0xFF)
        let large = [0xFFu8; 32];
        let result = reduce_hash_to_fr(&large);
        // Result should be reduced (not all 0xFF)
        assert_ne!(result, large);
    }
}

#[test]
fn test_eta_challenge_computation() {
    use sha3::{Digest, Keccak256};

    // Build the buffer that should be hashed for eta challenges
    let vk_hash =
        hex::decode("093e299e4b0c0559f7aa64cb989d22d9d10b1d6b343ce1a894099f63d7a85a75").unwrap();
    let public_input =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000009").unwrap();

    // Pairing point object (from proof offsets 0-15)
    let ppo = hex::decode(concat!(
        "0000000000000000000000000000000000000000000000042ab5d6d1986846cf",
        "00000000000000000000000000000000000000000000000b75c020998797da78",
        "0000000000000000000000000000000000000000000000005a107acb64952eca",
        "000000000000000000000000000000000000000000000000000031e97a575e9d",
        "00000000000000000000000000000000000000000000000b5666547acf8bd5a4",
        "00000000000000000000000000000000000000000000000c410db10a01750aeb",
        "00000000000000000000000000000000000000000000000d722669117f9758a4",
        "000000000000000000000000000000000000000000000000000178cbf4206471",
        "000000000000000000000000000000000000000000000000e91b8a11e7842c38",
        "000000000000000000000000000000000000000000000007fd51009034b3357f",
        "000000000000000000000000000000000000000000000009889939f81e9c7402",
        "0000000000000000000000000000000000000000000000000000f94656a2ca48",
        "000000000000000000000000000000000000000000000006fb128b46c1ddb67f",
        "0000000000000000000000000000000000000000000000093fe27776f50224bd",
        "000000000000000000000000000000000000000000000004a0c80c0da527a081",
        "0000000000000000000000000000000000000000000000000001b52c2020d746"
    ))
    .unwrap();

    // Gemini masking
    let gemini_masking = hex::decode(concat!(
        "23187927498f5cfbf450b29a71272b4a81aa1872514913ec252a8fd6ef501b1b",
        "0267ab0aadc0e98c7f3fb26fde26f82541caf5e78141caf0f1210c214d816625"
    ))
    .unwrap();

    // w1, w2, w3
    let w1 = hex::decode("092462a4ddd6c2ab48595c53c4ee761bb8569e630abf3e638c67ca4315adcfae18b1f68d440747fd0299ca6a88c11a5c831345b5eb43bd07b1d4fff389736fc6").unwrap();
    let w2 = hex::decode("195b08cdc744f7171c8b8d16561d5a35f34b7f7fc46492dda720c67abbe563a80ed23e3dec3ac5894aae98185eadaee9abfad668497c55b6a7f63c3557769fd6").unwrap();
    let w3 = hex::decode("29c3cde43ed77ccb2885781b3468009c4c60c9fac8252794e69e17d8e9ab39262a48ae684ba168ca3c21f5a5f7625342a2176bdba02f018fe00633c567b95dd4").unwrap();

    // Build buffer
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&vk_hash);
    buffer.extend_from_slice(&public_input);
    buffer.extend_from_slice(&ppo);
    buffer.extend_from_slice(&gemini_masking);
    buffer.extend_from_slice(&w1);
    buffer.extend_from_slice(&w2);
    buffer.extend_from_slice(&w3);

    println!("Buffer length: {} bytes", buffer.len());

    // Hash with Keccak256
    let mut hasher = Keccak256::new();
    hasher.update(&buffer);
    let hash = hasher.finalize();

    println!("Raw hash: {}", hex::encode(&hash));

    // Reduce mod r
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash);
    let reduced = reduce_hash_to_fr(&hash_bytes);

    println!("Reduced: {}", hex::encode(&reduced));

    // Expected from our debug output
    let expected =
        hex::decode("1a3944d67e26083de563474e54aed41ed5a2c61b13f978a4890a322e95159441").unwrap();

    println!("Expected: {}", hex::encode(&expected));

    assert_eq!(&reduced[..], &expected[..], "Hash mismatch!");
}

#[test]
fn test_eta_three_challenge_computation() {
    use sha3::{Digest, Keccak256};

    // After first challenge (eta/eta_two), the full challenge is added to hasher
    // Then hash just that to get second buffer for eta_three
    let first_challenge_full =
        hex::decode("1a3944d67e26083de563474e54aed41ed5a2c61b13f978a4890a322e95159441").unwrap();

    // Hash with Keccak256
    let mut hasher = Keccak256::new();
    hasher.update(&first_challenge_full);
    let hash = hasher.finalize();

    println!("Raw hash: {}", hex::encode(&hash));

    // Reduce mod r
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash);
    let reduced = reduce_hash_to_fr(&hash_bytes);

    println!("Reduced: {}", hex::encode(&reduced));

    // Expected from our debug output
    let expected =
        hex::decode("2d72cef8805992b6e40f26162c1e804a4bb1b646d0a91649e1794ef68656df54").unwrap();

    println!("Expected: {}", hex::encode(&expected));

    assert_eq!(&reduced[..], &expected[..], "Hash mismatch for eta_three!");
}

#[test]
fn test_libra_challenge_computation() {
    use sha3::{Digest, Keccak256};

    // From debug output:
    // After alpha challenge, hasher is reset with alpha_full
    // Then we hash to get gate_challenge
    // Gate challenge full (before split):
    let gate_challenge_full =
        hex::decode("10418e2285c3f6a8f2619942fccbf0e45208adf9d59d34bf3124c2d23b0f2660").unwrap();

    // libra_concat
    let libra_concat = hex::decode("2fd29d3a2d7db7aec93bac0ebfa1e602ae11d6822f85f9c1f04326893b37c0a218cd915c0d02a8d3422b82787d30239477a1b8c22eb9db3c7e96adeba7414092").unwrap();

    // libra_sum
    let libra_sum =
        hex::decode("1f9069771fb6c066d6574ed07af4797ce5623233c2c45ef8aa3e2dfbc8a55ce6").unwrap();

    // Build buffer: gate_challenge_full || libra_concat || libra_sum
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&gate_challenge_full);
    buffer.extend_from_slice(&libra_concat);
    buffer.extend_from_slice(&libra_sum);

    println!("Buffer length: {} bytes", buffer.len());
    println!("gate_challenge_full: {}", hex::encode(&gate_challenge_full));
    println!("libra_concat: {}", hex::encode(&libra_concat));
    println!("libra_sum: {}", hex::encode(&libra_sum));

    // Hash with Keccak256
    let mut hasher = Keccak256::new();
    hasher.update(&buffer);
    let hash = hasher.finalize();

    println!("Raw hash: {}", hex::encode(&hash));

    // Reduce mod r
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash);
    let reduced = reduce_hash_to_fr(&hash_bytes);

    println!("Reduced (libra_challenge_full): {}", hex::encode(&reduced));

    // Split to get lower 127 bits
    let (lower, _upper) = split_challenge(&reduced);
    println!("Lower 127 bits (libra_challenge): {}", hex::encode(&lower));

    // Expected from our debug output
    // libra_challenge = 0x0000000000000000000000000000000003e1c8b6e219065682b8e1be98d4a427
    let expected_lower =
        hex::decode("0000000000000000000000000000000003e1c8b6e219065682b8e1be98d4a427").unwrap();

    println!("Expected: {}", hex::encode(&expected_lower));

    assert_eq!(&lower[..], &expected_lower[..], "Libra challenge mismatch!");
}

#[test]
fn test_libra_initial_target() {
    use crate::field::fr_mul;

    // From our debug output
    let libra_sum =
        hex::decode("1f9069771fb6c066d6574ed07af4797ce5623233c2c45ef8aa3e2dfbc8a55ce6").unwrap();
    let libra_challenge =
        hex::decode("0000000000000000000000000000000003e1c8b6e219065682b8e1be98d4a427").unwrap();

    let mut sum_arr = [0u8; 32];
    let mut chal_arr = [0u8; 32];
    sum_arr.copy_from_slice(&libra_sum);
    chal_arr.copy_from_slice(&libra_challenge);

    // Compute product
    let product = fr_mul(&sum_arr, &chal_arr);

    println!("libra_sum: {}", hex::encode(&sum_arr));
    println!("libra_challenge: {}", hex::encode(&chal_arr));
    println!("product: {}", hex::encode(&product));

    // Expected from debug output
    // initial_target (libra_sum * libra_challenge) = 0x0a7cf578bcc7e079691f1258336d286bab00d03e0ec8152da82012133d62c566
    let expected =
        hex::decode("0a7cf578bcc7e079691f1258336d286bab00d03e0ec8152da82012133d62c566").unwrap();
    println!("expected: {}", hex::encode(&expected));

    assert_eq!(&product[..], &expected[..], "Multiplication mismatch!");
}

#[test]
fn test_libra_initial_target_full_challenge() {
    use crate::field::fr_mul;

    // From our debug output - using FULL libra_challenge (before split)
    let libra_sum =
        hex::decode("1f9069771fb6c066d6574ed07af4797ce5623233c2c45ef8aa3e2dfbc8a55ce6").unwrap();
    let libra_challenge_full =
        hex::decode("22fe6f5b1255d87612ffb11c5e60ce6203e1c8b6e219065682b8e1be98d4a427").unwrap();

    let mut sum_arr = [0u8; 32];
    let mut chal_arr = [0u8; 32];
    sum_arr.copy_from_slice(&libra_sum);
    chal_arr.copy_from_slice(&libra_challenge_full);

    // Compute product with FULL challenge
    let product = fr_mul(&sum_arr, &chal_arr);

    println!("libra_sum: {}", hex::encode(&sum_arr));
    println!("libra_challenge_full: {}", hex::encode(&chal_arr));
    println!("product: {}", hex::encode(&product));

    // Check if this matches u[0] + u[1]
    let u0 =
        hex::decode("1f68b522be16df59e0acc7849881cea4cef64b1e46ecfa3d32c37eac593e98a2").unwrap();
    let u1 =
        hex::decode("118cb84bd4df3a01c9fe5774c08d4fb325f9c03fb2f5186b73c59f284d6ccaf4").unwrap();

    let mut u0_arr = [0u8; 32];
    let mut u1_arr = [0u8; 32];
    u0_arr.copy_from_slice(&u0);
    u1_arr.copy_from_slice(&u1);

    let sum_univariates = crate::field::fr_add(&u0_arr, &u1_arr);
    println!("u[0] + u[1]: {}", hex::encode(&sum_univariates));

    if product == sum_univariates {
        println!("MATCH with FULL challenge!");
    } else {
        println!("No match with full challenge either");
    }
}

#[test]
fn test_backwards_compute_libra_challenge() {
    use crate::field::{fr_inv, fr_mul};

    // The sum u[0] + u[1] that bb must be using as the initial target
    let target =
        hex::decode("00911efbb1c47931f25ad942d78dc5faccbc23158028a21762a72840b6ab6395").unwrap();

    // libra_sum from proof
    let libra_sum =
        hex::decode("1f9069771fb6c066d6574ed07af4797ce5623233c2c45ef8aa3e2dfbc8a55ce6").unwrap();

    let mut target_arr = [0u8; 32];
    let mut sum_arr = [0u8; 32];
    target_arr.copy_from_slice(&target);
    sum_arr.copy_from_slice(&libra_sum);

    // Compute: implied_challenge = target / libra_sum
    if let Some(sum_inv) = fr_inv(&sum_arr) {
        let implied_challenge = fr_mul(&target_arr, &sum_inv);

        println!("target (u[0]+u[1]): {}", hex::encode(&target_arr));
        println!("libra_sum: {}", hex::encode(&sum_arr));
        println!("implied_challenge: {}", hex::encode(&implied_challenge));

        // Compare with our computed libra_challenge
        let our_libra_challenge =
            hex::decode("0000000000000000000000000000000003e1c8b6e219065682b8e1be98d4a427")
                .unwrap();
        println!("our_libra_challenge: {}", hex::encode(&our_libra_challenge));

        // Full challenge (before split)
        let full_challenge =
            hex::decode("22fe6f5b1255d87612ffb11c5e60ce6203e1c8b6e219065682b8e1be98d4a427")
                .unwrap();
        println!("full_challenge: {}", hex::encode(&full_challenge));

        // Are any of these equal to implied_challenge?
        if implied_challenge[..] == our_libra_challenge[..] {
            println!("MATCH: bb uses lower 127 bits");
        } else if implied_challenge[..] == full_challenge[..] {
            println!("MATCH: bb uses full challenge");
        } else {
            println!("NO MATCH - bb uses something different!");
        }
    } else {
        println!("Failed to compute inverse");
    }
}

#[test]
fn test_actual_eta_computation() {
    use sha3::{Digest, Keccak256};

    // Load actual proof if available
    let Ok(proof_bytes) = std::fs::read("../../test-circuits/simple_square/target/keccak/proof")
    else {
        println!("⚠️  Proof file not found. Skipping test.");
        return;
    };

    // bb 0.87: Pairing point object from proof (offset 0, 16*32 bytes)
    let ppo = &proof_bytes[0..512];

    // bb 0.87: Wire commitments are now limbed (128 bytes each)
    // Format: [x_0, x_1, y_0, y_1] for each G1 point
    let witness_start = 512; // After PPO
    let w1_limbed = &proof_bytes[witness_start..witness_start + 128];

    // Just verify we can read the proof structure without crashing
    assert!(!ppo.is_empty(), "PPO should not be empty");
    assert!(!w1_limbed.is_empty(), "W1 should not be empty");

    // Test that Keccak256 hashing works
    let mut hasher = Keccak256::new();
    hasher.update(ppo);
    let hash = hasher.finalize();

    println!("PPO hash: {}", hex::encode(&hash));
    assert_ne!(hash.as_slice(), &[0u8; 32], "Hash should not be zero");
}

#[test]
fn test_full_challenge_chain() {
    use sha3::{Digest, Keccak256};

    // Load actual proof
    let proof_bytes =
        std::fs::read("../../test-circuits/simple_square/target/keccak/proof").unwrap();

    // VK hash
    let vk_hash =
        hex::decode("093e299e4b0c0559f7aa64cb989d22d9d10b1d6b343ce1a894099f63d7a85a75").unwrap();

    // Public input
    let public_input =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000009").unwrap();

    // Pairing point object
    let ppo = &proof_bytes[0..512];

    // Wire commitments
    let w1 = &proof_bytes[16 * 32..18 * 32];
    let w2 = &proof_bytes[18 * 32..20 * 32];
    let w3 = &proof_bytes[20 * 32..22 * 32];

    // 1. Eta hash: [vkHash || pi || ppo || w1 || w2 || w3]
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&vk_hash);
    buffer.extend_from_slice(&public_input);
    buffer.extend_from_slice(ppo);
    buffer.extend_from_slice(w1);
    buffer.extend_from_slice(w2);
    buffer.extend_from_slice(w3);
    let eta_full = Keccak256::digest(&buffer);
    let eta_full_reduced = reduce_hash_to_fr(&eta_full.into());
    println!("eta_full: {}", hex::encode(&eta_full_reduced));

    // 2. eta_three hash: [eta_full]
    let eta_three_full = Keccak256::digest(&eta_full_reduced);
    let eta_three_reduced = reduce_hash_to_fr(&eta_three_full.into());
    println!("eta_three_full: {}", hex::encode(&eta_three_reduced));

    // 3. beta/gamma hash: [eta_three_full || lookup_counts || lookup_tags || w4]
    let lookup_counts = &proof_bytes[22 * 32..24 * 32];
    let lookup_tags = &proof_bytes[24 * 32..26 * 32];
    let w4 = &proof_bytes[26 * 32..28 * 32];

    let mut buffer = Vec::new();
    buffer.extend_from_slice(&eta_three_reduced);
    buffer.extend_from_slice(lookup_counts);
    buffer.extend_from_slice(lookup_tags);
    buffer.extend_from_slice(w4);
    let beta_full = Keccak256::digest(&buffer);
    let beta_full_reduced = reduce_hash_to_fr(&beta_full.into());
    println!("beta_full: {}", hex::encode(&beta_full_reduced));

    // 4. alpha hash: [beta_full || lookup_inverses || z_perm]
    let lookup_inverses = &proof_bytes[28 * 32..30 * 32];
    let z_perm = &proof_bytes[30 * 32..32 * 32];

    let mut buffer = Vec::new();
    buffer.extend_from_slice(&beta_full_reduced);
    buffer.extend_from_slice(lookup_inverses);
    buffer.extend_from_slice(z_perm);
    let alpha_full = Keccak256::digest(&buffer);
    let alpha_full_reduced = reduce_hash_to_fr(&alpha_full.into());
    println!("alpha_full: {}", hex::encode(&alpha_full_reduced));

    // 5. gate_challenge hash: [alpha_full]
    let gate_full = Keccak256::digest(&alpha_full_reduced);
    let gate_full_reduced = reduce_hash_to_fr(&gate_full.into());
    println!("gate_challenge_full: {}", hex::encode(&gate_full_reduced));

    // 6. libra_challenge hash: [gate_full || libra_concat || libra_sum]
    let libra_concat = &proof_bytes[32 * 32..34 * 32];
    let libra_sum = &proof_bytes[34 * 32..35 * 32];

    let mut buffer = Vec::new();
    buffer.extend_from_slice(&gate_full_reduced);
    buffer.extend_from_slice(libra_concat);
    buffer.extend_from_slice(libra_sum);
    let libra_full = Keccak256::digest(&buffer);
    let libra_full_reduced = reduce_hash_to_fr(&libra_full.into());
    println!("libra_challenge_full: {}", hex::encode(&libra_full_reduced));

    let (libra_split, _) = split_challenge(&libra_full_reduced);
    println!("libra_challenge (split): {}", hex::encode(&libra_split));

    // Compare with our debug output
    println!("\nExpected from debug:");
    println!(
        "gate_challenge_full: 16f6a95b6af3024dbea95d58c58ec7dc600583509d216a2b42494c3c9aeb4c42"
    );
    println!("libra_challenge: 4fcd4587b42514cc22bab3a051962383");
}
