//! Sumcheck verification for UltraHonk
//!
//! The sumcheck protocol verifies that the prover correctly evaluated the
//! constraint polynomials over the boolean hypercube.
//!
//! Algorithm:
//! 1. Initialize target = 0, pow_partial = 1
//! 2. For each round r in 0..log_n:
//!    - Check that univariate[0] + univariate[1] == target
//!    - Compute next target using barycentric interpolation
//!    - Update pow_partial with gate challenge
//! 3. Accumulate all 26 subrelations using sumcheck evaluations
//! 4. Verify that accumulated value equals final target

extern crate alloc;
use alloc::vec::Vec;

use crate::field::{
    batch_inv, batch_inv_limbs, fr_add, fr_inv, fr_mul, fr_sub, FrLimbs,
};
use crate::proof::Proof;
use crate::types::{Fr, SCALAR_ONE, SCALAR_ZERO};

/// Relation parameters for sumcheck evaluation
#[derive(Debug, Clone)]
pub struct RelationParameters {
    pub eta: Fr,
    pub eta_two: Fr,
    pub eta_three: Fr,
    pub beta: Fr,
    pub gamma: Fr,
    pub public_inputs_delta: Fr,
}

/// Challenges for sumcheck verification
#[derive(Debug, Clone)]
pub struct SumcheckChallenges {
    pub gate_challenges: Vec<Fr>,
    pub sumcheck_u_challenges: Vec<Fr>,
    pub alphas: Vec<Fr>,
}

/// Number of subrelations in UltraHonk
pub const NUM_SUBRELATIONS: usize = 26;

/// Number of coefficients per sumcheck univariate (8 for non-ZK, 9 for ZK)
pub const UNIVARIATE_LENGTH_NON_ZK: usize = 8;
pub const UNIVARIATE_LENGTH_ZK: usize = 9;

/// Barycentric interpolation coefficients for 8-point evaluation
/// These are precomputed constants from the BN254 scalar field
const BARY_8: [[u8; 32]; 8] = [
    // 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51
    hex_to_bytes32("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51"),
    // 0x00000000000000000000000000000000000000000000000000000000000002d0
    hex_to_bytes32("00000000000000000000000000000000000000000000000000000000000002d0"),
    // 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff11
    hex_to_bytes32("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff11"),
    // 0x0000000000000000000000000000000000000000000000000000000000000090
    hex_to_bytes32("0000000000000000000000000000000000000000000000000000000000000090"),
    // 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff71
    hex_to_bytes32("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffff71"),
    // 0x00000000000000000000000000000000000000000000000000000000000000f0
    hex_to_bytes32("00000000000000000000000000000000000000000000000000000000000000f0"),
    // 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31
    hex_to_bytes32("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31"),
    // 0x00000000000000000000000000000000000000000000000000000000000013b0
    hex_to_bytes32("00000000000000000000000000000000000000000000000000000000000013b0"),
];

/// Barycentric interpolation coefficients for 9-point evaluation (ZK proofs)
/// d_i = product((i-j) for j != i) for i in 0..9
const BARY_9: [[u8; 32]; 9] = [
    // d_0 = 40320 = 8!
    hex_to_bytes32("0000000000000000000000000000000000000000000000000000000000009d80"),
    // d_1 = -5040 mod r
    hex_to_bytes32("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51"),
    // d_2 = 1440
    hex_to_bytes32("00000000000000000000000000000000000000000000000000000000000005a0"),
    // d_3 = -720 mod r
    hex_to_bytes32("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31"),
    // d_4 = 576
    hex_to_bytes32("0000000000000000000000000000000000000000000000000000000000000240"),
    // d_5 = -720 mod r
    hex_to_bytes32("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffd31"),
    // d_6 = 1440
    hex_to_bytes32("00000000000000000000000000000000000000000000000000000000000005a0"),
    // d_7 = -5040 mod r
    hex_to_bytes32("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffec51"),
    // d_8 = 40320
    hex_to_bytes32("0000000000000000000000000000000000000000000000000000000000009d80"),
];

/// Precomputed Fr values for 0..9 (avoids fr_from_u64 calls in hot loops)
const I_FR: [[u8; 32]; 9] = [
    hex_to_bytes32("0000000000000000000000000000000000000000000000000000000000000000"), // 0
    hex_to_bytes32("0000000000000000000000000000000000000000000000000000000000000001"), // 1
    hex_to_bytes32("0000000000000000000000000000000000000000000000000000000000000002"), // 2
    hex_to_bytes32("0000000000000000000000000000000000000000000000000000000000000003"), // 3
    hex_to_bytes32("0000000000000000000000000000000000000000000000000000000000000004"), // 4
    hex_to_bytes32("0000000000000000000000000000000000000000000000000000000000000005"), // 5
    hex_to_bytes32("0000000000000000000000000000000000000000000000000000000000000006"), // 6
    hex_to_bytes32("0000000000000000000000000000000000000000000000000000000000000007"), // 7
    hex_to_bytes32("0000000000000000000000000000000000000000000000000000000000000008"), // 8
];

/// Toggle for using FrLimbs-native implementation (for A/B testing)
const USE_FR_LIMBS: bool = true;

// ============================================================================
// Precomputed FrLimbs Constants (in Montgomery form)
// Generated by test: generate_fr_limbs_constants
// ============================================================================

/// I_FR_LIMBS: 0..9 in Montgomery form
const I_FR_LIMBS: [FrLimbs; 9] = [
    FrLimbs::from_mont_limbs([
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ]), // 0
    FrLimbs::from_mont_limbs([
        0xac96341c4ffffffb,
        0x36fc76959f60cd29,
        0x666ea36f7879462e,
        0x0e0a77c19a07df2f,
    ]), // 1
    FrLimbs::from_mont_limbs([
        0x592c68389ffffff6,
        0x6df8ed2b3ec19a53,
        0xccdd46def0f28c5c,
        0x1c14ef83340fbe5e,
    ]), // 2
    FrLimbs::from_mont_limbs([
        0x05c29c54effffff1,
        0xa4f563c0de22677d,
        0x334bea4e696bd28a,
        0x2a1f6744ce179d8e,
    ]), // 3
    FrLimbs::from_mont_limbs([
        0x6e76dadd4fffffeb,
        0xb3bdf20e03c9c415,
        0xe16a48076063c05b,
        0x07c5909386eddc93,
    ]), // 4
    FrLimbs::from_mont_limbs([
        0x1b0d0ef99fffffe6,
        0xeaba68a3a32a913f,
        0x47d8eb76d8dd0689,
        0x15d0085520f5bbc3,
    ]), // 5
    FrLimbs::from_mont_limbs([
        0xc7a34315efffffe1,
        0x21b6df39428b5e68,
        0xae478ee651564cb8,
        0x23da8016bafd9af2,
    ]), // 6
    FrLimbs::from_mont_limbs([
        0x3057819e4fffffdb,
        0x307f6d866832bb01,
        0x5c65ec9f484e3a89,
        0x0180a96573d3d9f8,
    ]), // 7
    FrLimbs::from_mont_limbs([
        0xdcedb5ba9fffffd6,
        0x677be41c0793882a,
        0xc2d4900ec0c780b7,
        0x0f8b21270ddbb927,
    ]), // 8
];

/// BARY_8_LIMBS: barycentric coefficients for 8-point (non-ZK)
const BARY_8_LIMBS: [FrLimbs; 8] = [
    FrLimbs::from_mont_limbs([
        0x2330830990006827,
        0x3645d47de0fb29b5,
        0xb08cc36a469a4e86,
        0x1f269efc77a0593b,
    ]), // d_0
    FrLimbs::from_mont_limbs([
        0x3edb076dfffff120,
        0xfbe0c9ed59958f2e,
        0x55f305399bfd9649,
        0x2bf1132a3dd1936a,
    ]), // d_1
    FrLimbs::from_mont_limbs([
        0xc2f84be8a00004f6,
        0x7182578bddf470a6,
        0x5e39d76677ac5e25,
        0x119d2de92c308ef8,
    ]), // d_2
    FrLimbs::from_mont_limbs([
        0x354cfb3b8ffffd07,
        0x7db2808e27c0602d,
        0x1960c47906805313,
        0x25d2cc80937ae3fb,
    ]), // d_3
    FrLimbs::from_mont_limbs([
        0x0e94fa58600002fa,
        0xaa8167ba51f91064,
        0x9eef813d7b010549,
        0x0a9181f24db6bc2e,
    ]), // d_4
    FrLimbs::from_mont_limbs([
        0x80e9a9ab4ffffb0b,
        0xb6b190bc9bc4ffea,
        0x5a166e5009d4fa37,
        0x1ec72089b5011131,
    ]), // d_5
    FrLimbs::from_mont_limbs([
        0x0506ee25f0000ee1,
        0x2c531e5b2023e163,
        0x625d407ce583c213,
        0x04733b48a3600cbf,
    ]), // d_6
    FrLimbs::from_mont_limbs([
        0x20b1728a5fff97da,
        0xf1ee13ca98be46dc,
        0x07c3824c3ae709d6,
        0x113daf76699146ee,
    ]), // d_7
];

/// BARY_9_LIMBS: barycentric coefficients for 9-point (ZK)
const BARY_9_LIMBS: [FrLimbs; 9] = [
    FrLimbs::from_mont_limbs([
        0x7dc7a92b1ffcbece,
        0x3f08cdc3d27f55be,
        0xcd7b86f4d4359dfd,
        0x2924decd8a26f71c,
    ]), // d_0
    FrLimbs::from_mont_limbs([
        0x2330830990006827,
        0x3645d47de0fb29b5,
        0xb08cc36a469a4e86,
        0x1f269efc77a0593b,
    ]), // d_1
    FrLimbs::from_mont_limbs([
        0x39d419480fffe23f,
        0xcf8dab923971adcb,
        0xf395c4bcb679d436,
        0x277dd7e19a7186aa,
    ]), // d_2
    FrLimbs::from_mont_limbs([
        0x0506ee25f0000ee1,
        0x2c531e5b2023e163,
        0x625d407ce583c213,
        0x04733b48a3600cbf,
    ]), // d_3
    FrLimbs::from_mont_limbs([
        0x098e0c326ffff419,
        0x7e2e495f31d52f01,
        0x3c9240c0957d4336,
        0x061e46a9aa56af6f,
    ]), // d_4
    FrLimbs::from_mont_limbs([
        0x0506ee25f0000ee1,
        0x2c531e5b2023e163,
        0x625d407ce583c213,
        0x04733b48a3600cbf,
    ]), // d_5
    FrLimbs::from_mont_limbs([
        0x39d419480fffe23f,
        0xcf8dab923971adcb,
        0xf395c4bcb679d436,
        0x277dd7e19a7186aa,
    ]), // d_6
    FrLimbs::from_mont_limbs([
        0x2330830990006827,
        0x3645d47de0fb29b5,
        0xb08cc36a469a4e86,
        0x1f269efc77a0593b,
    ]), // d_7
    FrLimbs::from_mont_limbs([
        0x7dc7a92b1ffcbece,
        0x3f08cdc3d27f55be,
        0xcd7b86f4d4359dfd,
        0x2924decd8a26f71c,
    ]), // d_8
];

/// Convert hex string to 32-byte array at compile time
const fn hex_to_bytes32(hex: &str) -> [u8; 32] {
    let bytes = hex.as_bytes();
    let mut result = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = hex_char_to_nibble(bytes[i * 2]);
        let lo = hex_char_to_nibble(bytes[i * 2 + 1]);
        result[i] = (hi << 4) | lo;
        i += 1;
    }
    result
}

const fn hex_char_to_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Check if the sum of first two univariate coefficients equals target
/// This is the basic sumcheck round check: u[0] + u[1] == target
#[inline]
fn check_round_sum(univariate: &[Fr], target: &Fr) -> bool {
    let sum = fr_add(&univariate[0], &univariate[1]);
    sum == *target
}

/// FrLimbs version: check if u[0] + u[1] == target
#[inline]
#[allow(dead_code)]
fn check_round_sum_l(u0: &FrLimbs, u1: &FrLimbs, target: &FrLimbs) -> bool {
    let sum = u0.add(u1);
    sum == *target
}

/// Toggle for A/B testing batch inversion optimization
const USE_BATCH_INVERSION: bool = true;

/// Calculate next target using barycentric interpolation with batch inversion
/// B(χ) = ∏(χ - i) for i in 0..n
/// result = B(χ) * Σ(u[i] / (BARY[i] * (χ - i)))
///
/// OPTIMIZATION: Uses batch inversion to reduce 9 inversions to 1
/// Old: 9 inversions per round × 28 rounds = ~750K CUs
/// New: 1 inversion per round × 28 rounds = ~84K CUs  
/// Savings: ~300-400K CUs per proof
fn next_target(univariate: &[Fr], chi: &Fr, is_zk: bool) -> Result<Fr, &'static str> {
    if USE_BATCH_INVERSION {
        next_target_batch(univariate, chi, is_zk)
    } else {
        next_target_individual(univariate, chi, is_zk)
    }
}

/// Optimized version with batch inversion (ONE fr_inv call)
/// Uses FrLimbs internally to avoid byte conversion overhead between operations
fn next_target_batch(univariate: &[Fr], chi: &Fr, is_zk: bool) -> Result<Fr, &'static str> {
    if USE_FR_LIMBS {
        next_target_batch_limbs(univariate, chi, is_zk)
    } else {
        next_target_batch_bytes(univariate, chi, is_zk)
    }
}

/// FrLimbs-native version: uses PRECOMPUTED constants, all internal work in Montgomery form
/// OPTIMIZED: Uses fixed-size stack arrays instead of Vec to avoid heap allocation
///
/// CU Breakdown (measured on Solana BPF, mont_mul ≈ 2,400 CUs):
/// - Conversions (10 mont_muls): ~24K CUs
/// - chi_minus + B product (9+9 = 18 ops): ~44K CUs
/// - Denominators (9 muls): ~22K CUs
/// - Batch inversion (26 muls + 1 GCD): ~87K CUs
/// - Accumulate + result (10 muls): ~28K CUs
/// Total: ~205-215K CUs per round
fn next_target_batch_limbs(univariate: &[Fr], chi: &Fr, is_zk: bool) -> Result<Fr, &'static str> {
    let n = if is_zk { 9 } else { 8 };

    // Convert only non-constant inputs to FrLimbs
    let chi_l = FrLimbs::from_bytes(chi);

    // Convert univariate coefficients - FIXED ARRAY instead of Vec
    let mut u_limbs = [FrLimbs::ZERO; 9];
    for i in 0..n {
        u_limbs[i] = FrLimbs::from_bytes(&univariate[i]);
    }

    // Step 1: Compute chi_minus[i] = χ - i - FIXED ARRAY instead of Vec
    let mut chi_minus = [FrLimbs::ZERO; 9];
    for i in 0..n {
        chi_minus[i] = chi_l.sub(&I_FR_LIMBS[i]);
    }

    // Step 2: Compute B(χ) = ∏(χ - i)
    let mut b = FrLimbs::ONE;
    for i in 0..n {
        b = b.mul(&chi_minus[i]);
    }

    // Step 3: Compute all denominators - FIXED ARRAY instead of Vec
    let mut denoms = [FrLimbs::ZERO; 9];
    for i in 0..n {
        let bary = if is_zk {
            &BARY_9_LIMBS[i]
        } else {
            &BARY_8_LIMBS[i]
        };
        denoms[i] = bary.mul(&chi_minus[i]);
    }

    // Step 4: Batch invert using INLINE Montgomery's trick (avoids Vec allocation!)
    // Compute prefix products
    let mut prefix = [FrLimbs::ONE; 9];
    for i in 1..n {
        prefix[i] = prefix[i - 1].mul(&denoms[i - 1]);
    }

    // Compute product of all and invert
    let all_product = prefix[n - 1].mul(&denoms[n - 1]);
    let mut inv_suffix = all_product.inv().ok_or("inversion failed in barycentric")?;

    // Walk backwards to compute each inverse
    let mut denom_invs = [FrLimbs::ZERO; 9];
    for i in (0..n).rev() {
        denom_invs[i] = prefix[i].mul(&inv_suffix);
        if i > 0 {
            inv_suffix = inv_suffix.mul(&denoms[i]);
        }
    }

    // Step 5: Accumulate: acc = Σ(u[i] * denom_inv[i])
    let mut acc = FrLimbs::ZERO;
    for i in 0..n {
        let term = u_limbs[i].mul(&denom_invs[i]);
        acc = acc.add(&term);
    }

    // result = B(χ) * acc
    let result = b.mul(&acc);

    // Convert back to bytes ONCE at the end
    Ok(result.to_bytes())
}

/// Fully FrLimbs-native version: takes FrLimbs inputs, returns FrLimbs
/// For use in loops where state is kept in FrLimbs throughout
#[allow(dead_code)]
fn next_target_l(
    univariate: &[FrLimbs],
    chi: &FrLimbs,
    is_zk: bool,
) -> Result<FrLimbs, &'static str> {
    let n = if is_zk { 9 } else { 8 };

    // Step 1: Compute chi_minus[i] = χ - i using PRECOMPUTED I_FR_LIMBS
    let chi_minus: Vec<FrLimbs> = (0..n).map(|i| chi.sub(&I_FR_LIMBS[i])).collect();

    // Step 2: Compute B(χ) = ∏(χ - i)
    let mut b = FrLimbs::ONE;
    for cm in &chi_minus {
        b = b.mul(cm);
    }

    // Step 3: Compute all denominators using PRECOMPUTED BARY_*_LIMBS
    let denoms: Vec<FrLimbs> = (0..n)
        .map(|i| {
            let bary = if is_zk {
                &BARY_9_LIMBS[i]
            } else {
                &BARY_8_LIMBS[i]
            };
            bary.mul(&chi_minus[i])
        })
        .collect();

    // Step 4: Batch invert all denominators
    let denom_invs = batch_inv_limbs(&denoms).ok_or("batch inversion failed in barycentric")?;

    // Step 5: Accumulate: acc = Σ(u[i] * denom_inv[i])
    let mut acc = FrLimbs::ZERO;
    for i in 0..n {
        let term = univariate[i].mul(&denom_invs[i]);
        acc = acc.add(&term);
    }

    // result = B(χ) * acc
    Ok(b.mul(&acc))
}

/// Original version using Fr (bytes) throughout
fn next_target_batch_bytes(univariate: &[Fr], chi: &Fr, is_zk: bool) -> Result<Fr, &'static str> {
    let n = if is_zk { 9 } else { 8 };

    // Step 1: Compute chi_minus[i] = χ - i for all i (reused in both B(χ) and denominators)
    let mut chi_minus = Vec::with_capacity(n);
    for i in 0..n {
        chi_minus.push(fr_sub(chi, &I_FR[i]));
    }

    // Step 2: Compute B(χ) = ∏(χ - i)
    let mut b = SCALAR_ONE;
    for cm in &chi_minus {
        b = fr_mul(&b, cm);
    }

    // Step 3: Compute all denominators: denom[i] = BARY[i] * (χ - i)
    let mut denoms = Vec::with_capacity(n);
    for i in 0..n {
        let bary_i = if is_zk { &BARY_9[i] } else { &BARY_8[i] };
        denoms.push(fr_mul(bary_i, &chi_minus[i]));
    }

    // Step 4: Batch invert all denominators with only ONE inversion!
    let denom_invs = batch_inv(&denoms).ok_or("batch inversion failed in barycentric")?;

    // Step 5: Accumulate: acc = Σ(u[i] * denom_inv[i])
    let mut acc = SCALAR_ZERO;
    for i in 0..n {
        let term = fr_mul(&univariate[i], &denom_invs[i]);
        acc = fr_add(&acc, &term);
    }

    // result = B(χ) * acc
    Ok(fr_mul(&b, &acc))
}

/// Original version with individual inversions (9 fr_inv calls per round)
fn next_target_individual(univariate: &[Fr], chi: &Fr, is_zk: bool) -> Result<Fr, &'static str> {
    let n = if is_zk { 9 } else { 8 };

    // Compute B(χ) = ∏(χ - i)
    let mut b = SCALAR_ONE;
    for i in 0..n {
        let chi_minus_i = fr_sub(chi, &I_FR[i]);
        b = fr_mul(&b, &chi_minus_i);
    }

    // Accumulate: acc = Σ(u[i] / (BARY[i] * (χ - i)))
    let mut acc = SCALAR_ZERO;
    for i in 0..n {
        let chi_minus_i = fr_sub(chi, &I_FR[i]);
        let bary_i = if is_zk { &BARY_9[i] } else { &BARY_8[i] };
        let denom = fr_mul(bary_i, &chi_minus_i);
        let denom_inv = fr_inv(&denom).ok_or("inversion failed in barycentric")?;
        let term = fr_mul(&univariate[i], &denom_inv);
        acc = fr_add(&acc, &term);
    }

    // result = B(χ) * acc
    Ok(fr_mul(&b, &acc))
}

/// Update pow_partial for the next round (bytes version)
/// pow = pow * (1 + χ * (gate_challenge - 1))
#[inline]
fn update_pow(pow: &Fr, gate_challenge: &Fr, chi: &Fr) -> Fr {
    // gate_challenge - 1
    let gc_minus_one = fr_sub(gate_challenge, &SCALAR_ONE);

    // χ * (gate_challenge - 1)
    let chi_term = fr_mul(chi, &gc_minus_one);

    // 1 + χ * (gate_challenge - 1)
    let factor = fr_add(&SCALAR_ONE, &chi_term);

    // pow * factor
    fr_mul(pow, &factor)
}

/// Update pow_partial for the next round (FrLimbs version)
/// pow = pow * (1 + χ * (gate_challenge - 1))
/// For use when caller maintains state in FrLimbs
#[inline]
#[allow(dead_code)]
fn update_pow_l(pow: &FrLimbs, gate_challenge: &FrLimbs, chi: &FrLimbs) -> FrLimbs {
    // gate_challenge - 1
    let gc_minus_one = gate_challenge.sub(&FrLimbs::ONE);

    // χ * (gate_challenge - 1)
    let chi_term = chi.mul(&gc_minus_one);

    // 1 + χ * (gate_challenge - 1)
    let factor = FrLimbs::ONE.add(&chi_term);

    // pow * factor
    pow.mul(&factor)
}

/// Verify the sumcheck protocol round by round
///
/// # Arguments
/// * `proof` - The parsed proof containing sumcheck univariates and evaluations
/// * `challenges` - The sumcheck challenges
/// * `log_n` - log2 of circuit size
///
/// # Returns
/// * `Ok((target, pow_partial))` - The final target and pow_partial for relation evaluation
/// * `Err` - If any round check fails
fn verify_sumcheck_rounds(
    proof: &Proof,
    challenges: &SumcheckChallenges,
    libra_challenge: Option<&Fr>,
    log_n: usize,
) -> Result<(Fr, Fr), &'static str> {
    // For ZK proofs, initial target = libra_sum * libra_challenge
    // For non-ZK proofs, initial target is 0
    let mut target = if proof.is_zk {
        let libra_sum = proof.libra_sum();
        if let Some(lc) = libra_challenge {
            fr_mul(&libra_sum, lc)
        } else {
            libra_sum
        }
    } else {
        SCALAR_ZERO
    };
    let mut pow_partial = SCALAR_ONE;

    crate::trace!(
        "===== SUMCHECK VERIFICATION (log_n = {}, is_zk = {}) =====",
        log_n,
        proof.is_zk
    );
    crate::dbg_fr!("initial_target (libra_sum * libra_challenge)", &target);

    // Process each round
    for round in 0..log_n {
        // Get univariate coefficients for this round
        let univariate = proof.sumcheck_univariates_for_round(round);

        // Check round sum: u[0] + u[1] == target
        let _sum = fr_add(&univariate[0], &univariate[1]);
        if round < 3 {
            crate::trace!("--- Round {} ---", round);
            crate::dbg_fr!(&alloc::format!("u[{}][0]", round), &univariate[0]);
            crate::dbg_fr!(&alloc::format!("u[{}][1]", round), &univariate[1]);
            crate::dbg_fr!("sum(u[0]+u[1])", &sum);
            crate::dbg_fr!("target", &target);
        }

        if !check_round_sum(&univariate, &target) {
            crate::trace!("FAILED: round {} sum check", round);
            return Err("sumcheck round sum check failed");
        }

        // Get challenge for this round
        let chi = &challenges.sumcheck_u_challenges[round];
        if round < 3 {
            crate::dbg_fr!("chi", chi);
        }

        // Compute next target using barycentric interpolation
        target = next_target(&univariate, chi, proof.is_zk)
            .map_err(|_| "barycentric interpolation failed")?;
        if round < 3 {
            crate::dbg_fr!("next_target", &target);
        }

        // Update pow_partial
        let gate_challenge = &challenges.gate_challenges[round];
        pow_partial = update_pow(&pow_partial, gate_challenge, chi);
        if round < 3 {
            crate::dbg_fr!("pow_partial", &pow_partial);
        }
    }

    crate::trace!("===== SUMCHECK ROUNDS PASSED =====");
    crate::dbg_fr!("final_target", &target);
    crate::dbg_fr!("final_pow_partial", &pow_partial);

    Ok((target, pow_partial))
}

// ============================================================================
// Incremental Sumcheck Verification (for multi-TX verification)
// ============================================================================

/// Intermediate state for partial sumcheck round verification
#[derive(Clone)]
pub struct SumcheckRoundsState {
    pub target: Fr,
    pub pow_partial: Fr,
    pub rounds_completed: usize,
}

/// Initialize sumcheck rounds state
#[inline(never)]
pub fn sumcheck_rounds_init(proof: &Proof, libra_challenge: Option<&Fr>) -> SumcheckRoundsState {
    // For ZK proofs, initial target = libra_sum * libra_challenge
    // For non-ZK proofs, initial target is 0
    let target = if proof.is_zk {
        let libra_sum = proof.libra_sum();
        if let Some(lc) = libra_challenge {
            fr_mul(&libra_sum, lc)
        } else {
            libra_sum
        }
    } else {
        SCALAR_ZERO
    };

    SumcheckRoundsState {
        target,
        pow_partial: SCALAR_ONE,
        rounds_completed: 0,
    }
}

/// Verify a range of sumcheck rounds [start_round, end_round)
/// Returns updated state or error
#[inline(never)]
pub fn verify_sumcheck_rounds_partial(
    proof: &Proof,
    challenges: &SumcheckChallenges,
    state: &SumcheckRoundsState,
    start_round: usize,
    end_round: usize,
) -> Result<SumcheckRoundsState, &'static str> {
    let mut target = state.target;
    let mut pow_partial = state.pow_partial;

    #[cfg(feature = "solana")]
    {
        solana_program::msg!("Sumcheck rounds {}-{}", start_round, end_round);
        solana_program::log::sol_log_compute_units();
    }

    for round in start_round..end_round {
        if round >= proof.log_n {
            break;
        }

        // Get univariate coefficients for this round
        let univariate = proof.sumcheck_univariates_for_round(round);

        // Check round sum: u[0] + u[1] == target
        if !check_round_sum(&univariate, &target) {
            return Err("sumcheck round sum check failed");
        }

        // Get challenge for this round
        let chi = &challenges.sumcheck_u_challenges[round];

        // Compute next target using barycentric interpolation (~210K CUs per round)
        target = next_target(&univariate, chi, proof.is_zk)
            .map_err(|_| "barycentric interpolation failed")?;

        // Update pow_partial (~10K CUs)
        let gate_challenge = &challenges.gate_challenges[round];
        pow_partial = update_pow(&pow_partial, gate_challenge, chi);
    }

    #[cfg(feature = "solana")]
    {
        solana_program::msg!("Rounds {}-{} complete", start_round, end_round);
        solana_program::log::sol_log_compute_units();
    }

    Ok(SumcheckRoundsState {
        target,
        pow_partial,
        rounds_completed: end_round.min(proof.log_n),
    })
}

/// Verify relations and final check (after all rounds completed)
/// Uses verifier::RelationParameters for compatibility with phased verification
#[inline(never)]
pub fn verify_sumcheck_relations(
    proof: &Proof,
    relation_params: &crate::verifier::RelationParameters,
    alphas: &[Fr],
    sumcheck_u_challenges: &[Fr],
    state: &SumcheckRoundsState,
    libra_challenge: Option<&Fr>,
) -> Result<(), &'static str> {
    let target = &state.target;
    let pow_partial = &state.pow_partial;

    #[cfg(feature = "solana")]
    {
        solana_program::msg!("Sumcheck: relations");
        solana_program::log::sol_log_compute_units();
    }

    // Convert to local RelationParameters
    let local_params = RelationParameters {
        eta: relation_params.eta,
        eta_two: relation_params.eta_two,
        eta_three: relation_params.eta_three,
        beta: relation_params.beta,
        gamma: relation_params.gamma,
        public_inputs_delta: relation_params.public_input_delta,
    };

    // Accumulate relation evaluations
    let mut grand = accumulate_relations(proof, &local_params, alphas, pow_partial)?;

    #[cfg(feature = "solana")]
    {
        solana_program::msg!("Sumcheck: after relations");
        solana_program::log::sol_log_compute_units();
    }

    // ZK adjustment (for ZK proofs)
    // Solidity: grandHonkRelationSum = grandHonkRelationSum * (1 - evaluation) + libraEvaluation * libraChallenge
    // where evaluation = product(sumCheckUChallenges[2..log_n])
    if proof.is_zk {
        if let Some(libra_chal) = libra_challenge {
            let libra_eval = proof.libra_evaluation();
            // Compute evaluation = product(sumcheck_challenges[2..log_n])
            let mut evaluation = SCALAR_ONE;
            for i in 2..proof.log_n {
                evaluation = fr_mul(&evaluation, &sumcheck_u_challenges[i]);
            }

            // grand = grand * (1 - evaluation) + libraEvaluation * libraChallenge
            let one_minus_eval = fr_sub(&SCALAR_ONE, &evaluation);
            let libra_term = fr_mul(&libra_eval, libra_chal);
            let grand_scaled = fr_mul(&grand, &one_minus_eval);
            grand = fr_add(&grand_scaled, &libra_term);
        }
    }

    // Check that grand == target
    if grand == *target {
        Ok(())
    } else {
        Err("sumcheck final check failed")
    }
}

/// Verify the complete sumcheck protocol including relation evaluation
///
/// This performs:
/// 1. Round-by-round univariate checks
/// 2. Final relation accumulation
/// 3. ZK adjustment (for ZK proofs)
/// 4. Check that accumulated value equals final target
#[inline(never)]
pub fn verify_sumcheck(
    proof: &Proof,
    challenges: &SumcheckChallenges,
    relation_params: &RelationParameters,
    libra_challenge: Option<&Fr>,
) -> Result<(), &'static str> {
    let log_n = proof.log_n;

    #[cfg(feature = "solana")]
    {
        solana_program::msg!("Sumcheck: before rounds");
        solana_program::log::sol_log_compute_units();
    }

    // Step 1: Verify all rounds and get final target/pow_partial
    let (target, pow_partial) = verify_sumcheck_rounds(proof, challenges, libra_challenge, log_n)?;

    #[cfg(feature = "solana")]
    {
        solana_program::msg!("Sumcheck: after rounds, before relations");
        solana_program::log::sol_log_compute_units();
    }

    // Step 2: Accumulate relation evaluations
    crate::trace!("===== RELATION ACCUMULATION =====");
    crate::dbg_fr!("beta", &relation_params.beta);
    crate::dbg_fr!("gamma", &relation_params.gamma);
    crate::dbg_fr!("public_inputs_delta", &relation_params.public_inputs_delta);

    let mut grand = accumulate_relations(proof, relation_params, &challenges.alphas, &pow_partial)?;

    #[cfg(feature = "solana")]
    {
        solana_program::msg!("Sumcheck: after relations");
        solana_program::log::sol_log_compute_units();
    }

    crate::dbg_fr!("grand_relation (before ZK adjustment)", &grand);

    // Step 3: ZK adjustment (for ZK proofs)
    // Solidity: grandHonkRelationSum = grandHonkRelationSum * (1 - evaluation) + libraEvaluation * libraChallenge
    // where evaluation = product(sumCheckUChallenges[2..LOG_N])
    if proof.is_zk {
        if let Some(libra_chal) = libra_challenge {
            let libra_eval = proof.libra_evaluation();
            // Compute evaluation = product(sumcheck_challenges[2..log_n])
            let mut evaluation = SCALAR_ONE;
            for i in 2..log_n {
                evaluation = fr_mul(&evaluation, &challenges.sumcheck_u_challenges[i]);
            }
            crate::dbg_fr!("ZK evaluation (prod of u[2..])", &evaluation);

            // grand = grand * (1 - evaluation) + libraEvaluation * libraChallenge
            let one_minus_eval = fr_sub(&SCALAR_ONE, &evaluation);
            let libra_term = fr_mul(&libra_eval, libra_chal);
            let grand_scaled = fr_mul(&grand, &one_minus_eval);

            crate::dbg_fr!("1 - evaluation", &one_minus_eval);
            crate::dbg_fr!("libra_term (eval*challenge)", &libra_term);
            crate::dbg_fr!("grand * (1-eval)", &grand_scaled);

            grand = fr_add(&grand_scaled, &libra_term);

            crate::dbg_fr!("libra_evaluation", &libra_eval);
            crate::dbg_fr!("libra_challenge", libra_chal);
            crate::dbg_fr!("grand_relation (after ZK adjustment)", &grand);
        }
    }

    crate::trace!("===== FINAL CHECK =====");
    crate::dbg_fr!("grand_relation", &grand);
    crate::dbg_fr!("target", &target);

    // Debug: compute expected grand_before_ZK from target
    #[cfg(feature = "debug")]
    if proof.is_zk {
        if let Some(libra_chal) = libra_challenge {
            let libra_eval = proof.libra_evaluation();
            let mut evaluation = SCALAR_ONE;
            for i in 2..proof.log_n {
                evaluation = fr_mul(&evaluation, &challenges.sumcheck_u_challenges[i]);
            }
            let one_minus_eval = fr_sub(&SCALAR_ONE, &evaluation);
            let libra_term = fr_mul(&libra_eval, libra_chal);

            // target = grand * (1-eval) + libra_term
            // grand = (target - libra_term) / (1-eval)
            let numerator = fr_sub(&target, &libra_term);
            if let Some(_expected_grand) = crate::field::fr_div(&numerator, &one_minus_eval) {
                crate::trace!("===== EXPECTED VS ACTUAL =====");
                crate::dbg_fr!("expected grand_before_ZK (from target)", &_expected_grand);
                crate::dbg_fr!(
                    "actual grand_before_ZK",
                    &accumulate_relations(proof, relation_params, &challenges.alphas, &pow_partial)
                        .unwrap()
                );
            }
        }
    }

    // Step 4: Check that grand == target
    if grand == target {
        crate::trace!("SUMCHECK PASSED!");
        Ok(())
    } else {
        crate::trace!("SUMCHECK FAILED: grand != target");
        Err("sumcheck final relation check failed")
    }
}

/// Accumulate all 26 subrelations using sumcheck evaluations
///
/// This evaluates all constraint polynomials at the sumcheck point and
/// combines them using the alpha challenges.
///
/// Uses FrLimbs internally for faster computation (avoids per-operation byte conversions).
fn accumulate_relations(
    proof: &Proof,
    relation_params: &RelationParameters,
    alphas: &[Fr],
    pow_partial: &Fr,
) -> Result<Fr, &'static str> {
    // Get sumcheck evaluations (40 or 41 Fr values)
    let evals = proof.sumcheck_evaluations();

    if evals.len() < 40 {
        return Err("insufficient sumcheck evaluations");
    }

    // Convert all inputs to FrLimbs once at the boundary
    let evals_l: Vec<FrLimbs> = evals.iter().map(FrLimbs::from_bytes).collect();
    let alphas_l: Vec<FrLimbs> = alphas.iter().map(FrLimbs::from_bytes).collect();
    let pow_partial_l = FrLimbs::from_bytes(pow_partial);

    // Convert relation parameters to FrLimbs
    let rp_fr = crate::relations::RelationParameters {
        eta: relation_params.eta,
        eta_two: relation_params.eta_two,
        eta_three: relation_params.eta_three,
        beta: relation_params.beta,
        gamma: relation_params.gamma,
        public_inputs_delta: relation_params.public_inputs_delta,
    };
    let rp_l = crate::relations::RelationParametersLimbs::from_fr(&rp_fr);

    // Accumulate using FrLimbs (faster - no per-operation byte conversions)
    let grand_l = crate::relations::accumulate_relation_evaluations_l(
        &evals_l,
        &rp_l,
        &alphas_l,
        &pow_partial_l,
    );

    // Convert result back to Fr at the boundary
    Ok(grand_l.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bary_constants() {
        // Verify BARY_8 constants are valid Fr elements (not zero)
        for (i, bary) in BARY_8.iter().enumerate() {
            // Check it's not all zeros (except for the small value ones)
            let sum: u64 = bary.iter().map(|&b| b as u64).sum();
            assert!(sum > 0, "BARY_8[{}] is all zeros", i);
        }
    }

    #[test]
    fn test_check_round_sum() {
        let a = fr_from_u64(5);
        let b = fr_from_u64(7);
        let target = fr_from_u64(12);

        assert!(check_round_sum(&[a, b], &target));

        let wrong_target = fr_from_u64(13);
        assert!(!check_round_sum(&[a, b], &wrong_target));
    }

    #[test]
    fn test_update_pow() {
        let pow = SCALAR_ONE;
        let gate_challenge = fr_from_u64(2);
        let chi = fr_from_u64(3);

        // pow * (1 + chi * (gate_challenge - 1))
        // = 1 * (1 + 3 * (2 - 1))
        // = 1 * (1 + 3 * 1)
        // = 1 * 4
        // = 4
        let result = update_pow(&pow, &gate_challenge, &chi);
        let expected = fr_from_u64(4);
        assert_eq!(result, expected);
    }

    /// Generate FrLimbs constants for hardcoding
    /// Run with: cargo test generate_fr_limbs_constants -- --nocapture
    #[test]
    fn generate_fr_limbs_constants() {
        println!("\n=== FrLimbs Constants for Hardcoding ===\n");

        // I_FR constants (0..9)
        println!("// I_FR_LIMBS: 0..9 in Montgomery form");
        println!("const I_FR_LIMBS: [FrLimbs; 9] = [");
        for i in 0..9 {
            let fr_limbs = FrLimbs::from_bytes(&I_FR[i]);
            let limbs = fr_limbs.as_limbs();
            println!(
                "    FrLimbs::from_mont_limbs([0x{:016x}, 0x{:016x}, 0x{:016x}, 0x{:016x}]), // {}",
                limbs[0], limbs[1], limbs[2], limbs[3], i
            );
        }
        println!("];\n");

        // BARY_8 constants
        println!("// BARY_8_LIMBS: barycentric coefficients for 8-point (non-ZK)");
        println!("const BARY_8_LIMBS: [FrLimbs; 8] = [");
        for i in 0..8 {
            let fr_limbs = FrLimbs::from_bytes(&BARY_8[i]);
            let limbs = fr_limbs.as_limbs();
            println!(
                "    FrLimbs::from_mont_limbs([0x{:016x}, 0x{:016x}, 0x{:016x}, 0x{:016x}]), // d_{}",
                limbs[0], limbs[1], limbs[2], limbs[3], i
            );
        }
        println!("];\n");

        // BARY_9 constants
        println!("// BARY_9_LIMBS: barycentric coefficients for 9-point (ZK)");
        println!("const BARY_9_LIMBS: [FrLimbs; 9] = [");
        for i in 0..9 {
            let fr_limbs = FrLimbs::from_bytes(&BARY_9[i]);
            let limbs = fr_limbs.as_limbs();
            println!(
                "    FrLimbs::from_mont_limbs([0x{:016x}, 0x{:016x}, 0x{:016x}, 0x{:016x}]), // d_{}",
                limbs[0], limbs[1], limbs[2], limbs[3], i
            );
        }
        println!("];");

        // Verify by roundtrip
        println!("\n=== Verification ===");
        for i in 0..9 {
            let original = &I_FR[i];
            let limbs = FrLimbs::from_bytes(original);
            let back = limbs.to_bytes();
            assert_eq!(original, &back, "I_FR[{}] roundtrip failed", i);
        }
        println!("All I_FR roundtrips passed!");

        for i in 0..8 {
            let original = &BARY_8[i];
            let limbs = FrLimbs::from_bytes(original);
            let back = limbs.to_bytes();
            assert_eq!(original, &back, "BARY_8[{}] roundtrip failed", i);
        }
        println!("All BARY_8 roundtrips passed!");

        for i in 0..9 {
            let original = &BARY_9[i];
            let limbs = FrLimbs::from_bytes(original);
            let back = limbs.to_bytes();
            assert_eq!(original, &back, "BARY_9[{}] roundtrip failed", i);
        }
        println!("All BARY_9 roundtrips passed!");
    }
}
