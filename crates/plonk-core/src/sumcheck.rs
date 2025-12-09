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

use crate::field::{batch_inv, fr_add, fr_from_u64, fr_mul, fr_sub};
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

/// Calculate next target using barycentric interpolation with batch inversion
/// B(χ) = ∏(χ - i) for i in 0..n
/// result = B(χ) * Σ(u[i] / (BARY[i] * (χ - i)))
///
/// OPTIMIZATION: Uses batch inversion to reduce 9 inversions to 1
/// Old: 9 inversions per round × 28 rounds = ~750K CUs
/// New: 1 inversion per round × 28 rounds = ~84K CUs  
/// Savings: ~300-400K CUs per proof
fn next_target(univariate: &[Fr], chi: &Fr, is_zk: bool) -> Result<Fr, &'static str> {
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

/// Update pow_partial for the next round
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
        let sum = fr_add(&univariate[0], &univariate[1]);
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

        // Compute next target using barycentric interpolation
        target = next_target(&univariate, chi, proof.is_zk)
            .map_err(|_| "barycentric interpolation failed")?;

        // Update pow_partial
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
            if let Some(expected_grand) = crate::field::fr_div(&numerator, &one_minus_eval) {
                crate::trace!("===== EXPECTED VS ACTUAL =====");
                crate::dbg_fr!("expected grand_before_ZK (from target)", &expected_grand);
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

    // Convert our RelationParameters to the relations module format
    let rp = crate::relations::RelationParameters {
        eta: relation_params.eta,
        eta_two: relation_params.eta_two,
        eta_three: relation_params.eta_three,
        beta: relation_params.beta,
        gamma: relation_params.gamma,
        public_inputs_delta: relation_params.public_inputs_delta,
    };

    // Accumulate all 28 subrelations (bb 0.87)
    let grand = crate::relations::accumulate_relation_evaluations(&evals, &rp, alphas, pow_partial);

    Ok(grand)
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
}
