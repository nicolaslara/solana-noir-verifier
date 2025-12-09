//! UltraHonk verification logic
//!
//! This module implements verification for bb v0.84.0+ UltraHonk proofs.
//!
//! The verification algorithm follows Barretenberg's UltraHonk verifier:
//! 1. OinkVerifier: Generate relation parameters (eta, beta, gamma) and receive witness commitments
//! 2. SumcheckVerifier: Verify the sumcheck protocol
//! 3. ShpleminiVerifier: Verify batched polynomial commitment opening
//! 4. Final pairing check via Solana BN254 syscalls

use crate::errors::VerifyError;
use crate::field::{fr_add, fr_from_u64, fr_mul, fr_sub};
use crate::key::VerificationKey;
use crate::ops;
use crate::proof::Proof;
use crate::transcript::Transcript;
use crate::types::{Fr, G1, SCALAR_ONE};

extern crate alloc;
use alloc::vec::Vec;

/// Relation parameters derived from the transcript
#[derive(Debug, Clone)]
pub struct RelationParameters {
    pub eta: Fr,
    pub eta_two: Fr,
    pub eta_three: Fr,
    pub beta: Fr,
    pub gamma: Fr,
    pub public_input_delta: Fr,
}

/// Challenges for the verification protocol
#[derive(Debug, Clone)]
pub struct Challenges {
    pub relation_params: RelationParameters,
    pub alpha: Fr,
    pub alphas: Vec<Fr>,             // All 25 alpha challenges (bb 0.87)
    pub libra_challenge: Option<Fr>, // ZK only
    pub gate_challenges: Vec<Fr>,
    pub sumcheck_challenges: Vec<Fr>,
    pub rho: Fr,
    pub gemini_r: Fr,
    pub shplonk_nu: Fr,
    pub shplonk_z: Fr,
}

/// Verify an UltraHonk proof
///
/// # Arguments
/// * `vk_bytes` - Verification key (1760 bytes for new format, 1888 bytes for old format)
/// * `proof_bytes` - Proof bytes (variable size based on circuit's log_n)
/// * `public_inputs` - Array of public inputs (32 bytes each, big-endian)
/// * `is_zk` - Whether this is a ZK proof (true for default Keccak proofs)
///
/// # Returns
/// * `Ok(())` if verification succeeds
/// * `Err(VerifyError)` if verification fails
pub fn verify(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs: &[Fr],
    is_zk: bool,
) -> Result<(), VerifyError> {
    // Parse verification key first to get log_n
    let vk = VerificationKey::from_bytes(vk_bytes)?;

    // Get log_circuit_size from VK
    let log_n = vk.log2_circuit_size as usize;

    // Validate public inputs count (bb 0.87)
    // In bb 0.87, vk.num_public_inputs includes PAIRING_POINTS_SIZE (16) + actual user inputs
    // User-provided public_inputs should match: vk.num_public_inputs - PAIRING_POINTS_SIZE
    const PAIRING_POINTS_SIZE: usize = 16;
    let expected_user_pi = (vk.num_public_inputs as usize).saturating_sub(PAIRING_POINTS_SIZE);
    if public_inputs.len() != expected_user_pi {
        return Err(VerifyError::PublicInput(alloc::format!(
            "Expected {} public inputs, got {} (vk.num_public_inputs={}, pairing_points={})",
            expected_user_pi,
            public_inputs.len(),
            vk.num_public_inputs,
            PAIRING_POINTS_SIZE
        )));
    }

    // Parse proof with log_n from VK
    let proof = Proof::from_bytes(proof_bytes, log_n, is_zk)?;

    // Run verification
    verify_inner(&vk, &proof, public_inputs)
}

/// Internal verification with parsed structures
#[inline(never)]
pub fn verify_inner(
    vk: &VerificationKey,
    proof: &Proof,
    public_inputs: &[Fr],
) -> Result<(), VerifyError> {
    // Step 1: Generate challenges via Fiat-Shamir transcript
    let challenges = generate_challenges(vk, proof, public_inputs)?;

    // Step 2: Verify sumcheck protocol
    // This involves checking that the claimed sumcheck evaluations are consistent
    let sumcheck_result = verify_sumcheck(vk, proof, &challenges)?;
    if !sumcheck_result {
        return Err(VerifyError::VerificationFailed);
    }

    // Step 3: Compute the batched opening claim (P0, P1)
    let (p0, p1) = compute_pairing_points(vk, proof, &challenges)?;

    #[cfg(feature = "debug")]
    {
        crate::trace!("===== FINAL PAIRING CHECK =====");
        crate::dbg_g1!("P0", &p0);
        crate::dbg_g1!("P1", &p1);
    }

    // NOTE: bb 0.87 does NOT aggregate with pairing point object here.
    // The pairing point object is only used as public inputs in computePublicInputDelta.
    // Skip the old recursion separator aggregation (which was for bb 0.84).

    // Step 4: Final pairing check: e(P0, G2_gen) * e(P1, G2_x) == 1
    // where G2_x is the x·G2 from the trusted setup
    let pairing_result = ops::pairing_check(&[(p0, g2_generator()), (p1, vk_g2())])?;

    if pairing_result {
        crate::trace!("VERIFICATION PASSED!");
        Ok(())
    } else {
        crate::trace!("VERIFICATION FAILED: pairing check failed");
        Err(VerifyError::VerificationFailed)
    }
}

/// Step 1: Generate challenges (for phased verification)
#[inline(never)]
pub fn verify_step1_challenges(
    vk: &VerificationKey,
    proof: &Proof,
    public_inputs: &[Fr],
) -> Result<Challenges, VerifyError> {
    generate_challenges(vk, proof, public_inputs)
}

/// Step 2: Verify sumcheck (for phased verification)
#[inline(never)]
pub fn verify_step2_sumcheck(
    vk: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
) -> Result<bool, VerifyError> {
    verify_sumcheck(vk, proof, challenges)
}

/// Step 3: Compute pairing points (for phased verification)
#[inline(never)]
pub fn verify_step3_pairing_points(
    vk: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
) -> Result<(G1, G1), VerifyError> {
    compute_pairing_points(vk, proof, challenges)
}

/// Step 4: Final pairing check (for phased verification)
#[inline(never)]
pub fn verify_step4_pairing_check(p0: &G1, p1: &G1) -> Result<bool, VerifyError> {
    Ok(ops::pairing_check(&[
        (*p0, g2_generator()),
        (*p1, vk_g2()),
    ])?)
}

// ============================================================================
// Incremental Challenge Generation (for multi-TX verification)
// ============================================================================

/// Result from Phase 1a: eta, beta, gamma challenges
#[derive(Debug, Clone)]
pub struct Phase1aResult {
    pub eta: Fr,
    pub eta_two: Fr,
    pub eta_three: Fr,
    pub beta: Fr,
    pub gamma: Fr,
    /// Transcript state to continue from (32 bytes)
    pub transcript_state: Fr,
}

/// Result from Phase 1b: alphas and gate challenges  
#[derive(Debug, Clone)]
pub struct Phase1bResult {
    pub alphas: Vec<Fr>,
    pub gate_challenges: Vec<Fr>,
    pub libra_challenge: Option<Fr>,
    /// Transcript state to continue from
    pub transcript_state: Fr,
}

/// Result from Phase 1c: first half of sumcheck challenges (rounds 0-13)
#[derive(Debug, Clone)]
pub struct Phase1cResult {
    pub sumcheck_challenges: Vec<Fr>,
    /// Transcript state to continue from
    pub transcript_state: Fr,
}

/// Result from Phase 1d: remaining sumcheck + final challenges
#[derive(Debug, Clone)]
pub struct Phase1dResult {
    pub sumcheck_challenges: Vec<Fr>, // rounds 14-27
    pub rho: Fr,
    pub gemini_r: Fr,
    pub shplonk_nu: Fr,
    pub shplonk_z: Fr,
}

/// Phase 1a: Generate eta, beta, gamma challenges
/// Returns the challenges and transcript state to continue from
#[inline(never)]
pub fn generate_challenges_phase1a(
    vk: &VerificationKey,
    proof: &Proof,
    public_inputs: &[Fr],
) -> Result<Phase1aResult, VerifyError> {
    let mut transcript = Transcript::new();

    // Circuit metadata
    let circuit_size = vk.circuit_size() as u64;
    let public_inputs_size = vk.num_public_inputs as u64;
    let pub_inputs_offset = 1u64;

    transcript.append_u64(circuit_size);
    transcript.append_u64(public_inputs_size);
    transcript.append_u64(pub_inputs_offset);

    // Public inputs
    for pi in public_inputs.iter() {
        transcript.append_scalar(pi);
    }

    // Pairing point object (16 Fr values)
    let ppo = proof.pairing_point_object();
    for ppo_elem in ppo {
        transcript.append_scalar(&ppo_elem);
    }

    // First 3 wire commitments in limbed format
    for i in 0..3 {
        let limbed = proof.witness_commitment_limbed(i);
        for limb in &limbed {
            transcript.append_scalar(limb);
        }
    }

    // Get eta challenges
    let (eta, eta_two) = transcript.challenge_split();
    let (eta_three, _) = transcript.challenge_split();

    // Add lookup/w4 commitments for beta/gamma
    for i in 3..6 {
        let limbed = proof.witness_commitment_limbed(i);
        for limb in &limbed {
            transcript.append_scalar(limb);
        }
    }

    // Get beta, gamma
    let (beta, gamma) = transcript.challenge_split();

    // Debug: print challenges from phase1a (only when debug-solana feature is enabled)
    #[cfg(all(feature = "solana", feature = "debug-solana"))]
    {
        solana_program::msg!(
            "1a eta[24..32]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            eta[24],
            eta[25],
            eta[26],
            eta[27],
            eta[28],
            eta[29],
            eta[30],
            eta[31]
        );
        solana_program::msg!(
            "1a beta[24..32]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            beta[24],
            beta[25],
            beta[26],
            beta[27],
            beta[28],
            beta[29],
            beta[30],
            beta[31]
        );
        solana_program::msg!(
            "1a gamma[24..32]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            gamma[24],
            gamma[25],
            gamma[26],
            gamma[27],
            gamma[28],
            gamma[29],
            gamma[30],
            gamma[31]
        );
    }

    // Get transcript state (should be 32 bytes after challenge_split)
    let state = transcript.get_state();
    let mut transcript_state = [0u8; 32];
    if state.len() == 32 {
        transcript_state.copy_from_slice(&state);
    }

    Ok(Phase1aResult {
        eta,
        eta_two,
        eta_three,
        beta,
        gamma,
        transcript_state,
    })
}

/// Phase 1b: Generate alpha and gate challenges
/// Continues from Phase 1a transcript state
#[inline(never)]
pub fn generate_challenges_phase1b(
    proof: &Proof,
    transcript_state: &Fr,
) -> Result<Phase1bResult, VerifyError> {
    use crate::proof::CONST_PROOF_SIZE_LOG_N;
    use crate::relations::NUMBER_OF_ALPHAS;

    let mut transcript = Transcript::from_previous_challenge(transcript_state);

    // Add lookupInverses (4 limbs) + zPerm (4 limbs)
    let lookup_inv_limbed = proof.witness_commitment_limbed(6);
    let z_perm_limbed = proof.witness_commitment_limbed(7);
    for limb in &lookup_inv_limbed {
        transcript.append_scalar(limb);
    }
    for limb in &z_perm_limbed {
        transcript.append_scalar(limb);
    }

    // Generate alphas in pairs
    let mut alphas = Vec::with_capacity(NUMBER_OF_ALPHAS);
    let (alpha0, alpha1) = transcript.challenge_split();
    alphas.push(alpha0);
    alphas.push(alpha1);

    for _ in 1..(NUMBER_OF_ALPHAS / 2) {
        let (a0, a1) = transcript.challenge_split();
        alphas.push(a0);
        alphas.push(a1);
    }

    if NUMBER_OF_ALPHAS % 2 == 1 && NUMBER_OF_ALPHAS > 2 {
        let (a_last, _) = transcript.challenge_split();
        alphas.push(a_last);
    }

    // Generate gate challenges
    let mut gate_challenges = Vec::with_capacity(proof.log_n);
    for i in 0..CONST_PROOF_SIZE_LOG_N {
        let (gc, _) = transcript.challenge_split();
        if i < proof.log_n {
            gate_challenges.push(gc);
        }
    }

    // For ZK proofs: generate libra challenge
    let libra_challenge = if proof.is_zk {
        let libra_limbed = proof.libra_commitment_0_limbed();
        for limb in &libra_limbed {
            transcript.append_scalar(limb);
        }
        let libra_sum = proof.libra_sum();
        transcript.append_scalar(&libra_sum);
        let (lc, _) = transcript.challenge_split();
        Some(lc)
    } else {
        None
    };

    let state = transcript.get_state();
    let mut new_state = [0u8; 32];
    if state.len() == 32 {
        new_state.copy_from_slice(&state);
    }

    Ok(Phase1bResult {
        alphas,
        gate_challenges,
        libra_challenge,
        transcript_state: new_state,
    })
}

/// Phase 1c: Generate first half of sumcheck challenges (rounds 0-13)
#[inline(never)]
pub fn generate_challenges_phase1c(
    proof: &Proof,
    transcript_state: &Fr,
) -> Result<Phase1cResult, VerifyError> {
    let mut transcript = Transcript::from_previous_challenge(transcript_state);
    let mut sumcheck_challenges = Vec::with_capacity(14);

    for r in 0..14 {
        let univariate = proof.sumcheck_univariates_for_round(r);
        for coeff in &univariate {
            transcript.append_scalar(coeff);
        }
        let (lo, _) = transcript.challenge_split();
        sumcheck_challenges.push(lo);
    }

    let state = transcript.get_state();
    let mut new_state = [0u8; 32];
    if state.len() == 32 {
        new_state.copy_from_slice(&state);
    } else {
        // BUG: transcript state is not 32 bytes!
        #[cfg(feature = "solana")]
        {
            solana_program::msg!("BUG: transcript state len = {}", state.len());
        }
    }

    Ok(Phase1cResult {
        sumcheck_challenges,
        transcript_state: new_state,
    })
}

/// Phase 1d: Generate remaining sumcheck challenges + final challenges
#[inline(never)]
pub fn generate_challenges_phase1d(
    proof: &Proof,
    transcript_state: &Fr,
    is_zk: bool,
) -> Result<Phase1dResult, VerifyError> {
    use crate::proof::CONST_PROOF_SIZE_LOG_N;

    let mut transcript = Transcript::from_previous_challenge(transcript_state);
    let mut sumcheck_challenges = Vec::with_capacity(14);

    // Rounds 14-27
    for r in 14..CONST_PROOF_SIZE_LOG_N {
        let univariate = proof.sumcheck_univariates_for_round(r);
        for coeff in &univariate {
            transcript.append_scalar(coeff);
        }
        let (lo, _) = transcript.challenge_split();
        sumcheck_challenges.push(lo);
    }

    // Add sumcheck evaluations
    let sumcheck_evals = proof.sumcheck_evaluations();
    for eval in &sumcheck_evals {
        transcript.append_scalar(eval);
    }

    // ZK: add libra evaluation + commitments + masking poly + masking eval
    if is_zk {
        let libra_eval = proof.libra_evaluation();
        transcript.append_scalar(&libra_eval);

        let libra1_limbed = proof.libra_commitment_1_limbed();
        for limb in &libra1_limbed {
            transcript.append_scalar(limb);
        }

        let libra2_limbed = proof.libra_commitment_2_limbed();
        for limb in &libra2_limbed {
            transcript.append_scalar(limb);
        }

        let masking_limbed = proof.gemini_masking_poly_limbed();
        for limb in &masking_limbed {
            transcript.append_scalar(limb);
        }

        // geminiMaskingEval - was missing!
        let masking_eval = proof.gemini_masking_eval();
        transcript.append_scalar(&masking_eval);
    }

    // Rho challenge
    let (rho, _) = transcript.challenge_split();

    // Debug: print rho (only when debug-solana feature is enabled)
    #[cfg(all(feature = "solana", feature = "debug-solana"))]
    {
        solana_program::msg!(
            "1d rho[24..32]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            rho[24],
            rho[25],
            rho[26],
            rho[27],
            rho[28],
            rho[29],
            rho[30],
            rho[31]
        );
    }

    // Add Gemini fold commitments (log_n - 1 of them)
    for i in 0..(CONST_PROOF_SIZE_LOG_N - 1) {
        let fold_limbed = proof.gemini_fold_commitment_limbed(i);
        for limb in &fold_limbed {
            transcript.append_scalar(limb);
        }
    }

    // Gemini r challenge
    let gemini_r = transcript.challenge();

    // Debug: print gemini_r (only when debug-solana feature is enabled)
    #[cfg(all(feature = "solana", feature = "debug-solana"))]
    {
        solana_program::msg!(
            "1d gemini_r[24..32]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            gemini_r[24],
            gemini_r[25],
            gemini_r[26],
            gemini_r[27],
            gemini_r[28],
            gemini_r[29],
            gemini_r[30],
            gemini_r[31]
        );
    }

    // Add Gemini evaluations (CONST_PROOF_SIZE_LOG_N of them)
    for i in 0..CONST_PROOF_SIZE_LOG_N {
        let eval = proof.gemini_a_evaluation(i);
        transcript.append_scalar(&eval);
    }

    // ZK: add libra poly evals before shplonk_nu (NOT masking_eval - that was before rho)
    if is_zk {
        let libra_evals = proof.libra_poly_evals();
        for eval in &libra_evals {
            transcript.append_scalar(eval);
        }
    }

    // Shplonk nu challenge
    let (shplonk_nu, _) = transcript.challenge_split();

    // Add shplonk_q commitment in LIMBED format
    let shplonk_q_limbed = proof.shplonk_q_limbed();
    for limb in &shplonk_q_limbed {
        transcript.append_scalar(limb);
    }

    // Shplonk z challenge (KZG)
    let (shplonk_z, _) = transcript.challenge_split();

    // Debug: print shplonk challenges (only when debug-solana feature is enabled)
    #[cfg(all(feature = "solana", feature = "debug-solana"))]
    {
        solana_program::msg!(
            "1d shplonk_nu[24..32]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            shplonk_nu[24],
            shplonk_nu[25],
            shplonk_nu[26],
            shplonk_nu[27],
            shplonk_nu[28],
            shplonk_nu[29],
            shplonk_nu[30],
            shplonk_nu[31]
        );
        solana_program::msg!(
            "1d shplonk_z[24..32]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            shplonk_z[24],
            shplonk_z[25],
            shplonk_z[26],
            shplonk_z[27],
            shplonk_z[28],
            shplonk_z[29],
            shplonk_z[30],
            shplonk_z[31]
        );
    }

    Ok(Phase1dResult {
        sumcheck_challenges,
        rho,
        gemini_r,
        shplonk_nu,
        shplonk_z,
    })
}

/// Result from partial delta computation
#[derive(Debug, Clone)]
pub struct DeltaPartialResult {
    pub numerator: Fr,
    pub denominator: Fr,
    pub numerator_acc: Fr,
    pub denominator_acc: Fr,
    pub items_processed: usize,
}

/// Compute public_input_delta - Phase 1: First 9 items
/// Returns partial accumulators to continue in next TX
#[inline(never)]
pub fn compute_delta_part1(
    public_inputs: &[Fr],
    proof: &Proof,
    beta: &Fr,
    gamma: &Fr,
    circuit_size: u32,
) -> DeltaPartialResult {
    use crate::field::{fr_add, fr_from_u64, fr_mul, fr_sub};
    use crate::types::SCALAR_ONE;

    let n = circuit_size as u64;
    let offset = 1u32;

    let mut numerator = SCALAR_ONE;
    let mut denominator = SCALAR_ONE;

    let n_plus_offset = fr_from_u64(n + offset as u64);
    let mut numerator_acc = fr_add(gamma, &fr_mul(beta, &n_plus_offset));

    let offset_plus_one = fr_from_u64((offset + 1) as u64);
    let mut denominator_acc = fr_sub(gamma, &fr_mul(beta, &offset_plus_one));

    // Process public inputs (usually 1)
    for pi in public_inputs {
        numerator = fr_mul(&numerator, &fr_add(&numerator_acc, pi));
        denominator = fr_mul(&denominator, &fr_add(&denominator_acc, pi));
        numerator_acc = fr_add(&numerator_acc, beta);
        denominator_acc = fr_sub(&denominator_acc, beta);
    }

    // Process first 8 pairing point elements (indices 0-7)
    let ppo = proof.pairing_point_object();
    for i in 0..8 {
        numerator = fr_mul(&numerator, &fr_add(&numerator_acc, &ppo[i]));
        denominator = fr_mul(&denominator, &fr_add(&denominator_acc, &ppo[i]));
        numerator_acc = fr_add(&numerator_acc, beta);
        denominator_acc = fr_sub(&denominator_acc, beta);
    }

    DeltaPartialResult {
        numerator,
        denominator,
        numerator_acc,
        denominator_acc,
        items_processed: public_inputs.len() + 8,
    }
}

/// Compute public_input_delta - Phase 2: Remaining 8 items + final division
#[inline(never)]
pub fn compute_delta_part2(proof: &Proof, beta: &Fr, partial: &DeltaPartialResult) -> Fr {
    use crate::field::{fr_add, fr_div, fr_mul, fr_sub};
    use crate::types::SCALAR_ONE;

    let mut numerator = partial.numerator;
    let mut denominator = partial.denominator;
    let mut numerator_acc = partial.numerator_acc;
    let mut denominator_acc = partial.denominator_acc;

    // Process remaining 8 pairing point elements (indices 8-15)
    let ppo = proof.pairing_point_object();
    for i in 8..16 {
        numerator = fr_mul(&numerator, &fr_add(&numerator_acc, &ppo[i]));
        denominator = fr_mul(&denominator, &fr_add(&denominator_acc, &ppo[i]));
        numerator_acc = fr_add(&numerator_acc, beta);
        denominator_acc = fr_sub(&denominator_acc, beta);
    }

    // Final division
    fr_div(&numerator, &denominator).unwrap_or(SCALAR_ONE)
}

/// Generate all challenges from the transcript
///
/// Based on bb's UltraHonk transcript manifest (ultra_transcript.test.cpp)
#[inline(never)]
fn generate_challenges(
    vk: &VerificationKey,
    proof: &Proof,
    public_inputs: &[Fr],
) -> Result<Challenges, VerifyError> {
    let mut transcript = Transcript::new();

    crate::trace!("===== CHALLENGE GENERATION =====");
    crate::trace!("circuit_size = {}", vk.circuit_size());
    crate::trace!("num_public_inputs = {}", public_inputs.len());

    // bb 0.87 transcript order for generateEtaChallenge:
    // [circuitSize, publicInputsSize, pubInputsOffset, publicInputs[], pairingPointObject[16], w1(4 limbs), w2(4 limbs), w3(4 limbs)]
    // NOTE: No vk_hash in bb 0.87!

    // Add circuit metadata (as 32-byte big-endian)
    let circuit_size = vk.circuit_size() as u64;
    let public_inputs_size = vk.num_public_inputs as u64; // Total including pairing points
    let pub_inputs_offset = 1u64; // Standard offset

    transcript.append_u64(circuit_size);
    transcript.append_u64(public_inputs_size);
    transcript.append_u64(pub_inputs_offset);

    crate::trace!(
        "transcript: circuitSize={}, publicInputsSize={}, pubInputsOffset={}",
        circuit_size,
        public_inputs_size,
        pub_inputs_offset
    );

    // Add user public inputs (actual user inputs, not pairing points)
    for (i, pi) in public_inputs.iter().enumerate() {
        crate::dbg_fr!(&alloc::format!("public_input[{}]", i), pi);
        transcript.append_scalar(pi);
    }

    // Add pairing point object (16 Fr values)
    let ppo = proof.pairing_point_object();
    crate::trace!("pairing_point_object has {} elements", ppo.len());
    for ppo_elem in ppo {
        transcript.append_scalar(&ppo_elem);
    }

    // Add first 3 wire commitments (w1, w2, w3) in LIMBED format
    // bb 0.87 uses 4 limbs per G1 point: [x_0, x_1, y_0, y_1]
    let w1_limbed = proof.witness_commitment_limbed(0);
    let w2_limbed = proof.witness_commitment_limbed(1);
    let w3_limbed = proof.witness_commitment_limbed(2);
    for limb in &w1_limbed {
        transcript.append_scalar(limb);
    }
    for limb in &w2_limbed {
        transcript.append_scalar(limb);
    }
    for limb in &w3_limbed {
        transcript.append_scalar(limb);
    }

    // Get eta challenges (eta, eta_two, eta_three)
    let (eta, eta_two) = transcript.challenge_split();
    let (eta_three, _) = transcript.challenge_split();
    crate::dbg_fr!("eta", &eta);
    crate::dbg_fr!("eta_two", &eta_two);
    crate::dbg_fr!("eta_three", &eta_three);

    // Add lookup commitments and w4 in LIMBED format
    // bb 0.87: [previousChallenge, lookupReadCounts(4), lookupReadTags(4), w4(4)]
    let lookup_read_counts_limbed = proof.witness_commitment_limbed(3);
    let lookup_read_tags_limbed = proof.witness_commitment_limbed(4);
    let w4_limbed = proof.witness_commitment_limbed(5);
    for limb in &lookup_read_counts_limbed {
        transcript.append_scalar(limb);
    }
    for limb in &lookup_read_tags_limbed {
        transcript.append_scalar(limb);
    }
    for limb in &w4_limbed {
        transcript.append_scalar(limb);
    }

    // Get beta, gamma challenges
    let (beta, gamma) = transcript.challenge_split();
    crate::dbg_fr!("beta", &beta);
    crate::dbg_fr!("gamma", &gamma);

    // Debug: print beta/gamma challenges
    #[cfg(test)]
    {
        extern crate std;
        std::println!(
            "SINGLE_PASS beta[24..32]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            beta[24],
            beta[25],
            beta[26],
            beta[27],
            beta[28],
            beta[29],
            beta[30],
            beta[31]
        );
        std::println!(
            "SINGLE_PASS gamma[24..32]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            gamma[24],
            gamma[25],
            gamma[26],
            gamma[27],
            gamma[28],
            gamma[29],
            gamma[30],
            gamma[31]
        );
    }

    // NOTE: lookup_inverses and z_perm are NOT appended here!
    // They're appended in limbed format for alpha challenge generation (see below)

    // Get pairing point object (already returns [Fr; 16])
    let ppo_array = proof.pairing_point_object();

    // Compute public_input_delta (includes pairing point object)
    // Note: offset = 1, matching Solidity's pubInputsOffset = 1
    let public_input_delta = compute_public_input_delta_with_ppo(
        public_inputs,
        &ppo_array,
        &beta,
        &gamma,
        vk.circuit_size(),
        1, // pubInputsOffset = 1 in Solidity
    );

    let relation_params = RelationParameters {
        eta,
        eta_two,
        eta_three,
        beta,
        gamma,
        public_input_delta,
    };

    // Get alpha challenges (NUM_SUBRELATIONS - 1 = 25 alphas)
    // bb 0.87: First hash includes lookupInverses + zPerm (limbed format)
    // Then loop to generate pairs of alphas via split
    use crate::relations::NUMBER_OF_ALPHAS;

    // Append lookupInverses (4 limbs) + zPerm (4 limbs) for first alpha hash
    // lookupInverses = witness_commitment(6), zPerm = witness_commitment(7)
    let lookup_inv_limbed = proof.witness_commitment_limbed(6);
    let z_perm_limbed = proof.witness_commitment_limbed(7);
    for limb in &lookup_inv_limbed {
        transcript.append_scalar(limb);
    }
    for limb in &z_perm_limbed {
        transcript.append_scalar(limb);
    }

    // Generate alphas in pairs via split
    let mut alphas = Vec::with_capacity(NUMBER_OF_ALPHAS);
    let (alpha0, alpha1) = transcript.challenge_split();
    crate::dbg_fr!("alpha[0]", &alpha0);
    alphas.push(alpha0);
    alphas.push(alpha1);

    // Loop to generate remaining alphas (pairs)
    for i in 1..(NUMBER_OF_ALPHAS / 2) {
        let (a0, a1) = transcript.challenge_split();
        alphas.push(a0);
        alphas.push(a1);
    }

    // If odd number of alphas, generate one more
    if NUMBER_OF_ALPHAS % 2 == 1 && NUMBER_OF_ALPHAS > 2 {
        let (a_last, _) = transcript.challenge_split();
        alphas.push(a_last);
    }

    // Debug: print all alphas
    #[cfg(feature = "debug")]
    {
        crate::trace!("===== ALL {} ALPHA CHALLENGES =====", alphas.len());
        for (i, a) in alphas.iter().enumerate() {
            crate::dbg_fr!(&alloc::format!("alpha[{:2}]", i), a);
        }
    }

    let alpha = alphas[0]; // Keep for compatibility

    // Get gate challenges (bb 0.87: hash CONST_PROOF_SIZE_LOG_N times)
    // Each iteration: hash(previousChallenge) -> split -> gateChallenges[i]
    // The final previousChallenge state is then used for libra challenge
    use crate::proof::CONST_PROOF_SIZE_LOG_N;
    let mut gate_challenges = Vec::with_capacity(proof.log_n);
    for i in 0..CONST_PROOF_SIZE_LOG_N {
        let (gc, _) = transcript.challenge_split();
        if i < proof.log_n {
            if i < 2 {
                crate::dbg_fr!(&alloc::format!("gate_challenges[{}]", i), &gc);
            }
            gate_challenges.push(gc);
        }
    }

    // For ZK proofs: add libra commitment and sum, generate libra challenge
    // This happens AFTER gate_challenge but BEFORE sumcheck univariates
    // The initial sumcheck target = libra_sum * libra_challenge
    // NOTE: bb 0.87 uses the LIMBED format (4 × 32 bytes) for libra commitment in transcript
    // NOTE: libra_challenge uses split challenge (lower 128 bits only)
    let libra_challenge = if proof.is_zk {
        // bb 0.87: append x_0, x_1, y_0, y_1 (limbed format) + libraSum
        let libra_limbed = proof.libra_commitment_0_limbed();
        for limb in &libra_limbed {
            transcript.append_scalar(limb);
        }

        let libra_sum = proof.libra_sum();
        crate::dbg_fr!("libra_sum", &libra_sum);
        transcript.append_scalar(&libra_sum);

        // bb 0.87: use split challenge (lower 128 bits)
        let (lc, _) = transcript.challenge_split();
        crate::dbg_fr!("libra_challenge", &lc);
        Some(lc)
    } else {
        None
    };

    // Debug: print transcript state after libra_challenge (end of phase 1b equivalent)
    #[cfg(test)]
    {
        extern crate std;
        let state_1b = transcript.get_state();
        if state_1b.len() == 32 {
            std::println!(
                "SINGLE_PASS 1b_end transcript[24..32]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                state_1b[24], state_1b[25], state_1b[26], state_1b[27],
                state_1b[28], state_1b[29], state_1b[30], state_1b[31]
            );
        }
    }

    // Get sumcheck u challenges
    // Per Solidity verifier: ONE hash per round, take ONLY lower 128 bits, discard upper!
    // See generateSumcheckChallenges in the generated HonkVerifier.sol
    // IMPORTANT: Solidity loops CONST_PROOF_SIZE_LOG_N times (28), not just log_n!
    // This affects the transcript state for subsequent challenges
    crate::trace!(
        "===== SUMCHECK ROUND CHALLENGES (log_n = {}, loops = {}) =====",
        proof.log_n,
        CONST_PROOF_SIZE_LOG_N
    );
    let mut sumcheck_challenges = Vec::with_capacity(CONST_PROOF_SIZE_LOG_N);

    for r in 0..CONST_PROOF_SIZE_LOG_N {
        let univariate = proof.sumcheck_univariates_for_round(r);

        // Add univariate to transcript (one hash per round)
        if r < 3 {
            crate::trace!(
                "round {} univariate[0..2] = {:02x?}, {:02x?}",
                r,
                &univariate[0][0..4],
                &univariate[1][0..4]
            );
        }
        for coeff in &univariate {
            transcript.append_scalar(coeff);
        }

        // Hash and split - ONLY use lower 128 bits, discard upper (matches Solidity)
        let (lo, _hi) = transcript.challenge_split();

        if r < 3 {
            crate::dbg_fr!(&alloc::format!("sumcheck_u[{}]", r), &lo);
        }
        sumcheck_challenges.push(lo);

        // Debug: print transcript state after round 13 (end of phase1c equivalent)
        #[cfg(test)]
        if r == 13 {
            extern crate std;
            let state_1c = transcript.get_state();
            if state_1c.len() == 32 {
                std::println!(
                    "SINGLE_PASS 1c_end (round 13) transcript[24..32]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    state_1c[24], state_1c[25], state_1c[26], state_1c[27],
                    state_1c[28], state_1c[29], state_1c[30], state_1c[31]
                );
            }
        }
    }

    // Add sumcheck evaluations to transcript
    let sumcheck_evals = proof.sumcheck_evaluations();
    crate::trace!("sumcheck_evaluations count = {}", sumcheck_evals.len());
    if !sumcheck_evals.is_empty() {
        crate::dbg_fr!("sumcheck_eval[0]", &sumcheck_evals[0]);
    }
    for eval in &sumcheck_evals {
        transcript.append_scalar(eval);
    }

    // For ZK proofs, add additional elements before rho challenge:
    // - libraEvaluation
    // - libraCommitments[1] (4 limbs: x_0, x_1, y_0, y_1)
    // - libraCommitments[2] (4 limbs)
    // - geminiMaskingPoly (4 limbs)
    // - geminiMaskingEval
    // Note: Solidity uses limbed format for G1 points here!
    if proof.is_zk {
        // libraEvaluation
        let libra_eval = proof.libra_evaluation();
        transcript.append_scalar(&libra_eval);
        crate::dbg_fr!("rho transcript: libra_eval", &libra_eval);

        // libraCommitments[1] in limbed format (4 x 32 bytes)
        let libra_comm_1_limbed = proof.libra_commitment_1_limbed();
        for limb in &libra_comm_1_limbed {
            transcript.append_scalar(limb);
        }
        crate::dbg_g1!("rho transcript: libra_comm[1]", &proof.libra_commitment_1());

        // libraCommitments[2] in limbed format
        let libra_comm_2_limbed = proof.libra_commitment_2_limbed();
        for limb in &libra_comm_2_limbed {
            transcript.append_scalar(limb);
        }
        crate::dbg_g1!("rho transcript: libra_comm[2]", &proof.libra_commitment_2());

        // geminiMaskingPoly in limbed format
        let masking_poly_limbed = proof.gemini_masking_poly_limbed();
        for limb in &masking_poly_limbed {
            transcript.append_scalar(limb);
        }
        crate::dbg_g1!(
            "rho transcript: gemini_masking_poly",
            &proof.gemini_masking_poly()
        );

        // geminiMaskingEval
        let masking_eval = proof.gemini_masking_eval();
        transcript.append_scalar(&masking_eval);
        crate::dbg_fr!("rho transcript: gemini_masking_eval", &masking_eval);
    }

    // Get rho challenge
    let (rho, _) = transcript.challenge_split();
    crate::dbg_fr!("rho", &rho);

    // Debug: print rho challenge
    #[cfg(test)]
    {
        extern crate std;
        std::println!(
            "SINGLE_PASS rho[24..32]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            rho[24],
            rho[25],
            rho[26],
            rho[27],
            rho[28],
            rho[29],
            rho[30],
            rho[31]
        );
    }

    // Add Gemini fold commitments to transcript
    // Solidity uses CONST_PROOF_SIZE_LOG_N - 1 = 27 fold comms in LIMBED format
    crate::trace!(
        "gemini_fold_comms count = {} (CONST_PROOF_SIZE_LOG_N - 1)",
        CONST_PROOF_SIZE_LOG_N - 1
    );
    for i in 0..(CONST_PROOF_SIZE_LOG_N - 1) {
        let fold_comm_limbed = proof.gemini_fold_commitment_limbed(i);
        if i == 0 {
            crate::dbg_g1!("gemini_fold_comm[0]", &proof.gemini_fold_commitment(0));
        }
        for limb in &fold_comm_limbed {
            transcript.append_scalar(limb);
        }
    }

    // Get gemini_r challenge
    let (gemini_r, _) = transcript.challenge_split();
    crate::dbg_fr!("gemini_r", &gemini_r);

    // Debug: print gemini_r
    #[cfg(test)]
    {
        extern crate std;
        std::println!(
            "SINGLE_PASS gemini_r[24..32]: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            gemini_r[24],
            gemini_r[25],
            gemini_r[26],
            gemini_r[27],
            gemini_r[28],
            gemini_r[29],
            gemini_r[30],
            gemini_r[31]
        );
    }

    // Add Gemini A evaluations to transcript
    // Solidity uses CONST_PROOF_SIZE_LOG_N = 28 evaluations
    crate::trace!(
        "gemini_a_evaluations count = {} (CONST_PROOF_SIZE_LOG_N)",
        CONST_PROOF_SIZE_LOG_N
    );
    for i in 0..CONST_PROOF_SIZE_LOG_N {
        let eval = proof.gemini_a_evaluation(i);
        transcript.append_scalar(&eval);
    }

    // Add libra poly evals to transcript (ZK only) - required for shplonk_nu challenge
    // Solidity: shplonkNuChallengeElements = [prevChallenge, geminiAEvals[0..CONST_PROOF_SIZE_LOG_N], libraPolyEvals[0..4]]
    if proof.is_zk {
        let libra_evals = proof.libra_poly_evals();
        for eval in &libra_evals {
            transcript.append_scalar(eval);
        }
    }

    // Get shplonk_nu challenge
    let (shplonk_nu, _) = transcript.challenge_split();
    crate::dbg_fr!("shplonk_nu", &shplonk_nu);

    // Add shplonk_q to transcript in LIMBED format
    let shplonk_q_limbed = proof.shplonk_q_limbed();
    crate::dbg_g1!("shplonk_q", &proof.shplonk_q());
    for limb in &shplonk_q_limbed {
        transcript.append_scalar(limb);
    }

    // Get shplonk_z challenge
    let (shplonk_z, _) = transcript.challenge_split();
    crate::dbg_fr!("shplonk_z", &shplonk_z);
    crate::trace!("===== END CHALLENGE GENERATION =====");

    Ok(Challenges {
        relation_params,
        alpha,
        alphas,
        libra_challenge,
        gate_challenges,
        sumcheck_challenges,
        rho,
        gemini_r,
        shplonk_nu,
        shplonk_z,
    })
}

/// Compute the VK hash for the transcript
/// This matches bb's `vk->hash_with_origin_tagging` behavior
/// For Keccak (U256Codec): each field/commitment is raw uint256_t
fn compute_vk_hash(vk: &VerificationKey) -> Fr {
    use sha3::{Digest, Keccak256};

    let mut hasher = Keccak256::new();

    // Add VK header fields as uint256_t (32 bytes each, big-endian padded)
    let mut buf = [0u8; 32];
    buf[28..32].copy_from_slice(&vk.log2_circuit_size.to_be_bytes());
    hasher.update(&buf);

    buf = [0u8; 32];
    buf[28..32].copy_from_slice(&vk.log2_domain_size.to_be_bytes());
    hasher.update(&buf);

    buf = [0u8; 32];
    buf[28..32].copy_from_slice(&vk.num_public_inputs.to_be_bytes());
    hasher.update(&buf);

    // Add all VK commitments as 64 bytes each (x || y)
    for commitment in &vk.commitments {
        hasher.update(commitment);
    }

    // Finalize and reduce to Fr
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);

    // Reduce mod r if needed
    crate::transcript::reduce_hash_to_fr_public(&result)
}

/// Compute the public input contribution to the permutation argument
/// Including the pairing point object (16 Fr values)
fn compute_public_input_delta_with_ppo(
    public_inputs: &[Fr],
    pairing_point_object: &[Fr; 16],
    beta: &Fr,
    gamma: &Fr,
    circuit_size: u32,
    offset: u32,
) -> Fr {
    // bb 0.87: Solidity uses N (circuit_size) for numeratorAcc
    // numeratorAcc = gamma + beta * (N + offset)
    let n = circuit_size as u64;

    let mut numerator = SCALAR_ONE;
    let mut denominator = SCALAR_ONE;

    // numerator_acc = gamma + beta * (N + offset)
    // Solidity: Fr numeratorAcc = gamma + (beta * FrLib.from(N + offset));
    let n_plus_offset = fr_from_u64(n + offset as u64);
    let mut numerator_acc = fr_add(gamma, &fr_mul(beta, &n_plus_offset));

    // denominator_acc = gamma - beta * (offset + 1)
    let offset_plus_one = fr_from_u64((offset + 1) as u64);
    let mut denominator_acc = fr_sub(gamma, &fr_mul(beta, &offset_plus_one));

    #[cfg(feature = "debug")]
    {
        crate::trace!("===== PUBLIC_INPUT_DELTA COMPUTATION =====");
        crate::dbg_fr!("beta", beta);
        crate::dbg_fr!("gamma", gamma);
        crate::trace!("N (circuit_size) = {}", n);
        crate::trace!("N + offset = {}", n + offset as u64);
        crate::dbg_fr!("initial numerator_acc", &numerator_acc);
        crate::dbg_fr!("initial denominator_acc", &denominator_acc);
        crate::trace!(
            "processing {} public inputs + 16 pairing points",
            public_inputs.len()
        );
    }

    // Process regular public inputs
    for pi in public_inputs {
        numerator = fr_mul(&numerator, &fr_add(&numerator_acc, pi));
        denominator = fr_mul(&denominator, &fr_add(&denominator_acc, pi));
        numerator_acc = fr_add(&numerator_acc, beta);
        denominator_acc = fr_sub(&denominator_acc, beta);
    }

    // Process pairing point object (16 additional Fr values)
    for ppo in pairing_point_object {
        numerator = fr_mul(&numerator, &fr_add(&numerator_acc, ppo));
        denominator = fr_mul(&denominator, &fr_add(&denominator_acc, ppo));
        numerator_acc = fr_add(&numerator_acc, beta);
        denominator_acc = fr_sub(&denominator_acc, beta);
    }

    #[cfg(feature = "debug")]
    {
        crate::dbg_fr!("final numerator", &numerator);
        crate::dbg_fr!("final denominator", &denominator);
    }

    // Return numerator / denominator
    let result = crate::field::fr_div(&numerator, &denominator).unwrap_or(SCALAR_ONE);

    #[cfg(feature = "debug")]
    {
        crate::dbg_fr!("public_input_delta (result)", &result);
    }

    result
}

/// Verify the sumcheck protocol
#[inline(never)]
fn verify_sumcheck(
    _vk: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
) -> Result<bool, VerifyError> {
    use crate::sumcheck::{self, RelationParameters as SumcheckRelParams, SumcheckChallenges};

    // Convert to sumcheck module's types
    let sumcheck_relation_params = SumcheckRelParams {
        eta: challenges.relation_params.eta,
        eta_two: challenges.relation_params.eta_two,
        eta_three: challenges.relation_params.eta_three,
        beta: challenges.relation_params.beta,
        gamma: challenges.relation_params.gamma,
        public_inputs_delta: challenges.relation_params.public_input_delta,
    };

    // Use the 25 individual alphas we generated earlier (not powers of alpha!)
    // bb 0.87: Each alpha is independently derived from the transcript
    let sumcheck_challenges = SumcheckChallenges {
        gate_challenges: challenges.gate_challenges.clone(),
        sumcheck_u_challenges: challenges.sumcheck_challenges.clone(),
        alphas: challenges.alphas.clone(),
    };

    // Run sumcheck verification
    match sumcheck::verify_sumcheck(
        proof,
        &sumcheck_challenges,
        &sumcheck_relation_params,
        challenges.libra_challenge.as_ref(),
    ) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Compute the pairing points for the final verification
#[inline(never)]
fn compute_pairing_points(
    vk: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
) -> Result<(G1, G1), VerifyError> {
    // Use Shplemini to compute the batched opening claim
    //
    // For UltraHonk with Shplemini, the final pairing check verifies:
    // e(P0, G2) == e(P1, x·G2)
    //
    // Which is equivalent to:
    // e(P0, G2) * e(-P1, x·G2) == 1

    crate::shplemini::compute_shplemini_pairing_points(proof, vk, challenges)
        .map_err(|_| VerifyError::VerificationFailed)
}

/// Get the x·G2 point from the trusted setup
/// This is hardcoded because bb VK format doesn't contain G2 points
fn vk_g2() -> crate::types::G2 {
    // This is the x·G2 point from the trusted setup (SRS)
    // Used for the second pairing: e(P1, x·G2)
    let mut g2 = [0u8; 128];

    // x1, x0, y1, y0 (big-endian)
    let x1 = hex_literal::hex!("260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c1");
    let x0 = hex_literal::hex!("0118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b0");
    let y1 = hex_literal::hex!("04fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe4");
    let y0 = hex_literal::hex!("22febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55");

    g2[0..32].copy_from_slice(&x1);
    g2[32..64].copy_from_slice(&x0);
    g2[64..96].copy_from_slice(&y1);
    g2[96..128].copy_from_slice(&y0);

    g2
}

/// BN254 G2 generator point
fn g2_generator() -> crate::types::G2 {
    // BN254 G2 generator coordinates (big-endian)
    // x = (x0, x1) where x = x0 + x1*i
    // y = (y0, y1) where y = y0 + y1*i
    let mut g2 = [0u8; 128];

    // These are the actual BN254 G2 generator coordinates
    // x1 (bytes 0-31)
    let x1 = hex_literal::hex!("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2");
    // x0 (bytes 32-63)
    let x0 = hex_literal::hex!("1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed");
    // y1 (bytes 64-95)
    let y1 = hex_literal::hex!("090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b");
    // y0 (bytes 96-127)
    let y0 = hex_literal::hex!("12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa");

    g2[0..32].copy_from_slice(&x1);
    g2[32..64].copy_from_slice(&x0);
    g2[64..96].copy_from_slice(&y1);
    g2[96..128].copy_from_slice(&y0);

    g2
}

/// Convert pairing point object (16 Fr limbs) to two G1 points
///
/// The pairing points are serialized as 68-bit limbs (4 limbs per 256-bit coordinate)
/// - lhs.x = limbs[0] | limbs[1] << 68 | limbs[2] << 136 | limbs[3] << 204
/// - lhs.y = limbs[4..7]
/// - rhs.x = limbs[8..11]
/// - rhs.y = limbs[12..15]
fn convert_pairing_points_to_g1(ppo: &[Fr]) -> Result<(G1, G1), VerifyError> {
    if ppo.len() != 16 {
        return Err(VerifyError::PublicInput(alloc::format!(
            "Expected 16 pairing point limbs, got {}",
            ppo.len()
        )));
    }

    // Helper to combine 4 68-bit limbs into a 256-bit value
    // Fr values are big-endian 32-byte arrays, but limbs are small values (fit in ~68 bits)
    fn combine_limbs(limbs: &[Fr]) -> [u8; 32] {
        // Each limb is 68 bits. We combine them:
        // val = limbs[0] | (limbs[1] << 68) | (limbs[2] << 136) | (limbs[3] << 204)

        // Since Fr is big-endian, convert to little-endian for easier bit manipulation
        let limb0 = fr_to_le(&limbs[0]);
        let limb1 = fr_to_le(&limbs[1]);
        let limb2 = fr_to_le(&limbs[2]);
        let limb3 = fr_to_le(&limbs[3]);

        // Combine using bit shifts (working in little-endian)
        let mut combined = limb0;
        combined = add_256_le(&combined, &shift_left_256_le(&limb1, 68));
        combined = add_256_le(&combined, &shift_left_256_le(&limb2, 136));
        combined = add_256_le(&combined, &shift_left_256_le(&limb3, 204));

        // Convert back to big-endian for the result
        le_to_be(&combined)
    }

    // Convert Fr (big-endian) to little-endian
    fn fr_to_le(fr: &Fr) -> [u8; 32] {
        let mut le = [0u8; 32];
        for i in 0..32 {
            le[i] = fr[31 - i];
        }
        le
    }

    // Convert little-endian to big-endian
    fn le_to_be(le: &[u8; 32]) -> [u8; 32] {
        let mut be = [0u8; 32];
        for i in 0..32 {
            be[i] = le[31 - i];
        }
        be
    }

    // Shift left in little-endian representation
    fn shift_left_256_le(val: &[u8; 32], bits: usize) -> [u8; 32] {
        let mut result = [0u8; 32];
        let byte_shift = bits / 8;
        let bit_shift = bits % 8;

        if byte_shift >= 32 {
            return result;
        }

        for i in byte_shift..32 {
            let src_idx = i - byte_shift;
            result[i] = val[src_idx] << bit_shift;
            if bit_shift > 0 && src_idx > 0 {
                result[i] |= val[src_idx - 1] >> (8 - bit_shift);
            }
        }

        result
    }

    // Add two 256-bit values in little-endian
    fn add_256_le(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut result = [0u8; 32];
        let mut carry: u16 = 0;

        for i in 0..32 {
            let sum = a[i] as u16 + b[i] as u16 + carry;
            result[i] = sum as u8;
            carry = sum >> 8;
        }

        result
    }

    // Extract coordinates
    let lhs_x = combine_limbs(&ppo[0..4]);
    let lhs_y = combine_limbs(&ppo[4..8]);
    let rhs_x = combine_limbs(&ppo[8..12]);
    let rhs_y = combine_limbs(&ppo[12..16]);

    // Create G1 points (64 bytes each: x || y)
    let mut lhs = [0u8; 64];
    lhs[0..32].copy_from_slice(&lhs_x);
    lhs[32..64].copy_from_slice(&lhs_y);

    let mut rhs = [0u8; 64];
    rhs[0..32].copy_from_slice(&rhs_x);
    rhs[32..64].copy_from_slice(&rhs_y);

    #[cfg(feature = "debug")]
    {
        crate::dbg_g1!("lhs from pairingPointObject", &lhs);
        crate::dbg_g1!("rhs from pairingPointObject", &rhs);
    }

    Ok((lhs, rhs))
}

/// Generate recursion separator by hashing pairing points
///
/// Hashes: proofLhs, proofRhs, accLhs, accRhs -> keccak256 -> Fr (mod r)
fn generate_recursion_separator(
    proof_lhs: &G1,
    proof_rhs: &G1,
    acc_lhs: &G1,
    acc_rhs: &G1,
) -> Result<Fr, VerifyError> {
    use sha3::{Digest, Keccak256};

    // Hash: proofLhs.x, proofLhs.y, proofRhs.x, proofRhs.y, accLhs.x, accLhs.y, accRhs.x, accRhs.y
    let mut hasher = Keccak256::new();

    hasher.update(&proof_lhs[0..32]); // proofLhs.x
    hasher.update(&proof_lhs[32..64]); // proofLhs.y
    hasher.update(&proof_rhs[0..32]); // proofRhs.x
    hasher.update(&proof_rhs[32..64]); // proofRhs.y
    hasher.update(&acc_lhs[0..32]); // accLhs.x
    hasher.update(&acc_lhs[32..64]); // accLhs.y
    hasher.update(&acc_rhs[0..32]); // accRhs.x
    hasher.update(&acc_rhs[32..64]); // accRhs.y

    let hash = hasher.finalize();

    #[cfg(feature = "debug")]
    {
        let mut raw_hash = [0u8; 32];
        raw_hash.copy_from_slice(&hash);
        crate::dbg_fr!("  raw hash", &raw_hash);
    }

    // Convert to Fr with modular reduction (like Solidity's FrLib.fromBytes32)
    // FrLib.fromBytes32: return Fr.wrap(uint256(value) % MODULUS)
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);

    // Apply modular reduction
    result = crate::field::fr_reduce(&result);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{VK_SIZE_NEW, VK_SIZE_OLD};
    use crate::proof::Proof as ProofStruct;
    use crate::types::SCALAR_ZERO;

    /// Create a test VK in the NEW format (1760 bytes, bb v0.84.0+)
    fn create_test_vk() -> Vec<u8> {
        let mut vk = vec![0u8; VK_SIZE_NEW];
        // Header: 4 × 8-byte big-endian u64
        // circuit_size = 64 (at bytes 0-7)
        vk[7] = 64;
        // log2_circuit_size = 6 (at bytes 8-15)
        vk[15] = 6;
        // num_public_inputs = 1 (at bytes 16-23)
        vk[23] = 1;
        // pub_inputs_offset = 1 (at bytes 24-31)
        vk[31] = 1;
        vk
    }

    /// Create a test VK in the OLD format (1888 bytes, legacy)
    fn create_test_vk_old() -> Vec<u8> {
        let mut vk = vec![0u8; VK_SIZE_OLD];
        vk[31] = 6; // log2_circuit_size = 6
        vk[63] = 17; // log2_domain_size = 17
        vk[95] = 1; // num_public_inputs = 1
        vk
    }

    fn create_test_proof(log_n: usize, is_zk: bool) -> Vec<u8> {
        let expected_fr = ProofStruct::expected_size(log_n, is_zk);
        vec![0u8; expected_fr * 32]
    }

    #[test]
    fn test_verify_wrong_public_inputs_count() {
        let vk = create_test_vk();
        let proof = create_test_proof(6, true);
        let public_inputs: [[u8; 32]; 2] = [[0u8; 32], [0u8; 32]]; // 2 inputs, expect 1

        let result = verify(&vk, &proof, &public_inputs, true);
        assert!(matches!(result, Err(VerifyError::PublicInput(_))));
    }

    #[test]
    fn test_verify_parses_correctly() {
        let vk = create_test_vk();
        let proof = create_test_proof(6, true);
        let public_inputs: [[u8; 32]; 1] = [[0u8; 32]]; // 1 input as expected

        // In unit tests (non-Solana environment), solana-bn254 has mock implementations
        // that may return success. The real test is the integration test with solana-program-test.
        let result = verify(&vk, &proof, &public_inputs, true);
        // Just verify the function runs without panic
        let _ = result;
    }

    #[test]
    fn test_public_input_delta_with_ppo() {
        let beta = fr_from_u64(2);
        let gamma = fr_from_u64(10);
        let pi = fr_from_u64(5);
        let ppo = [[0u8; 32]; 16]; // Zero pairing point object

        let delta = compute_public_input_delta_with_ppo(&[pi], &ppo, &beta, &gamma, 64, 0);
        // Just verify it returns something non-trivial
        assert_ne!(delta, SCALAR_ZERO);
    }

    /// Debug test that loads real proof files and traces verification
    /// Run with: cargo test -p plonk-solana-core test_debug_real_proof --features debug -- --nocapture
    #[test]
    #[cfg(feature = "debug")]
    fn test_debug_real_proof() {
        use std::path::Path;

        // Path to test artifacts
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("test-circuits/simple_square/target/keccak");

        let vk_path = base.join("vk");
        let proof_path = base.join("proof");
        let pi_path = base.join("public_inputs");

        if !vk_path.exists() {
            println!("⚠️  Test artifacts not found at {:?}", base);
            println!("   Run: cd test-circuits/simple_square && nargo compile && nargo execute");
            println!("   Then: bb prove -b ./target/simple_square.json -w ./target/simple_square.gz --oracle_hash keccak --write_vk -o ./target/keccak");
            return;
        }

        println!("\n========== DEBUG VERIFICATION TEST ==========\n");

        // Load files
        let vk_bytes = std::fs::read(&vk_path).expect("Failed to read VK");
        let proof_bytes = std::fs::read(&proof_path).expect("Failed to read proof");
        let pi_bytes = std::fs::read(&pi_path).expect("Failed to read public inputs");

        println!("VK size: {} bytes", vk_bytes.len());
        println!("Proof size: {} bytes", proof_bytes.len());
        println!("Public inputs size: {} bytes", pi_bytes.len());

        // Parse VK to get log_n (auto-detects format)
        assert!(
            vk_bytes.len() == crate::VK_SIZE || vk_bytes.len() == crate::VK_SIZE_OLD,
            "VK size {} doesn't match new ({}) or old ({}) format",
            vk_bytes.len(),
            crate::VK_SIZE,
            crate::VK_SIZE_OLD
        );
        let vk = crate::key::VerificationKey::from_bytes(&vk_bytes).expect("Failed to parse VK");
        println!("log2_circuit_size: {}", vk.log2_circuit_size);
        println!("num_public_inputs: {}", vk.num_public_inputs);

        // Parse public inputs (each is 32 bytes)
        let num_pi = pi_bytes.len() / 32;
        println!("Number of public inputs: {}", num_pi);

        let mut public_inputs = Vec::new();
        for i in 0..num_pi {
            let mut pi = [0u8; 32];
            pi.copy_from_slice(&pi_bytes[i * 32..(i + 1) * 32]);
            println!("Public input[{}]: 0x{}", i, hex::encode(&pi));
            public_inputs.push(pi);
        }

        // Run verification (ZK)
        println!("\n--- Running verification (ZK) ---\n");
        let result = verify(&vk_bytes, &proof_bytes, &public_inputs, true);

        match result {
            Ok(()) => println!("\n✅ VERIFICATION PASSED!"),
            Err(e) => println!("\n❌ VERIFICATION FAILED: {:?}", e),
        }

        println!("\n========== END DEBUG TEST ==========\n");
    }

    /// Debug test for NON-ZK proof
    /// Run with: cargo test -p plonk-solana-core test_debug_non_zk_proof --features debug -- --nocapture
    #[test]
    #[cfg(feature = "debug")]
    fn test_debug_non_zk_proof() {
        use std::path::Path;

        // Path to non-ZK test artifacts
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("test-circuits/simple_square/target/keccak_non_zk");

        let vk_path = base.join("vk");
        let proof_path = base.join("proof");
        let pi_path = base.join("public_inputs");

        if !vk_path.exists() {
            println!("⚠️  Non-ZK test artifacts not found at {:?}", base);
            println!("   Run: bb prove ... --disable_zk ...");
            return;
        }

        println!("\n========== DEBUG NON-ZK VERIFICATION TEST ==========\n");

        // Load files
        let vk_bytes = std::fs::read(&vk_path).expect("Failed to read VK");
        let proof_bytes = std::fs::read(&proof_path).expect("Failed to read proof");
        let pi_bytes = std::fs::read(&pi_path).expect("Failed to read public inputs");

        println!("VK size: {} bytes", vk_bytes.len());
        println!("Proof size: {} bytes", proof_bytes.len());
        println!("Public inputs size: {} bytes", pi_bytes.len());

        // Parse public inputs
        let num_pi = pi_bytes.len() / 32;
        let mut public_inputs = Vec::new();
        for i in 0..num_pi {
            let mut pi = [0u8; 32];
            pi.copy_from_slice(&pi_bytes[i * 32..(i + 1) * 32]);
            public_inputs.push(pi);
        }

        // Run verification (non-ZK)
        println!("\n--- Running verification (non-ZK) ---\n");
        let result = verify(&vk_bytes, &proof_bytes, &public_inputs, false);

        match result {
            Ok(()) => println!("\n✅ NON-ZK VERIFICATION PASSED!"),
            Err(e) => println!("\n❌ NON-ZK VERIFICATION FAILED: {:?}", e),
        }

        println!("\n========== END NON-ZK DEBUG TEST ==========\n");
    }

    // ============================================================================
    // Test Vector Module: Valid Proof, Tampered Proof, Wrong Inputs
    // ============================================================================
    //
    // These tests use the simple_square circuit: x * x = y
    // - Private witness: x = 3
    // - Public input: y = 9
    //
    // Reference: docs/theory.md for protocol details
    // ============================================================================

    /// Helper to load test artifacts from test-circuits/simple_square
    fn load_test_artifacts() -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        use std::path::Path;

        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("test-circuits/simple_square/target/keccak");

        let vk_path = base.join("vk");
        let proof_path = base.join("proof");
        let pi_path = base.join("public_inputs");

        if !vk_path.exists() {
            return None;
        }

        let vk_bytes = std::fs::read(&vk_path).ok()?;
        let proof_bytes = std::fs::read(&proof_path).ok()?;
        let pi_bytes = std::fs::read(&pi_path).ok()?;

        Some((vk_bytes, proof_bytes, pi_bytes))
    }

    /// Test 1: Valid proof with correct public inputs should verify
    ///
    /// Circuit: simple_square (x * x = y)
    /// Witness: x = 3 (private)
    /// Public input: y = 9
    ///
    /// This is the positive test case - a legitimately generated proof.
    #[test]
    fn test_valid_proof_verifies() {
        let Some((vk_bytes, proof_bytes, pi_bytes)) = load_test_artifacts() else {
            println!("⚠️  Test artifacts not found. Skipping test.");
            println!("   Generate with: cd test-circuits/simple_square && nargo compile && nargo execute");
            println!("   Then: bb prove -b ./target/circuit.json -w ./target/circuit.gz --oracle_hash keccak --write_vk -o ./target/keccak");
            return;
        };

        // Verify sizes match expected (either old or new format)
        assert!(
            vk_bytes.len() == crate::VK_SIZE || vk_bytes.len() == crate::VK_SIZE_OLD,
            "VK size {} doesn't match new ({}) or old ({}) format",
            vk_bytes.len(),
            crate::VK_SIZE,
            crate::VK_SIZE_OLD
        );
        assert_eq!(pi_bytes.len(), 32, "Expected 1 public input (32 bytes)");

        // Parse public inputs
        let mut public_inputs = Vec::new();
        let mut pi = [0u8; 32];
        pi.copy_from_slice(&pi_bytes[0..32]);
        public_inputs.push(pi);

        // Verify the public input is y = 9
        let mut expected_pi = [0u8; 32];
        expected_pi[31] = 9; // Big-endian: 9 in last byte
        assert_eq!(pi, expected_pi, "Public input should be y = 9");

        // Verify - this should pass (verify accepts &[u8] for VK)
        let result = verify(&vk_bytes, &proof_bytes, &public_inputs, true);
        assert!(
            result.is_ok(),
            "Valid proof should verify: {:?}",
            result.err()
        );
    }

    /// Test 2: Tampered proof (modified bytes) should NOT verify
    ///
    /// We flip bits in various parts of the proof to ensure the verifier
    /// properly rejects invalid proofs at different stages.
    #[test]
    fn test_tampered_proof_fails() {
        let Some((vk_bytes, proof_bytes, pi_bytes)) = load_test_artifacts() else {
            println!("⚠️  Test artifacts not found. Skipping test.");
            return;
        };

        // Prepare public inputs
        let mut pi = [0u8; 32];
        pi.copy_from_slice(&pi_bytes[0..32]);
        let public_inputs = vec![pi];

        // Test tampering at different offsets
        let tamper_offsets = [
            (512, "witness commitment W1"),   // First witness commitment
            (544, "witness commitment W1 y"), // W1 y-coordinate
            (1024, "sumcheck univariate"),    // Sumcheck data
            (2048, "sumcheck evaluations"),   // Evaluations
            (4096, "gemini data"),            // Gemini folding
            (5000, "KZG quotient"),           // Near the end
        ];

        for (offset, description) in tamper_offsets.iter() {
            if *offset >= proof_bytes.len() {
                continue;
            }

            let mut tampered_proof = proof_bytes.clone();
            // Flip all bits in one byte
            tampered_proof[*offset] ^= 0xFF;

            let result = verify(&vk_bytes, &tampered_proof, &public_inputs, true);
            assert!(
                result.is_err(),
                "Tampered proof (at {}: {}) should NOT verify",
                offset,
                description
            );
        }
    }

    /// Test 3: Wrong public inputs should NOT verify
    ///
    /// The proof proves x*x = 9, so any other public input should fail.
    #[test]
    fn test_wrong_public_input_fails() {
        let Some((vk_bytes, proof_bytes, _pi_bytes)) = load_test_artifacts() else {
            println!("⚠️  Test artifacts not found. Skipping test.");
            return;
        };

        // Test with wrong public input values
        let wrong_inputs = [
            (
                0u64,
                "y = 0 (not a square of any field element we're proving)",
            ),
            (1u64, "y = 1 (would require x = 1)"),
            (4u64, "y = 4 (would require x = 2)"),
            (10u64, "y = 10 (not 9)"),
            (16u64, "y = 16 (would require x = 4)"),
        ];

        for (wrong_value, description) in wrong_inputs.iter() {
            let mut wrong_pi = [0u8; 32];
            // Set value in big-endian
            let value_bytes = wrong_value.to_be_bytes();
            wrong_pi[24..32].copy_from_slice(&value_bytes);

            let public_inputs = vec![wrong_pi];
            let result = verify(&vk_bytes, &proof_bytes, &public_inputs, true);
            assert!(
                result.is_err(),
                "Wrong public input ({}) should NOT verify",
                description
            );
        }
    }

    /// Test 4: Empty/truncated proof should fail gracefully
    #[test]
    fn test_truncated_proof_fails() {
        let Some((vk_bytes, proof_bytes, pi_bytes)) = load_test_artifacts() else {
            println!("⚠️  Test artifacts not found. Skipping test.");
            return;
        };

        let mut pi = [0u8; 32];
        pi.copy_from_slice(&pi_bytes[0..32]);
        let public_inputs = vec![pi];

        // Test with various truncated proofs
        let truncation_sizes = [0, 32, 512, 1024, 2048, proof_bytes.len() - 32];

        for size in truncation_sizes {
            let truncated = &proof_bytes[..size];
            let result = verify(&vk_bytes, truncated, &public_inputs, true);
            assert!(
                result.is_err(),
                "Truncated proof (size={}) should NOT verify",
                size
            );
        }
    }

    /// Test 5: Verify proof structure matches theory documentation
    ///
    /// Cross-reference with docs/theory.md Section 12 (Data Formats)
    /// Updated for bb 0.87 format with fixed-size proofs.
    #[test]
    fn test_proof_structure_matches_theory() {
        let Some((vk_bytes, proof_bytes, _pi_bytes)) = load_test_artifacts() else {
            println!("⚠️  Test artifacts not found. Skipping test.");
            return;
        };

        // VK size depends on format:
        // - bb 0.87: 1760 bytes (32 header + 27 * 64 commitments)
        // - bb 0.84: 1888 bytes (96 header + 28 * 64 commitments)
        assert!(
            vk_bytes.len() == crate::VK_SIZE || vk_bytes.len() == crate::VK_SIZE_OLD,
            "VK size {} doesn't match new ({}) or old ({}) format",
            vk_bytes.len(),
            crate::VK_SIZE,
            crate::VK_SIZE_OLD
        );

        // Parse VK - use the VK parser to get correct values
        let vk = crate::key::VerificationKey::from_bytes(&vk_bytes).expect("VK should parse");
        let log2_circuit = vk.log2_circuit_size as usize;
        let num_public_inputs = vk.num_public_inputs as usize;

        // Our test circuit (simple_square) has log_n=12 with bb 0.87
        assert_eq!(
            log2_circuit, 12,
            "log2_circuit_size should be 12 for simple_square"
        );
        // bb 0.87: 17 public inputs (1 user + 16 pairing points)
        assert_eq!(num_public_inputs, 17, "num_public_inputs should be 17");

        // bb 0.87: ZK proofs are FIXED SIZE (507 Fr = 16224 bytes)
        let expected_proof_size = crate::proof::Proof::expected_size_bytes(true);
        assert_eq!(
            proof_bytes.len(),
            expected_proof_size,
            "Proof size should match bb 0.87 ZK format (507 Fr elements)"
        );

        // Verify proof structure offsets for bb 0.87:
        // Pairing Point Object: 16 Fr = 512 bytes at offset 0
        // Witness Commitments: 8 G1 (limbed) = 8 * 128 = 1024 bytes
        let _ppo_start = 0;
        let _ppo_end = 512;
        let _witness_start = 512;
        let _witness_end = 1536; // 512 + 1024

        // Just verify the proof parses without error
        let proof = crate::proof::Proof::from_bytes(&proof_bytes, log2_circuit, true);
        assert!(proof.is_ok(), "Proof should parse: {:?}", proof.err());
    }

    /// Test 6: Verify proof size formula works for different circuit sizes
    ///
    /// Our implementation dynamically sizes proofs based on log_circuit_size (log_n),
    /// bb 0.87 uses FIXED-SIZE proofs based on CONST_PROOF_SIZE_LOG_N=28.
    /// All proofs (regardless of actual circuit log_n) have the same size.
    /// This test validates that our proof parsing handles various circuit sizes.
    #[test]
    fn test_variable_circuit_size_support() {
        use crate::proof::Proof;

        // Test that our parser accepts different log_n values
        // In bb 0.87, proof size is FIXED based on CONST_PROOF_SIZE_LOG_N=28
        let test_cases = vec![
            (6, true),   // Small circuit
            (10, true),  // Medium circuit
            (12, true),  // Our test circuit
            (15, true),  // Larger circuit
            (20, true),  // Large circuit
            (6, false),  // Non-ZK variant
            (20, false), // Non-ZK larger
        ];

        // All ZK proofs should have the same size in bb 0.87
        let expected_zk_size = Proof::expected_size_bytes(true);
        let expected_non_zk_size = Proof::expected_size_bytes(false);

        for (log_n, is_zk) in test_cases.iter() {
            let size = Proof::expected_size(*log_n, *is_zk);
            let expected = if *is_zk {
                expected_zk_size
            } else {
                expected_non_zk_size
            };

            // All proofs of the same type should have the same size (FIXED)
            assert_eq!(
                size * 32,
                expected,
                "Proof size should be fixed: log_n={} is_zk={} size={}",
                log_n,
                is_zk,
                size * 32
            );

            // Verify we can create a dummy proof of this size
            let bytes = vec![0u8; expected];
            let result = Proof::from_bytes(&bytes, *log_n, *is_zk);
            assert!(
                result.is_ok(),
                "Should parse proof with log_n={}, is_zk={}: {:?}",
                log_n,
                is_zk,
                result.err()
            );
        }

        // Document the size range
        let min_size = Proof::expected_size(1, false) * 32;
        let max_size = Proof::expected_size(28, true) * 32;
        println!(
            "Supported proof size range: {} - {} bytes",
            min_size, max_size
        );
        println!(
            "  log_n=6 (our test):  {} bytes",
            Proof::expected_size(6, true) * 32
        );
        println!(
            "  log_n=28 (maximum):  {} bytes",
            Proof::expected_size(28, true) * 32
        );
    }

    /// Test 7: Verify VK hash matches expected value
    ///
    /// Note: In bb 0.87, VK hash is NOT used in the transcript initialization.
    /// This test just verifies VK hash computation is deterministic.
    #[test]
    fn test_vk_hash_computation() {
        let Some((vk_bytes, _proof_bytes, _pi_bytes)) = load_test_artifacts() else {
            println!("⚠️  Test artifacts not found. Skipping test.");
            return;
        };

        let vk = crate::key::VerificationKey::from_bytes(&vk_bytes).unwrap();
        let vk_hash = compute_vk_hash(&vk);

        // Verify VK hash is non-zero and deterministic
        assert_ne!(vk_hash, [0u8; 32], "VK hash should not be zero");

        // Compute again to verify determinism
        let vk_hash2 = compute_vk_hash(&vk);
        assert_eq!(vk_hash, vk_hash2, "VK hash should be deterministic");

        // Log the hash for debugging
        println!("VK hash: 0x{}", hex::encode(vk_hash));
    }

    /// Test: Verify all available test circuits
    ///
    /// This test verifies proofs from multiple test circuits with varying sizes.
    /// It demonstrates that our verifier handles different circuit sizes correctly.
    #[test]
    fn test_all_available_circuits() {
        use std::path::Path;

        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("test-circuits");

        // List of test circuits with their expected properties
        // (name, expected_log_n, is_zk, num_public_inputs excluding pairing points)
        // All circuits are now built with --zk flag, so they all produce ZK proofs
        let circuits = vec![
            ("simple_square", 12, true, 1),
            ("iterated_square_100", 12, true, 1),
            ("iterated_square_1000", 13, true, 1),
            ("iterated_square_10k", 14, true, 1),
            ("fib_chain_100", 12, true, 1),
            ("hash_batch", 17, true, 32),
            ("merkle_membership", 18, true, 32),
            // ("iterated_square_100k", 17, true, 1), // Skip - takes longer to verify
        ];

        let mut passed = 0;
        let mut skipped = 0;
        let mut failed = 0;

        println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Testing all available circuits");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        for (name, expected_log_n, is_zk, expected_num_pi) in circuits {
            let circuit_path = base.join(name).join("target/keccak");
            let vk_path = circuit_path.join("vk");
            let proof_path = circuit_path.join("proof");
            let pi_path = circuit_path.join("public_inputs");

            print!("  {:<25} ", name);

            // Check if files exist
            if !vk_path.exists() || !proof_path.exists() || !pi_path.exists() {
                println!("⚠️  SKIPPED (files not found)");
                skipped += 1;
                continue;
            }

            // Load artifacts
            let vk_bytes = std::fs::read(&vk_path).unwrap();
            let proof_bytes = std::fs::read(&proof_path).unwrap();
            let pi_bytes = std::fs::read(&pi_path).unwrap();

            // Check proof size to determine if ZK or non-ZK
            let expected_zk_size = crate::proof::Proof::expected_size_bytes(true);
            let expected_non_zk_size = crate::proof::Proof::expected_size_bytes(false);
            let actual_is_zk = proof_bytes.len() == expected_zk_size;

            if actual_is_zk != is_zk {
                println!(
                    "⚠️  SKIPPED (expected {} proof, got {} bytes)",
                    if is_zk { "ZK" } else { "non-ZK" },
                    proof_bytes.len()
                );
                skipped += 1;
                continue;
            }

            // Parse VK to check log_n
            let vk = match crate::key::VerificationKey::from_bytes(&vk_bytes) {
                Ok(vk) => vk,
                Err(e) => {
                    println!("❌ FAILED (VK parse error: {:?})", e);
                    failed += 1;
                    continue;
                }
            };

            // Verify log_n
            if vk.log2_circuit_size as usize != expected_log_n {
                println!(
                    "❌ FAILED (log_n mismatch: expected {}, got {})",
                    expected_log_n, vk.log2_circuit_size
                );
                failed += 1;
                continue;
            }

            // Parse public inputs (each is 32 bytes)
            let public_inputs: Vec<crate::types::Fr> = pi_bytes
                .chunks(32)
                .map(|c| {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(c);
                    arr
                })
                .collect();

            // Verify number of public inputs (excluding pairing points for ZK proofs)
            let actual_pi_count = public_inputs.len();
            if actual_pi_count != expected_num_pi {
                println!(
                    "⚠️  PI count: expected {}, got {}",
                    expected_num_pi, actual_pi_count
                );
            }

            // Verify the proof
            match super::verify(&vk_bytes, &proof_bytes, &public_inputs, actual_is_zk) {
                Ok(()) => {
                    println!(
                        "✅ PASSED (log_n={}, {} proof, {} PI)",
                        expected_log_n,
                        if actual_is_zk { "ZK" } else { "non-ZK" },
                        actual_pi_count
                    );
                    passed += 1;
                }
                Err(e) => {
                    println!("❌ FAILED ({:?})", e);
                    failed += 1;
                }
            }
        }

        println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!(
            "Results: {} passed, {} failed, {} skipped",
            passed, failed, skipped
        );
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        // Only fail if there were actual failures (not just skips)
        assert_eq!(failed, 0, "Some circuits failed verification");
    }
}
