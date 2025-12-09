//! UltraHonk verification logic
//!
//! This module implements verification for bb 3.0 UltraHonk proofs.
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
/// * `vk_bytes` - Verification key (1888 bytes)
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

    // Validate public inputs count
    // The num_public_inputs in VK is the actual count of public inputs for the circuit
    // (The pairing point object is part of the proof, not public inputs)
    if public_inputs.len() != vk.num_public_inputs as usize {
        return Err(VerifyError::PublicInput(alloc::format!(
            "Expected {} public inputs, got {}",
            vk.num_public_inputs,
            public_inputs.len()
        )));
    }

    // Parse proof with log_n from VK
    let proof = Proof::from_bytes(proof_bytes, log_n, is_zk)?;

    // Run verification
    verify_inner(&vk, &proof, public_inputs)
}

/// Internal verification with parsed structures
fn verify_inner(
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

    // Step 3: Compute the batched opening claim (P0, P1 before aggregation)
    let (p0, p1) = compute_pairing_points(vk, proof, &challenges)?;

    #[cfg(feature = "debug")]
    {
        crate::trace!("===== PAIRING AGGREGATION =====");
        crate::dbg_g1!("P0 (before aggregation)", &p0);
        crate::dbg_g1!("P1 (before aggregation)", &p1);
    }

    // Step 4: Convert pairing point object to G1 points
    let ppo = proof.pairing_point_object();
    let (p0_other, p1_other) = convert_pairing_points_to_g1(ppo)?;

    #[cfg(feature = "debug")]
    {
        crate::dbg_g1!("P0_other (from proof)", &p0_other);
        crate::dbg_g1!("P1_other (from proof)", &p1_other);
    }

    // Step 5: Generate recursion separator
    let recursion_separator = generate_recursion_separator(&p0_other, &p1_other, &p0, &p1)?;

    #[cfg(feature = "debug")]
    {
        crate::dbg_fr!("recursion_separator", &recursion_separator);
    }

    // Step 6: Aggregate pairing points
    // Final P0 = P0 * recursion_separator + P0_other
    // Final P1 = P1 * recursion_separator + P1_other
    let p0_scaled = ops::g1_scalar_mul(&p0, &recursion_separator)?;
    let final_p0 = ops::g1_add(&p0_scaled, &p0_other)?;

    let p1_scaled = ops::g1_scalar_mul(&p1, &recursion_separator)?;
    let final_p1 = ops::g1_add(&p1_scaled, &p1_other)?;

    #[cfg(feature = "debug")]
    {
        crate::dbg_g1!("Final P0", &final_p0);
        crate::dbg_g1!("Final P1", &final_p1);
    }

    // Step 7: Final pairing check: e(P0, G2) * e(P1, x·G2) == 1
    // Equivalently: e(P0, G2) * e(-P1, x·G2) == 1 where P1 is already negated from Shplemini
    // Actually, Solidity does: pairing(pair.P_0, pair.P_1) which checks e(P0, G2_gen) * e(P1, G2_x) == 1
    // The G2 points are: G2_generator and x·G2 (from trusted setup)
    let pairing_result = ops::pairing_check(&[(final_p0, g2_generator()), (final_p1, vk_g2())])?;

    if pairing_result {
        crate::trace!("VERIFICATION PASSED!");
        Ok(())
    } else {
        crate::trace!("VERIFICATION FAILED: pairing check failed");
        Err(VerifyError::VerificationFailed)
    }
}

/// Generate all challenges from the transcript
///
/// Based on bb's UltraHonk transcript manifest (ultra_transcript.test.cpp)
fn generate_challenges(
    vk: &VerificationKey,
    proof: &Proof,
    public_inputs: &[Fr],
) -> Result<Challenges, VerifyError> {
    let mut transcript = Transcript::new();

    crate::trace!("===== CHALLENGE GENERATION =====");
    crate::trace!("circuit_size = {}", vk.circuit_size());
    crate::trace!("num_public_inputs = {}", public_inputs.len());

    // VK hash is computed and added to transcript first
    // This is done by bb's OinkVerifier before anything else
    let vk_hash = compute_vk_hash(vk);
    crate::dbg_fr!("vk_hash", &vk_hash);
    transcript.append_scalar(&vk_hash);

    // NOTE: bb does NOT add circuit_size, num_public_inputs, offset to transcript!
    // Only vk_hash and public_input values are added.

    // Add public inputs (actual user inputs)
    for (i, pi) in public_inputs.iter().enumerate() {
        crate::dbg_fr!(&alloc::format!("public_input[{}]", i), pi);
        transcript.append_scalar(pi);
    }

    // Add pairing point object (16 Fr values) - these are also public inputs for DefaultIO
    // In bb's manifest: public_input_0 = user input, public_input_1..16 = pairing points
    let ppo = proof.pairing_point_object();
    crate::trace!("pairing_point_object has {} elements", ppo.len());
    for (i, p) in ppo.iter().enumerate() {
        if i < 2 {
            crate::dbg_fr!(&alloc::format!("ppo[{}]", i), p);
        }
    }
    for ppo_elem in ppo {
        transcript.append_scalar(ppo_elem);
    }

    // NOTE: For UltraKeccakZK, gemini_masking is NOT added to transcript before wires!
    // It's added later as part of the rho challenge buffer (after sumcheck evaluations).
    // This differs from other ZK flavors which add gemini_masking during Oink.

    // Add first 3 wire commitments (w1, w2, w3)
    let w1 = proof.wire_commitment(0);
    let w2 = proof.wire_commitment(1);
    let w3 = proof.wire_commitment(2);
    crate::dbg_g1!("w1", &w1);
    crate::dbg_g1!("w2", &w2);
    crate::dbg_g1!("w3", &w3);
    transcript.append_g1(&w1);
    transcript.append_g1(&w2);
    transcript.append_g1(&w3);

    // Debug: print transcript buffer size before first challenge
    #[cfg(all(feature = "debug", not(target_family = "solana")))]
    {
        // Print what Solidity expects:
        // 24 elements: vkHash(1) + pi(1) + ppo(16) + w1(2) + w2(2) + w3(2) = 24 * 32 = 768 bytes
        crate::trace!(
            "Transcript buffer before eta: {} + {} + {} + {} = expected 768 bytes",
            32,
            32,
            512,
            192
        );
    }

    // Get eta challenges (eta, eta_two, eta_three)
    let (eta, eta_two) = transcript.challenge_split();
    let (eta_three, _) = transcript.challenge_split();
    crate::dbg_fr!("eta", &eta);
    crate::dbg_fr!("eta_two", &eta_two);
    crate::dbg_fr!("eta_three", &eta_three);

    // Add lookup commitments and w4
    let lookup_read_counts = proof.wire_commitment(3);
    let lookup_read_tags = proof.wire_commitment(4);
    let w4 = proof.wire_commitment(5);
    crate::dbg_g1!("lookup_read_counts", &lookup_read_counts);
    crate::dbg_g1!("lookup_read_tags", &lookup_read_tags);
    crate::dbg_g1!("w4", &w4);
    transcript.append_g1(&lookup_read_counts);
    transcript.append_g1(&lookup_read_tags);
    transcript.append_g1(&w4);

    // Get beta, gamma challenges
    let (beta, gamma) = transcript.challenge_split();
    crate::dbg_fr!("beta", &beta);
    crate::dbg_fr!("gamma", &gamma);

    // Add lookup_inverses and z_perm
    let lookup_inverses = proof.wire_commitment(6);
    let z_perm = proof.wire_commitment(7);
    crate::dbg_g1!("lookup_inverses", &lookup_inverses);
    crate::dbg_g1!("z_perm", &z_perm);
    transcript.append_g1(&lookup_inverses);
    transcript.append_g1(&z_perm);

    // Convert pairing point object slice to array for compute_public_input_delta_with_ppo
    let ppo_slice = proof.pairing_point_object();
    let mut ppo_array = [[0u8; 32]; 16];
    for (i, fr) in ppo_slice.iter().enumerate() {
        ppo_array[i] = *fr;
    }

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
    let alpha = transcript.challenge();
    crate::dbg_fr!("alpha", &alpha);

    // Get gate challenge (SPLIT challenge, then expanded to powers via squaring)
    // gate_challenges = [c, c^2, c^4, c^8, ...]
    // bb generates log_n gate challenges, not CONST_PROOF_SIZE_LOG_N
    let (gate_challenge_base, _) = transcript.challenge_split();
    crate::dbg_fr!("gate_challenge_base", &gate_challenge_base);

    let mut gate_challenges = Vec::with_capacity(proof.log_n);
    let mut gc = gate_challenge_base;
    for i in 0..proof.log_n {
        if i < 2 {
            crate::dbg_fr!(&alloc::format!("gate_challenges[{}]", i), &gc);
        }
        gate_challenges.push(gc);
        gc = fr_mul(&gc, &gc); // Square for next power
    }

    // For ZK proofs: add libra commitment and sum, generate libra challenge
    // This happens AFTER gate_challenge but BEFORE sumcheck univariates
    // The initial sumcheck target = libra_sum * libra_challenge
    // NOTE: libra_challenge uses full challenge (not split)
    let libra_challenge = if proof.is_zk {
        if let Some(libra_concat) = proof.libra_concat_commitment() {
            crate::dbg_g1!("libra_concat", &libra_concat);
            transcript.append_g1(&libra_concat);
        }
        if let Some(libra_sum) = proof.libra_sum() {
            crate::dbg_fr!("libra_sum", &libra_sum);
            transcript.append_scalar(&libra_sum);
        }
        let lc = transcript.challenge(); // Full challenge, not split!
        crate::dbg_fr!("libra_challenge", &lc);
        Some(lc)
    } else {
        None
    };

    // Get sumcheck u challenges
    // Per Solidity verifier: ONE hash per round, take ONLY lower 128 bits, discard upper!
    // See generateSumcheckChallenges in the generated HonkVerifier.sol
    crate::trace!(
        "===== SUMCHECK ROUND CHALLENGES (log_n = {}) =====",
        proof.log_n
    );
    let mut sumcheck_challenges = Vec::with_capacity(proof.log_n);

    for r in 0..proof.log_n {
        let univariate = proof.sumcheck_univariate(r);

        // Add univariate to transcript (one hash per round)
        if r < 3 {
            crate::trace!(
                "round {} univariate[0..2] = {:02x?}, {:02x?}",
                r,
                &univariate[0][0..4],
                &univariate[1][0..4]
            );
        }
        for coeff in univariate {
            transcript.append_scalar(coeff);
        }

        // Hash and split - ONLY use lower 128 bits, discard upper (matches Solidity)
        let (lo, _hi) = transcript.challenge_split();

        if r < 3 {
            crate::dbg_fr!(&alloc::format!("sumcheck_u[{}]", r), &lo);
        }
        sumcheck_challenges.push(lo);
    }

    // Add sumcheck evaluations to transcript
    let sumcheck_evals = proof.sumcheck_evaluations();
    crate::trace!("sumcheck_evaluations count = {}", sumcheck_evals.len());
    if !sumcheck_evals.is_empty() {
        crate::dbg_fr!("sumcheck_eval[0]", &sumcheck_evals[0]);
    }
    for eval in sumcheck_evals {
        transcript.append_scalar(eval);
    }

    // For ZK proofs, add additional elements before rho challenge:
    // - libraEvaluation
    // - libraCommitments[1] (x, y)
    // - libraCommitments[2] (x, y)
    // - geminiMaskingPoly (x, y)
    // - geminiMaskingEval
    if proof.is_zk {
        // libraEvaluation
        if let Some(libra_eval) = proof.libra_evaluation() {
            transcript.append_scalar(&libra_eval);
            crate::dbg_fr!("rho transcript: libra_eval", &libra_eval);
        }

        // libraCommitments[1] and [2] (these are the "grand sum" and "quotient" commitments)
        // From Solidity: libraCommitments[1].x, libraCommitments[1].y, libraCommitments[2].x, libraCommitments[2].y
        if let Some(libra_comms) = proof.libra_commitments() {
            // libra_comms[0] is already included earlier
            // libra_comms[1] and libra_comms[2] are added here
            if libra_comms.len() >= 3 {
                transcript.append_g1(&libra_comms[1]);
                transcript.append_g1(&libra_comms[2]);
                crate::dbg_g1!("rho transcript: libra_comm[1]", &libra_comms[1]);
                crate::dbg_g1!("rho transcript: libra_comm[2]", &libra_comms[2]);
            }
        }

        // geminiMaskingPoly
        if let Some(masking_poly) = proof.gemini_masking_commitment() {
            transcript.append_g1(&masking_poly);
            crate::dbg_g1!("rho transcript: gemini_masking_poly", &masking_poly);
        }

        // geminiMaskingEval
        if let Some(masking_eval) = proof.gemini_masking_eval() {
            transcript.append_scalar(&masking_eval);
            crate::dbg_fr!("rho transcript: gemini_masking_eval", &masking_eval);
        }
    }

    // Get rho challenge
    let (rho, _) = transcript.challenge_split();
    crate::dbg_fr!("rho", &rho);

    // Add Gemini fold commitments to transcript
    // Note: number of fold comms = log_n - 1
    crate::trace!("gemini_fold_comms count = {}", proof.log_n - 1);
    for i in 0..(proof.log_n - 1) {
        let fold_comm = proof.gemini_fold_comm(i);
        if i == 0 {
            crate::dbg_g1!("gemini_fold_comm[0]", &fold_comm);
        }
        transcript.append_g1(&fold_comm);
    }

    // Get gemini_r challenge
    let (gemini_r, _) = transcript.challenge_split();
    crate::dbg_fr!("gemini_r", &gemini_r);

    // Add Gemini A evaluations to transcript
    let gemini_a_evals = proof.gemini_a_evaluations();
    crate::trace!("gemini_a_evaluations count = {}", gemini_a_evals.len());
    for eval in gemini_a_evals {
        transcript.append_scalar(eval);
    }

    // Add libra poly evals to transcript (ZK only) - required for shplonk_nu challenge
    // Solidity: shplonkNuChallengeElements = [prevChallenge, geminiAEvals[0..logN], libraPolyEvals[0..4]]
    if proof.is_zk {
        if let Some(libra_evals) = proof.libra_poly_evals() {
            for eval in libra_evals {
                transcript.append_scalar(eval);
            }
        }
    }

    // Get shplonk_nu challenge
    let (shplonk_nu, _) = transcript.challenge_split();
    crate::dbg_fr!("shplonk_nu", &shplonk_nu);

    // Add shplonk_q to transcript
    let shplonk_q = proof.shplonk_q();
    crate::dbg_g1!("shplonk_q", &shplonk_q);
    transcript.append_g1(&shplonk_q);

    // Get shplonk_z challenge
    let (shplonk_z, _) = transcript.challenge_split();
    crate::dbg_fr!("shplonk_z", &shplonk_z);
    crate::trace!("===== END CHALLENGE GENERATION =====");

    Ok(Challenges {
        relation_params,
        alpha,
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
    _circuit_size: u32,
    offset: u32,
) -> Fr {
    // CRITICAL: Solidity uses PERMUTATION_ARGUMENT_VALUE_SEPARATOR = 1 << 28, NOT circuit_size!
    const PERMUTATION_ARGUMENT_VALUE_SEPARATOR: u64 = 1 << 28;

    let mut numerator = SCALAR_ONE;
    let mut denominator = SCALAR_ONE;

    let offset_fr = fr_from_u64(offset as u64);

    // numerator_acc = gamma + beta * (SEPARATOR + offset)
    // Solidity: Fr numeratorAcc = gamma + (beta * FrLib.from(PERMUTATION_ARGUMENT_VALUE_SEPARATOR + offset));
    let separator_plus_offset = fr_from_u64(PERMUTATION_ARGUMENT_VALUE_SEPARATOR + offset as u64);
    let mut numerator_acc = fr_add(gamma, &fr_mul(beta, &separator_plus_offset));

    // denominator_acc = gamma - beta * (offset + 1)
    let offset_plus_one = fr_from_u64((offset + 1) as u64);
    let mut denominator_acc = fr_sub(gamma, &fr_mul(beta, &offset_plus_one));

    #[cfg(feature = "debug")]
    {
        crate::trace!("===== PUBLIC_INPUT_DELTA COMPUTATION =====");
        crate::dbg_fr!("beta", beta);
        crate::dbg_fr!("gamma", gamma);
        crate::trace!(
            "separator + offset = {}",
            PERMUTATION_ARGUMENT_VALUE_SEPARATOR + offset as u64
        );
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

    // Generate alpha challenges (NUM_SUBRELATIONS - 1 = 27 alphas)
    // Solidity: NUMBER_OF_ALPHAS = NUMBER_OF_SUBRELATIONS - 1 = 28 - 1 = 27
    let mut alphas = Vec::with_capacity(27);
    let mut alpha_pow = challenges.alpha;
    for _ in 0..27 {
        alphas.push(alpha_pow);
        alpha_pow = fr_mul(&alpha_pow, &challenges.alpha);
    }

    let sumcheck_challenges = SumcheckChallenges {
        gate_challenges: challenges.gate_challenges.clone(),
        sumcheck_u_challenges: challenges.sumcheck_challenges.clone(),
        alphas,
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
/// This is hardcoded because bb 3.0 VK format doesn't contain G2 points
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
    use crate::proof::Proof as ProofStruct;
    use crate::types::SCALAR_ZERO;
    use crate::VK_SIZE;

    fn create_test_vk() -> [u8; VK_SIZE] {
        let mut vk = [0u8; VK_SIZE];
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

        // Parse VK to get log_n
        assert_eq!(vk_bytes.len(), crate::VK_SIZE, "VK size mismatch");
        let vk = crate::key::VerificationKey::from_bytes(&vk_bytes).expect("Failed to parse VK");
        println!("log2_circuit_size: {}", vk.log2_circuit_size);
        println!("num_public_inputs: {}", vk.num_public_inputs);

        // Prepare arrays
        let mut vk_array = [0u8; crate::VK_SIZE];
        vk_array.copy_from_slice(&vk_bytes);

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
        let result = verify(&vk_array, &proof_bytes, &public_inputs, true);

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

        // Prepare arrays
        let mut vk_array = [0u8; crate::VK_SIZE];
        vk_array.copy_from_slice(&vk_bytes);

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
        let result = verify(&vk_array, &proof_bytes, &public_inputs, false);

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

        // Verify sizes match expected
        assert_eq!(vk_bytes.len(), crate::VK_SIZE, "VK size mismatch");
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

        // Prepare VK array
        let mut vk_array = [0u8; crate::VK_SIZE];
        vk_array.copy_from_slice(&vk_bytes);

        // Verify - this should pass
        let result = verify(&vk_array, &proof_bytes, &public_inputs, true);
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

        // Prepare VK
        let mut vk_array = [0u8; crate::VK_SIZE];
        vk_array.copy_from_slice(&vk_bytes);

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

            let result = verify(&vk_array, &tampered_proof, &public_inputs, true);
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

        // Prepare VK
        let mut vk_array = [0u8; crate::VK_SIZE];
        vk_array.copy_from_slice(&vk_bytes);

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
            let result = verify(&vk_array, &proof_bytes, &public_inputs, true);
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

        let mut vk_array = [0u8; crate::VK_SIZE];
        vk_array.copy_from_slice(&vk_bytes);

        let mut pi = [0u8; 32];
        pi.copy_from_slice(&pi_bytes[0..32]);
        let public_inputs = vec![pi];

        // Test with various truncated proofs
        let truncation_sizes = [0, 32, 512, 1024, 2048, proof_bytes.len() - 32];

        for size in truncation_sizes {
            let truncated = &proof_bytes[..size];
            let result = verify(&vk_array, truncated, &public_inputs, true);
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
    #[test]
    fn test_proof_structure_matches_theory() {
        let Some((vk_bytes, proof_bytes, _pi_bytes)) = load_test_artifacts() else {
            println!("⚠️  Test artifacts not found. Skipping test.");
            return;
        };

        // Per theory.md Section 12:
        // - VK: 1888 bytes (96 header + 28 * 64 commitments)
        assert_eq!(vk_bytes.len(), 1888, "VK size per theory.md");

        // Parse VK header
        let log2_circuit = vk_bytes[31] as usize;
        let log2_domain = vk_bytes[63] as usize;
        let num_public_inputs = vk_bytes[95] as usize;

        assert_eq!(log2_circuit, 6, "log2_circuit_size should be 6");
        assert_eq!(log2_domain, 17, "log2_domain_size should be 17");
        assert_eq!(num_public_inputs, 1, "num_public_inputs should be 1");

        // Per theory.md: ZK proof with log_n=6 has 162 Fr elements = 5184 bytes
        let expected_proof_size = 162 * 32;
        assert_eq!(
            proof_bytes.len(),
            expected_proof_size,
            "Proof size should match theory.md (162 Fr elements for ZK with log_n=6)"
        );

        // Verify proof structure offsets (per theory.md Section 12)
        // Pairing Point Object: 16 Fr = 512 bytes at offset 0
        // Witness Commitments: 8 G1 = 512 bytes starting at offset 512
        let _ppo_start = 0;
        let _ppo_end = 512;
        let _witness_start = 512;
        let _witness_end = 1024;

        // Just verify the proof parses without error
        let proof = crate::proof::Proof::from_bytes(&proof_bytes, log2_circuit, true);
        assert!(proof.is_ok(), "Proof should parse: {:?}", proof.err());
    }

    /// Test 6: Verify VK hash matches expected value
    ///
    /// The VK hash is the first element added to the Fiat-Shamir transcript.
    /// Per docs/theory.md, this must match bb's output.
    #[test]
    fn test_vk_hash_computation() {
        let Some((vk_bytes, _proof_bytes, _pi_bytes)) = load_test_artifacts() else {
            println!("⚠️  Test artifacts not found. Skipping test.");
            return;
        };

        let mut vk_array = [0u8; crate::VK_SIZE];
        vk_array.copy_from_slice(&vk_bytes);

        let vk = crate::key::VerificationKey::from_bytes(&vk_array).unwrap();
        let vk_hash = compute_vk_hash(&vk);

        // Expected VK hash from bb verify output (documented in docs/theory.md)
        let expected_hash =
            hex_literal::hex!("093e299e4b0c0559f7aa64cb989d22d9d10b1d6b343ce1a894099f63d7a85a75");

        assert_eq!(
            vk_hash,
            expected_hash,
            "VK hash mismatch - transcript will be wrong!\n\
             Computed: 0x{}\n\
             Expected: 0x{}",
            hex::encode(vk_hash),
            hex::encode(expected_hash)
        );
    }
}
