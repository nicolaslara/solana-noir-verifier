//! Shplemini batch-opening verification for UltraHonk
//!
//! This module implements the batched polynomial commitment opening verification
//! using the Shplemini scheme (KZG-based).
//!
//! The verification computes:
//! 1. r^(2^i) powers for each round
//! 2. Shplonk weights for batching
//! 3. MSM of all commitments with computed scalars
//! 4. Final pairing check

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::field::{fr_add, fr_inv, fr_mul, fr_neg, fr_sub};
use crate::key::VerificationKey;
use crate::ops;
use crate::proof::{Proof, CONST_PROOF_SIZE_LOG_N};
use crate::types::{Fr, G1, SCALAR_ONE, SCALAR_ZERO};
use crate::verifier::Challenges;

/// Number of unshifted evaluations (indices 0-34) - matches Solidity bb 0.87
pub const NUMBER_UNSHIFTED: usize = 35;

/// Number of shifted evaluations (indices 35-39) - bb 0.87
pub const NUMBER_TO_BE_SHIFTED: usize = 5;

/// Total number of entities for batching - bb 0.87
pub const NUMBER_OF_ENTITIES: usize = NUMBER_UNSHIFTED + NUMBER_TO_BE_SHIFTED; // 40

/// Index in commitments array where shifted commitments start
pub const SHIFTED_COMMITMENTS_START: usize = 30;

/// Number of libra commitments (ZK only)
pub const LIBRA_COMMITMENTS: usize = 3;

/// Number of libra evaluations (ZK only)  
pub const LIBRA_EVALUATIONS: usize = 4;

/// Compute the pairing points for Shplemini verification
///
/// Returns (P0, P1) where the pairing check is: e(P0, G2) == e(P1, x·G2)
#[inline(never)]
pub fn compute_shplemini_pairing_points(
    proof: &Proof,
    vk: &VerificationKey,
    challenges: &Challenges,
) -> Result<(G1, G1), &'static str> {
    let log_n = vk.log2_circuit_size as usize;

    #[cfg(feature = "debug")]
    {
        crate::trace!("===== SHPLEMINI VERIFICATION =====");
        crate::trace!("log_n = {}", log_n);
        crate::dbg_fr!("gemini_r", &challenges.gemini_r);
        crate::dbg_fr!("shplonk_z", &challenges.shplonk_z);
        crate::dbg_fr!("shplonk_nu", &challenges.shplonk_nu);
        crate::dbg_fr!("rho", &challenges.rho);
    }

    // 1) Compute r^(2^i) powers
    // Need CONST_PROOF_SIZE_LOG_N powers for the full fold loop
    let mut r_pows = Vec::with_capacity(CONST_PROOF_SIZE_LOG_N);
    r_pows.push(challenges.gemini_r);
    for i in 1..CONST_PROOF_SIZE_LOG_N {
        r_pows.push(fr_mul(&r_pows[i - 1], &r_pows[i - 1]));
    }

    // 2) Compute shplonk weights
    // pos0 = 1 / (z - r^0)
    // neg0 = 1 / (z + r^0)
    #[cfg(feature = "debug")]
    {
        crate::dbg_fr!("shplonk_z for pos0/neg0", &challenges.shplonk_z);
        crate::dbg_fr!("r_pows[0] (gemini_r) for pos0/neg0", &r_pows[0]);
    }
    let z_minus_r0 = fr_sub(&challenges.shplonk_z, &r_pows[0]);
    let z_plus_r0 = fr_add(&challenges.shplonk_z, &r_pows[0]);

    #[cfg(feature = "debug")]
    {
        crate::dbg_fr!("z - r (before invert)", &z_minus_r0);
        crate::dbg_fr!("z + r (before invert)", &z_plus_r0);
    }

    let pos0 = fr_inv(&z_minus_r0).ok_or("shplonk denominator z - r^0 is zero")?;
    let neg0 = fr_inv(&z_plus_r0).ok_or("shplonk denominator z + r^0 is zero")?;

    #[cfg(feature = "debug")]
    {
        crate::dbg_fr!("pos0 = 1/(z-r)", &pos0);
        crate::dbg_fr!("neg0 = 1/(z+r)", &neg0);
    }

    // unshifted = pos0 + nu * neg0
    let unshifted = fr_add(&pos0, &fr_mul(&challenges.shplonk_nu, &neg0));

    // shifted = (1/r) * (pos0 - nu * neg0)
    let r_inv = fr_inv(&challenges.gemini_r).ok_or("gemini_r is zero")?;
    let shifted = fr_mul(
        &r_inv,
        &fr_sub(&pos0, &fr_mul(&challenges.shplonk_nu, &neg0)),
    );

    #[cfg(feature = "debug")]
    {
        crate::dbg_fr!("unshiftedScalar", &unshifted);
        crate::dbg_fr!("shiftedScalar", &shifted);
    }

    // 3) Accumulate scalars for commitments
    // For now, we'll compute P0 as the MSM result

    // Get sumcheck evaluations
    let evals = proof.sumcheck_evaluations();

    // Weight sumcheck evals with rho powers
    // Start with gemini_masking_eval (from proof) for ZK proofs
    // IMPORTANT: Solidity starts with batchingChallenge = rho, not 1!
    let mut rho_pow = challenges.rho;
    let mut eval_acc = if proof.is_zk {
        proof.gemini_masking_eval()
    } else {
        SCALAR_ZERO
    };

    #[cfg(feature = "debug")]
    {
        crate::dbg_fr!("initial eval_acc (geminiMaskingEval)", &eval_acc);
        crate::dbg_fr!("initial rho_pow (should be rho)", &rho_pow);
    }

    // Solidity loops: first NUMBER_UNSHIFTED (36), then NUMBER_TO_BE_SHIFTED (5)
    // But our NUMBER_OF_ENTITIES is 41, so we can just iterate over all
    for (idx, eval) in evals.iter().take(NUMBER_OF_ENTITIES).enumerate() {
        // The scalar for each commitment
        let weight = if idx < NUMBER_UNSHIFTED {
            fr_neg(&unshifted)
        } else {
            fr_neg(&shifted)
        };
        let _scalar = fr_mul(&weight, &rho_pow);

        // Accumulate eval contribution
        eval_acc = fr_add(&eval_acc, &fr_mul(eval, &rho_pow));
        rho_pow = fr_mul(&rho_pow, &challenges.rho);
    }

    #[cfg(feature = "debug")]
    {
        crate::dbg_fr!("batchedEvaluation after unshifted+shifted", &eval_acc);
    }

    // 4) Folding rounds
    let mut fold_pos = vec![SCALAR_ZERO; log_n];
    let mut cur = eval_acc;

    let gemini_a_evals = proof.gemini_a_evaluations();

    #[cfg(feature = "debug")]
    {
        crate::trace!("===== GEMINI A EVALUATIONS =====");
        for (idx, eval) in gemini_a_evals.iter().enumerate() {
            crate::dbg_fr!(&format!("geminiAEvaluations[{}]", idx), eval);
        }
        crate::trace!("===== FOLD POS COMPUTATION =====");
    }

    for j in (1..=log_n).rev() {
        let r2 = r_pows[j - 1];
        let u = challenges.sumcheck_challenges[j - 1];

        // num = r2 * cur * 2 - A[j-1] * (r2 * (1 - u) - u)
        let two = fr_add(&SCALAR_ONE, &SCALAR_ONE);
        let term1 = fr_mul(&fr_mul(&r2, &cur), &two);

        let one_minus_u = fr_sub(&SCALAR_ONE, &u);
        let r2_one_minus_u = fr_mul(&r2, &one_minus_u);
        let bracket = fr_sub(&r2_one_minus_u, &u);
        let term2 = fr_mul(&gemini_a_evals[j - 1], &bracket);

        let num = fr_sub(&term1, &term2);

        // den = r2 * (1 - u) + u
        let den = fr_add(&r2_one_minus_u, &u);
        let den_inv = fr_inv(&den).ok_or("fold round denominator is zero")?;

        cur = fr_mul(&num, &den_inv);
        fold_pos[j - 1] = cur;

        #[cfg(feature = "debug")]
        {
            crate::dbg_fr!(&format!("foldPos[{}] (j={})", j - 1, j), &cur);
        }
    }

    #[cfg(feature = "debug")]
    {
        crate::dbg_fr!("fold_pos[0]", &fold_pos[0]);
        crate::dbg_fr!("pos0", &pos0);
        crate::dbg_fr!("neg0", &neg0);
        crate::dbg_fr!("gemini_a_evals[0]", &gemini_a_evals[0]);
    }

    // 5) Accumulate constant term
    // const_acc = fold_pos[0] * pos0 + A[0] * nu * neg0
    let mut const_acc = fr_add(
        &fr_mul(&fold_pos[0], &pos0),
        &fr_mul(&fr_mul(&gemini_a_evals[0], &challenges.shplonk_nu), &neg0),
    );

    #[cfg(feature = "debug")]
    {
        crate::dbg_fr!("const_acc after initial term", &const_acc);
    }

    // 6) Further folding (gemini fold loop: i = 0 to CONST_PROOF_SIZE_LOG_N - 2)
    // Solidity loops 27 times, but only accumulates for i < LOG_N - 1 (non-dummy rounds)
    // IMPORTANT: v_pow is ALWAYS updated even in dummy rounds!
    let mut v_pow = fr_mul(&challenges.shplonk_nu, &challenges.shplonk_nu);
    let mut gemini_scalars = vec![SCALAR_ZERO; CONST_PROOF_SIZE_LOG_N - 1];

    for i in 0..(CONST_PROOF_SIZE_LOG_N - 1) {
        let dummy_round = i >= log_n - 1;

        if !dummy_round {
            let j = i + 1; // Our index into r_pows, fold_pos, gemini_a_evals

        let z_minus_rj = fr_sub(&challenges.shplonk_z, &r_pows[j]);
        let z_plus_rj = fr_add(&challenges.shplonk_z, &r_pows[j]);

        let pos_inv = fr_inv(&z_minus_rj).ok_or("shplonk denominator z - r^j is zero")?;
        let neg_inv = fr_inv(&z_plus_rj).ok_or("shplonk denominator z + r^j is zero")?;

        let sp = fr_mul(&v_pow, &pos_inv);
        let sn = fr_mul(&fr_mul(&v_pow, &challenges.shplonk_nu), &neg_inv);

            // Compute gemini scalar for this fold commitment
            // scalars[boundary + i] = -scalingFactorNeg - scalingFactorPos
            gemini_scalars[i] = fr_neg(&fr_add(&sn, &sp));

        // Update const_acc
        const_acc = fr_add(
            &const_acc,
            &fr_add(&fr_mul(&gemini_a_evals[j], &sn), &fr_mul(&fold_pos[j], &sp)),
        );
        }

        // ALWAYS update v_pow, even in dummy rounds!
        v_pow = fr_mul(
            &v_pow,
            &fr_mul(&challenges.shplonk_nu, &challenges.shplonk_nu),
        );
    }

    // 7) Add libra polynomial evaluation contributions (ZK only)
    // Also compute libra_scalars for the MSM
    // Solidity:
    //   denominators[0] = 1/(z - r)
    //   denominators[1] = 1/(z - SUBGROUP_GENERATOR * r)
    //   denominators[2] = denominators[0]
    //   denominators[3] = denominators[0]
    // Then: v_pow *= nu^2, and for each libraPolyEval:
    //   scalingFactor = denominators[i] * v_pow
    //   batchingScalars[i] = -scalingFactor
    //   const_acc += scalingFactor * libraPolyEvals[i]
    //   v_pow *= nu
    // Final libra scalars:
    //   scalars[boundary] = batchingScalars[0]
    //   scalars[boundary+1] = batchingScalars[1] + batchingScalars[2]
    //   scalars[boundary+2] = batchingScalars[3]
    let mut libra_scalars = vec![SCALAR_ZERO; 3];

    if proof.is_zk {
        // SUBGROUP_GENERATOR (from Solidity)
        // Fr.wrap(0x07b0c561a6148404f086204a9f36ffb0617942546750f230c893619174a57a76)
        let subgroup_generator: crate::types::Fr = [
            0x07, 0xb0, 0xc5, 0x61, 0xa6, 0x14, 0x84, 0x04, 0xf0, 0x86, 0x20, 0x4a, 0x9f, 0x36,
            0xff, 0xb0, 0x61, 0x79, 0x42, 0x54, 0x67, 0x50, 0xf2, 0x30, 0xc8, 0x93, 0x61, 0x91,
            0x74, 0xa5, 0x7a, 0x76,
        ];

        // denominators[0] = 1/(z - r)
        let denom0 = fr_inv(&fr_sub(&challenges.shplonk_z, &challenges.gemini_r))
            .ok_or("libra denominator 0 is zero")?;
        // denominators[1] = 1/(z - SUBGROUP_GENERATOR * r)
        let denom1 = fr_inv(&fr_sub(
            &challenges.shplonk_z,
            &fr_mul(&subgroup_generator, &challenges.gemini_r),
        ))
        .ok_or("libra denominator 1 is zero")?;

        // Update v_pow: v_pow *= nu^2
        v_pow = fr_mul(
            &v_pow,
            &fr_mul(&challenges.shplonk_nu, &challenges.shplonk_nu),
        );

        // Get libra poly evals
        let libra_evals = proof.libra_poly_evals();
        #[cfg(feature = "debug")]
        {
            crate::trace!("===== LIBRA POLY EVALS =====");
            for (idx, eval) in libra_evals.iter().enumerate() {
                crate::dbg_fr!(&format!("libraPolyEvals[{}]", idx), eval);
            }
        }

        // For each libraPolyEval, compute batchingScalars and update const_acc
        // denominators = [denom0, denom1, denom0, denom0]
        let denominators = [denom0, denom1, denom0, denom0];
        let mut batching_scalars = [SCALAR_ZERO; 4];
        for (i, eval) in libra_evals.iter().enumerate() {
            let scaling_factor = fr_mul(&denominators[i], &v_pow);
            batching_scalars[i] = fr_neg(&scaling_factor);
            const_acc = fr_add(&const_acc, &fr_mul(&scaling_factor, eval));
            v_pow = fr_mul(&v_pow, &challenges.shplonk_nu);
        }

        // Final libra scalars for commitments:
        // scalars[boundary] = batchingScalars[0]
        // scalars[boundary+1] = batchingScalars[1] + batchingScalars[2]
        // scalars[boundary+2] = batchingScalars[3]
        libra_scalars[0] = batching_scalars[0];
        libra_scalars[1] = fr_add(&batching_scalars[1], &batching_scalars[2]);
        libra_scalars[2] = batching_scalars[3];
    }

    #[cfg(feature = "debug")]
    {
        crate::trace!("===== SHPLEMINI INTERMEDIATE VALUES =====");
        crate::dbg_fr!("const_acc (constantTermAccumulator)", &const_acc);
        crate::dbg_fr!("eval_acc", &eval_acc);
        crate::dbg_fr!("unshifted scalar", &unshifted);
        crate::dbg_fr!("shifted scalar", &shifted);
    }

    // 8) Build the final pairing points
    // P0 = MSM(commitments, scalars)
    // P1 = -kzg_quotient (NEGATED!)

    // Compute P0 using the full MSM
    let p0 = compute_p0_full(
        proof,
        vk,
        challenges,
        &const_acc,
        &unshifted,
        &shifted,
        &r_pows,
        &gemini_scalars,
        &libra_scalars,
    )?;

    // P1 = -kzg_quotient (negate the y-coordinate)
    let kzg_quotient = proof.kzg_quotient();
    let p1 = ops::g1_neg(&kzg_quotient).map_err(|_| "G1 negate failed")?;

    #[cfg(feature = "debug")]
    {
        crate::trace!("===== SHPLEMINI PAIRING POINTS =====");
        crate::dbg_g1!("P0", &p0);
        crate::dbg_g1!("P1", &p1);
    }

    Ok((p0, p1))
}

/// Compute P0 for Shplemini verification
///
/// This builds the complete P0 point using all commitments from VK and proof
/// implementing the full MSM as in Solidity's batchMul
fn compute_p0_full(
    proof: &Proof,
    vk: &VerificationKey,
    challenges: &Challenges,
    const_acc: &Fr,
    unshifted_scalar: &Fr,
    shifted_scalar: &Fr,
    r_pows: &[Fr],
    gemini_scalars: &[Fr],
    libra_scalars: &[Fr],
) -> Result<G1, &'static str> {
    let log_n = vk.log2_circuit_size as usize;

    // We compute P0 as the MSM of all commitments with their scalars
    // Solidity order:
    // [0] shplonk_q (scalar=1)
    // [1] geminiMaskingPoly (scalar=-unshifted)
    // [2..38] VK commitments (28) + proof wire commitments (8) with scalars -unshifted*rho^i / -shifted*rho^i
    // [38..38+log_n-1] gemini fold comms
    // [...+3] libra commitments
    // [...] G1_generator (scalar=const_acc)
    // [...] kzg_quotient (scalar=z)

    // Start with shplonk_q (scalar = 1)
    let mut p0 = proof.shplonk_q();

    #[cfg(feature = "debug")]
    {
        crate::trace!("===== MSM COMMITMENTS =====");
        crate::dbg_g1!("shplonk_q (commitment[0])", &p0);

        // Print first VK commitment
        crate::dbg_g1!("vk.commitments[0] (qm)", &vk.commitments[0]);
        crate::dbg_g1!("vk.commitments[1] (qc)", &vk.commitments[1]);
        crate::dbg_g1!("vk.commitments[27] (lagrangeLast)", &vk.commitments[27]);

        // Print first wire commitment
        crate::dbg_g1!("witness_commitment(0) (w1)", &proof.witness_commitment(0));
    }

    // Add geminiMaskingPoly * (-unshifted)
    if proof.is_zk {
        let neg_unshifted = fr_neg(unshifted_scalar);
        #[cfg(feature = "debug")]
        {
            crate::dbg_fr!("scalar[1] (masking, -unshifted)", &neg_unshifted);
        }
        let masking_comm = proof.gemini_masking_poly();
        let scaled =
            ops::g1_scalar_mul(&masking_comm, &neg_unshifted).map_err(|_| "G1 mul failed")?;
        p0 = ops::g1_add(&p0, &scaled).map_err(|_| "G1 add failed")?;
    }

    // Build scalars for VK and proof commitments
    // We need to accumulate: -unshifted*rho^i for unshifted, -shifted*rho^i for shifted
    // Solidity populates scalars[2..38] with these values
    let neg_unshifted = fr_neg(unshifted_scalar);
    let neg_shifted = fr_neg(shifted_scalar);

    // VK commitments (27 entries for bb 0.87, indices 2-28 in Solidity)
    // scalars[i+2] = -unshifted * rho^(i+1) for i = 0..num_commitments
    // Note: batchingChallenge starts at rho, so first scalar is -unshifted * rho
    let num_vk_commitments = vk.num_commitments;
    let mut rho_pow = challenges.rho;
    for i in 0..num_vk_commitments {
        let scalar = fr_mul(&neg_unshifted, &rho_pow);
        let commitment = vk.commitments[i];
        let scaled = ops::g1_scalar_mul(&commitment, &scalar).map_err(|_| "G1 mul failed")?;
        p0 = ops::g1_add(&p0, &scaled).map_err(|_| "G1 add failed")?;

        #[cfg(feature = "debug")]
        if i < 3 || i == num_vk_commitments - 1 {
            crate::dbg_fr!(&format!("VK[{}] scalar (rho^{})", i, i + 1), &scalar);
        }

        rho_pow = fr_mul(&rho_pow, &challenges.rho);
    }

    #[cfg(feature = "debug")]
    {
        crate::dbg_g1!("P0 after VK commitments", &p0);
        crate::dbg_fr!(
            &format!(
                "rho_pow after VK (should be rho^{})",
                num_vk_commitments + 1
            ),
            &rho_pow
        );
    }

    // Proof wire commitments (8 entries, indices 30-37 in Solidity)
    // But we need to be careful about the order and shifted vs unshifted
    // Solidity order: w1(30), w2(31), w3(32), w4(33), zPerm(34), lookupInverses(35), lookupReadCounts(36), lookupReadTags(37)
    // Our proof order: w1(0), w2(1), w3(2), lookupReadCounts(3), lookupReadTags(4), w4(5), lookupInverses(6), zPerm(7)

    // Map our proof indices to Solidity order
    // Solidity idx 30-37: [w1, w2, w3, w4, zPerm, lookupInverses, lookupReadCounts, lookupReadTags]
    // Our idx 0-7: [w1, w2, w3, lookupReadCounts, lookupReadTags, w4, lookupInverses, zPerm]
    // Mapping: [0, 1, 2, 5, 7, 6, 3, 4]
    let wire_mapping = [0usize, 1, 2, 5, 7, 6, 3, 4];

    // Indices 30-34 (w1, w2, w3, w4, zPerm) are shifted commitments
    // They get both unshifted and shifted scalar contributions
    // SHIFTED_COMMITMENTS_START = 30
    for (sol_idx, &our_idx) in wire_mapping.iter().enumerate() {
        let commitment = proof.witness_commitment(our_idx);

        // Solidity scalars[30..38] start with unshifted scalar contribution
        // After VK loop (28 iterations), rho_pow = rho^29
        // Wire scalars use rho^29, rho^30, ..., rho^36
        let mut scalar = fr_mul(&neg_unshifted, &rho_pow);

        #[cfg(feature = "debug")]
        {
            crate::dbg_fr!(
                &format!("Wire[{}] (sol_idx={}) unshifted_scalar", our_idx, sol_idx),
                &scalar
            );
        }

        // For shifted commitments (indices 30-34 in Solidity, 0-4 in wire_mapping)
        // we also add the shifted contribution
        if sol_idx < NUMBER_TO_BE_SHIFTED {
            // Compute the shifted rho power
            // In Solidity, after unshifted loop (36 iterations starting with rho),
            // batchingChallenge = rho^37
            // So shifted contribution uses rho^(37 + sol_idx)
            // NUMBER_UNSHIFTED = 36, so we need rho^(37 + sol_idx) = rho^(NUMBER_UNSHIFTED + 1 + sol_idx)
            let shifted_rho_idx = NUMBER_UNSHIFTED + 1 + sol_idx; // 37, 38, 39, 40, 41
            let mut shifted_rho_pow = SCALAR_ONE;
            for _ in 0..shifted_rho_idx {
                shifted_rho_pow = fr_mul(&shifted_rho_pow, &challenges.rho);
            }
            let shifted_contrib = fr_mul(&neg_shifted, &shifted_rho_pow);

            #[cfg(feature = "debug")]
            {
                crate::dbg_fr!(
                    &format!(
                        "Wire[{}] shifted_contrib (rho^{})",
                        our_idx, shifted_rho_idx
                    ),
                    &shifted_contrib
                );
            }

            scalar = fr_add(&scalar, &shifted_contrib);

            #[cfg(feature = "debug")]
            {
                crate::dbg_fr!(
                    &format!("Wire[{}] FINAL scalar (sol_idx={})", our_idx, sol_idx),
                    &scalar
                );
            }
        }

        #[cfg(feature = "debug")]
        if sol_idx >= NUMBER_TO_BE_SHIFTED {
            crate::dbg_fr!(
                &format!(
                    "Wire[{}] FINAL scalar (sol_idx={}, no shift)",
                    our_idx, sol_idx
                ),
                &scalar
            );
        }

        let scaled = ops::g1_scalar_mul(&commitment, &scalar).map_err(|_| "G1 mul failed")?;
        p0 = ops::g1_add(&p0, &scaled).map_err(|_| "G1 add failed")?;
        rho_pow = fr_mul(&rho_pow, &challenges.rho);
    }

    #[cfg(feature = "debug")]
    {
        crate::dbg_g1!("P0 after wire commitments", &p0);
    }

    // Add gemini fold commitments with their scalars
    // Solidity: for all CONST_PROOF_SIZE_LOG_N - 1 = 27 commitments
    // scalars are zero for dummy rounds (i >= log_n - 1)
    #[cfg(feature = "debug")]
    {
        crate::trace!("===== GEMINI FOLD SCALARS (27 total) =====");
    }
    for i in 0..(CONST_PROOF_SIZE_LOG_N - 1) {
        #[cfg(feature = "debug")]
        if i < 3 || i == 26 {
            crate::dbg_fr!(&format!("gemini_scalars[{}]", i), &gemini_scalars[i]);
        }
        let commitment = proof.gemini_fold_commitment(i);
        let scaled =
            ops::g1_scalar_mul(&commitment, &gemini_scalars[i]).map_err(|_| "G1 mul failed")?;
        p0 = ops::g1_add(&p0, &scaled).map_err(|_| "G1 add failed")?;
    }

    #[cfg(feature = "debug")]
    {
        crate::dbg_g1!("P0 after gemini fold", &p0);
    }

    // Add libra commitments with their scalars (ZK only)
    if proof.is_zk {
        #[cfg(feature = "debug")]
        {
            crate::trace!("===== LIBRA SCALARS =====");
            crate::dbg_fr!("libra_scalars[0]", &libra_scalars[0]);
            crate::dbg_fr!("libra_scalars[1]", &libra_scalars[1]);
            crate::dbg_fr!("libra_scalars[2]", &libra_scalars[2]);
        }

        // libraCommitments[0], [1], [2]
        let libra_comm_0 = proof.libra_commitment_0();
        let libra_comm_1 = proof.libra_commitment_1();
        let libra_comm_2 = proof.libra_commitment_2();

        let scaled0 =
            ops::g1_scalar_mul(&libra_comm_0, &libra_scalars[0]).map_err(|_| "G1 mul failed")?;
        p0 = ops::g1_add(&p0, &scaled0).map_err(|_| "G1 add failed")?;

        // libra_scalars[1] = batchingScalars[1] + batchingScalars[2] (combined)
        let scaled1 =
            ops::g1_scalar_mul(&libra_comm_1, &libra_scalars[1]).map_err(|_| "G1 mul failed")?;
        p0 = ops::g1_add(&p0, &scaled1).map_err(|_| "G1 add failed")?;

        let scaled2 =
            ops::g1_scalar_mul(&libra_comm_2, &libra_scalars[2]).map_err(|_| "G1 mul failed")?;
        p0 = ops::g1_add(&p0, &scaled2).map_err(|_| "G1 add failed")?;

        #[cfg(feature = "debug")]
        {
            crate::dbg_g1!("P0 after libra comms", &p0);
        }
    }

    // Add const_acc * G1_generator
    let g_scaled =
        ops::g1_scalar_mul(&ops::g1_generator(), const_acc).map_err(|_| "G1 scalar mul failed")?;
    p0 = ops::g1_add(&p0, &g_scaled).map_err(|_| "G1 add failed")?;

    // Add z * kzg_quotient
    let kzg_quotient = proof.kzg_quotient();
    let kzg_scaled = ops::g1_scalar_mul(&kzg_quotient, &challenges.shplonk_z)
        .map_err(|_| "G1 scalar mul failed")?;
    p0 = ops::g1_add(&p0, &kzg_scaled).map_err(|_| "G1 add failed")?;

    #[cfg(feature = "debug")]
    {
        crate::dbg_g1!("P0 after full MSM", &p0);
    }

    Ok(p0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        // Match Solidity constants
        assert_eq!(NUMBER_UNSHIFTED, 35);
        assert_eq!(NUMBER_TO_BE_SHIFTED, 5);
        assert_eq!(NUMBER_OF_ENTITIES, 40);
        assert_eq!(SHIFTED_COMMITMENTS_START, 30);
        assert_eq!(LIBRA_COMMITMENTS, 3);
        assert_eq!(LIBRA_EVALUATIONS, 4);
    }
}
