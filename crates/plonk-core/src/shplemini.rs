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
use crate::proof::Proof;
use crate::types::{Fr, G1, SCALAR_ONE, SCALAR_ZERO};
use crate::verifier::Challenges;

/// Number of unshifted evaluations (indices 0-35) - matches Solidity
pub const NUMBER_UNSHIFTED: usize = 36;

/// Number of shifted evaluations (indices 36-40)  
pub const NUMBER_TO_BE_SHIFTED: usize = 5;

/// Total number of entities for batching
pub const NUMBER_OF_ENTITIES: usize = NUMBER_UNSHIFTED + NUMBER_TO_BE_SHIFTED; // 41

/// Index in commitments array where shifted commitments start
pub const SHIFTED_COMMITMENTS_START: usize = 30;

/// Number of libra commitments (ZK only)
pub const LIBRA_COMMITMENTS: usize = 3;

/// Number of libra evaluations (ZK only)  
pub const LIBRA_EVALUATIONS: usize = 4;

/// Compute the pairing points for Shplemini verification
///
/// Returns (P0, P1) where the pairing check is: e(P0, G2) == e(P1, x·G2)
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
    let mut r_pows = Vec::with_capacity(log_n);
    r_pows.push(challenges.gemini_r);
    for i in 1..log_n {
        r_pows.push(fr_mul(&r_pows[i - 1], &r_pows[i - 1]));
    }

    // 2) Compute shplonk weights
    // pos0 = 1 / (z - r^0)
    // neg0 = 1 / (z + r^0)
    let z_minus_r0 = fr_sub(&challenges.shplonk_z, &r_pows[0]);
    let z_plus_r0 = fr_add(&challenges.shplonk_z, &r_pows[0]);

    let pos0 = fr_inv(&z_minus_r0).ok_or("shplonk denominator z - r^0 is zero")?;
    let neg0 = fr_inv(&z_plus_r0).ok_or("shplonk denominator z + r^0 is zero")?;

    // unshifted = pos0 + nu * neg0
    let unshifted = fr_add(&pos0, &fr_mul(&challenges.shplonk_nu, &neg0));

    // shifted = (1/r) * (pos0 - nu * neg0)
    let r_inv = fr_inv(&challenges.gemini_r).ok_or("gemini_r is zero")?;
    let shifted = fr_mul(
        &r_inv,
        &fr_sub(&pos0, &fr_mul(&challenges.shplonk_nu, &neg0)),
    );

    // 3) Accumulate scalars for commitments
    // For now, we'll compute P0 as the MSM result

    // Get sumcheck evaluations
    let evals = proof.sumcheck_evaluations();

    // Weight sumcheck evals with rho powers
    // Start with gemini_masking_eval (from proof) for ZK proofs
    // IMPORTANT: Solidity starts with batchingChallenge = rho, not 1!
    let mut rho_pow = challenges.rho;
    let mut eval_acc = if proof.is_zk {
        proof.gemini_masking_eval().unwrap_or(SCALAR_ZERO)
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
    }

    // 5) Accumulate constant term
    // const_acc = fold_pos[0] * pos0 + A[0] * nu * neg0
    let mut const_acc = fr_add(
        &fr_mul(&fold_pos[0], &pos0),
        &fr_mul(&fr_mul(&gemini_a_evals[0], &challenges.shplonk_nu), &neg0),
    );

    // 6) Further folding
    let mut v_pow = fr_mul(&challenges.shplonk_nu, &challenges.shplonk_nu);

    for j in 1..log_n {
        let z_minus_rj = fr_sub(&challenges.shplonk_z, &r_pows[j]);
        let z_plus_rj = fr_add(&challenges.shplonk_z, &r_pows[j]);

        let pos_inv = fr_inv(&z_minus_rj).ok_or("shplonk denominator z - r^j is zero")?;
        let neg_inv = fr_inv(&z_plus_rj).ok_or("shplonk denominator z + r^j is zero")?;

        let sp = fr_mul(&v_pow, &pos_inv);
        let sn = fr_mul(&fr_mul(&v_pow, &challenges.shplonk_nu), &neg_inv);

        // Update const_acc
        const_acc = fr_add(
            &const_acc,
            &fr_add(&fr_mul(&gemini_a_evals[j], &sn), &fr_mul(&fold_pos[j], &sp)),
        );

        v_pow = fr_mul(
            &v_pow,
            &fr_mul(&challenges.shplonk_nu, &challenges.shplonk_nu),
        );
    }

    #[cfg(feature = "debug")]
    {
        crate::trace!("===== SHPLEMINI INTERMEDIATE VALUES =====");
        crate::dbg_fr!("const_acc (constantTermAccumulator)", &const_acc);
        crate::dbg_fr!("eval_acc", &eval_acc);
        crate::dbg_fr!("unshifted scalar", &unshifted);
        crate::dbg_fr!("shifted scalar", &shifted);
    }

    // 7) Build the final pairing points
    // P0 = MSM(commitments, scalars) + const_acc * G1_generator
    // P1 = -kzg_quotient (NEGATED!)

    // For Solana, we need to build this incrementally using scalar muls and additions
    // For now, return the shplonk_q as a placeholder

    // The actual P0 would be computed via MSM, but for now we use a simplified version:
    // P0 = shplonk_q + const_acc * G + z * kzg_quotient
    let p0 = compute_p0_simplified(proof, vk, challenges, &const_acc)?;

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
fn compute_p0_simplified(
    proof: &Proof,
    vk: &VerificationKey,
    challenges: &Challenges,
    const_acc: &Fr,
) -> Result<G1, &'static str> {
    // Start with shplonk_q (scalar = 1)
    let mut p0 = proof.shplonk_q();

    #[cfg(feature = "debug")]
    {
        crate::dbg_g1!("shplonk_q", &p0);
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
        crate::dbg_g1!("P0 after shplonk_q + const*G + z*kzg", &p0);
    }

    // For now, we're using a simplified approach that doesn't include all VK commitments
    // This is a placeholder - full implementation requires the complete MSM
    //
    // The full computation would be:
    // P0 = batchMul(commitments, scalars) where:
    //   commitments = [shplonk_q, geminiMaskingPoly, VK_comms..., proof_wire_comms...,
    //                  gemini_fold_comms..., libra_comms..., G1_generator, kzg_quotient]
    //   scalars = [1, -unshifted, -unshifted*rho^i..., -shifted*rho^i...,
    //              gemini_scalars..., libra_scalars..., const_acc, z]

    // For UltraHonk with the pairing point object (recursive aggregation),
    // we also need to aggregate with proof.pairingPointObject

    // TODO: Implement the full MSM computation
    // For now, this simplified version may not produce correct results

    Ok(p0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        // Match Solidity constants
        assert_eq!(NUMBER_UNSHIFTED, 36);
        assert_eq!(NUMBER_TO_BE_SHIFTED, 5);
        assert_eq!(NUMBER_OF_ENTITIES, 41);
        assert_eq!(SHIFTED_COMMITMENTS_START, 30);
        assert_eq!(LIBRA_COMMITMENTS, 3);
        assert_eq!(LIBRA_EVALUATIONS, 4);
    }
}
