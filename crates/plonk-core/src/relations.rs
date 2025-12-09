//! UltraHonk relation evaluation
//!
//! This module accumulates all 28 UltraHonk subrelations.
//! Index mapping (from Solidity verifier):
//! - Arithmetic (2 subrelations): indices 0-1
//! - Permutation (2 subrelations): indices 2-3
//! - Lookup (3 subrelations): indices 4-6
//! - Range/DeltaRange (4 subrelations): indices 7-10
//! - Elliptic (2 subrelations): indices 11-12
//! - Memory (6 subrelations): indices 13-18
//! - NNF (1 subrelation): index 19
//! - Poseidon External (4 subrelations): indices 20-23
//! - Poseidon Internal (4 subrelations): indices 24-27
//!
//! Total: 2+2+3+4+2+6+1+4+4 = 28

extern crate alloc;
use alloc::vec;

use crate::field::{fr_add, fr_from_hex, fr_from_u64, fr_mul, fr_neg, fr_sub};
use crate::types::{Fr, SCALAR_ONE, SCALAR_ZERO};

/// Relation parameters for constraint evaluation
#[derive(Debug, Clone)]
pub struct RelationParameters {
    pub eta: Fr,
    pub eta_two: Fr,
    pub eta_three: Fr,
    pub beta: Fr,
    pub gamma: Fr,
    pub public_inputs_delta: Fr,
}

/// Number of subrelations in UltraHonk
/// Matches Solidity's NUMBER_OF_SUBRELATIONS = 26 (bb 0.87)
pub const NUM_SUBRELATIONS: usize = 26;

/// Number of alpha challenges = NUMBER_OF_SUBRELATIONS - 1 = 25 (bb 0.87)
pub const NUMBER_OF_ALPHAS: usize = NUM_SUBRELATIONS - 1;

/// Wire indices for sumcheck evaluations
/// These map to the evaluation values in the proof
/// MUST match Solidity verifier's WIRE enum exactly!
/// bb 0.87: 40 entities total (indices 0-39)
#[repr(usize)]
#[derive(Clone, Copy)]
pub enum Wire {
    // Selector polynomials (0-12)
    Qm = 0,
    Qc = 1,
    Ql = 2,
    Qr = 3,
    Qo = 4,
    Q4 = 5,
    QLookup = 6,
    QArith = 7,
    QRange = 8,
    QElliptic = 9,
    QAux = 10,               // Q_AUX in bb 0.87 (was Q_MEMORY/Q_NNF in older versions)
    QPoseidon2External = 11, // Q_POSEIDON2_EXTERNAL in Solidity
    QPoseidon2Internal = 12, // Q_POSEIDON2_INTERNAL in Solidity
    // Permutation polynomials (13-20)
    Sigma1 = 13,
    Sigma2 = 14,
    Sigma3 = 15,
    Sigma4 = 16,
    Id1 = 17,
    Id2 = 18,
    Id3 = 19,
    Id4 = 20,
    // Lookup table polynomials (21-24)
    Table1 = 21,
    Table2 = 22,
    Table3 = 23,
    Table4 = 24,
    // Lagrange polynomials (25-26)
    LagrangeFirst = 25,
    LagrangeLast = 26,
    // Wire polynomials (27-34)
    Wl = 27,
    Wr = 28,
    Wo = 29,
    W4 = 30,
    ZPerm = 31,
    LookupInverses = 32,
    LookupReadCounts = 33,
    LookupReadTags = 34,
    // Shifted wire polynomials (35-39)
    WlShift = 35,
    WrShift = 36,
    WoShift = 37,
    W4Shift = 38,
    ZPermShift = 39,
}

/// Get wire evaluation from the evaluations array
#[inline]
fn wire(evals: &[Fr], w: Wire) -> Fr {
    evals[w as usize]
}

/// NEG_HALF = (p - 1) / 2 for BN254 scalar field
fn neg_half() -> Fr {
    // 0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000
    let mut bytes = [0u8; 32];
    bytes[0] = 0x18;
    bytes[1] = 0x32;
    bytes[2] = 0x27;
    bytes[3] = 0x39;
    bytes[4] = 0x70;
    bytes[5] = 0x98;
    bytes[6] = 0xd0;
    bytes[7] = 0x14;
    bytes[8] = 0xdc;
    bytes[9] = 0x28;
    bytes[10] = 0x22;
    bytes[11] = 0xdb;
    bytes[12] = 0x40;
    bytes[13] = 0xc0;
    bytes[14] = 0xac;
    bytes[15] = 0x2e;
    bytes[16] = 0x94;
    bytes[17] = 0x19;
    bytes[18] = 0xf4;
    bytes[19] = 0x24;
    bytes[20] = 0x3c;
    bytes[21] = 0xdc;
    bytes[22] = 0xb8;
    bytes[23] = 0x48;
    bytes[24] = 0xa1;
    bytes[25] = 0xf0;
    bytes[26] = 0xfa;
    bytes[27] = 0xc9;
    bytes[28] = 0xf8;
    bytes[29] = 0x00;
    bytes[30] = 0x00;
    bytes[31] = 0x00;
    bytes
}

/// Accumulate arithmetic subrelations (indices 0-1)
fn accumulate_arithmetic(evals: &[Fr], out: &mut [Fr], d: &Fr) {
    // Subrelation 0: quadratic gate
    let q_arith = wire(evals, Wire::QArith);
    let q_m = wire(evals, Wire::Qm);
    let w_l = wire(evals, Wire::Wl);
    let w_r = wire(evals, Wire::Wr);
    let w_o = wire(evals, Wire::Wo);
    let w_4 = wire(evals, Wire::W4);
    let w_4_shift = wire(evals, Wire::W4Shift);
    let q_l = wire(evals, Wire::Ql);
    let q_r = wire(evals, Wire::Qr);
    let q_o = wire(evals, Wire::Qo);
    let q_4 = wire(evals, Wire::Q4);
    let q_c = wire(evals, Wire::Qc);

    #[cfg(feature = "debug")]
    {
        crate::trace!("===== ARITHMETIC WIRE VALUES =====");
        crate::dbg_fr!("q_arith (idx 7)", &q_arith);
        crate::dbg_fr!("q_m (idx 0)", &q_m);
        crate::dbg_fr!("w_l (idx 28)", &w_l);
        crate::dbg_fr!("w_r (idx 29)", &w_r);
        crate::dbg_fr!("domainSep (pow_partial)", d);
    }

    // (q_arith - 3) * q_m * w_r * w_l * neg_half
    // Solidity: accum = (q_arith - 3) * (q_m * w_r * w_l) * neg_half
    let q_minus_3 = fr_sub(&q_arith, &fr_from_u64(3));
    // Solidity order: q_m * w_r first, then * w_l
    let qm_wr = fr_mul(&q_m, &w_r);
    let qm_wr_wl = fr_mul(&qm_wr, &w_l);
    let mut acc = fr_mul(&q_minus_3, &qm_wr_wl);
    acc = fr_mul(&acc, &neg_half());

    #[cfg(feature = "debug")]
    {
        crate::trace!("===== ARITHMETIC REL 0 FULL TRACE =====");
        crate::dbg_fr!("q_arith", &q_arith);
        crate::dbg_fr!("q_m", &q_m);
        crate::dbg_fr!("w_l", &w_l);
        crate::dbg_fr!("w_r", &w_r);
        crate::dbg_fr!("q_minus_3", &q_minus_3);
        crate::dbg_fr!("q_m * w_r", &qm_wr);
        crate::dbg_fr!("q_m * w_r * w_l", &qm_wr_wl);
        crate::dbg_fr!(
            "(q_arith-3) * (q_m*w_r*w_l)",
            &fr_mul(&q_minus_3, &qm_wr_wl)
        );
        crate::dbg_fr!("after neg_half mult", &acc);
    }

    // + q_l * w_l + q_r * w_r + q_o * w_o + q_4 * w_4 + q_c
    acc = fr_add(&acc, &fr_mul(&q_l, &w_l));
    acc = fr_add(&acc, &fr_mul(&q_r, &w_r));
    acc = fr_add(&acc, &fr_mul(&q_o, &w_o));
    acc = fr_add(&acc, &fr_mul(&q_4, &w_4));
    acc = fr_add(&acc, &q_c);

    // (acc + (q_arith - 1) * w_4_shift) * q_arith * d
    let q_minus_1 = fr_sub(&q_arith, &SCALAR_ONE);
    let term = fr_mul(&q_minus_1, &w_4_shift);
    acc = fr_add(&acc, &term);
    acc = fr_mul(&acc, &q_arith);
    acc = fr_mul(&acc, d);
    out[0] = acc;

    // Subrelation 1: indicator
    let w_l_shift = wire(evals, Wire::WlShift);
    let mut acc1 = fr_add(&w_l, &w_4);
    acc1 = fr_sub(&acc1, &w_l_shift);
    acc1 = fr_add(&acc1, &q_m);

    let q_minus_2 = fr_sub(&q_arith, &fr_from_u64(2));
    acc1 = fr_mul(&acc1, &q_minus_2);
    acc1 = fr_mul(&acc1, &q_minus_1);
    acc1 = fr_mul(&acc1, &q_arith);
    acc1 = fr_mul(&acc1, d);
    out[1] = acc1;
}

/// Accumulate permutation subrelations (indices 2-3)
fn accumulate_permutation(evals: &[Fr], rp: &RelationParameters, out: &mut [Fr], d: &Fr) {
    let w_l = wire(evals, Wire::Wl);
    let w_r = wire(evals, Wire::Wr);
    let w_o = wire(evals, Wire::Wo);
    let w_4 = wire(evals, Wire::W4);

    let id1 = wire(evals, Wire::Id1);
    let id2 = wire(evals, Wire::Id2);
    let id3 = wire(evals, Wire::Id3);
    let id4 = wire(evals, Wire::Id4);

    let sigma1 = wire(evals, Wire::Sigma1);
    let sigma2 = wire(evals, Wire::Sigma2);
    let sigma3 = wire(evals, Wire::Sigma3);
    let sigma4 = wire(evals, Wire::Sigma4);

    let z_perm = wire(evals, Wire::ZPerm);
    let z_perm_shift = wire(evals, Wire::ZPermShift);

    let lag_first = wire(evals, Wire::LagrangeFirst);
    let lag_last = wire(evals, Wire::LagrangeLast);

    // Numerator: ∏(w_i + id_i * β + γ)
    let mut num = fr_add(&w_l, &fr_mul(&id1, &rp.beta));
    num = fr_add(&num, &rp.gamma);

    let term2 = fr_add(&w_r, &fr_mul(&id2, &rp.beta));
    let term2 = fr_add(&term2, &rp.gamma);
    num = fr_mul(&num, &term2);

    let term3 = fr_add(&w_o, &fr_mul(&id3, &rp.beta));
    let term3 = fr_add(&term3, &rp.gamma);
    num = fr_mul(&num, &term3);

    let term4 = fr_add(&w_4, &fr_mul(&id4, &rp.beta));
    let term4 = fr_add(&term4, &rp.gamma);
    num = fr_mul(&num, &term4);

    // Denominator: ∏(w_i + σ_i * β + γ)
    let mut den = fr_add(&w_l, &fr_mul(&sigma1, &rp.beta));
    den = fr_add(&den, &rp.gamma);

    let term2 = fr_add(&w_r, &fr_mul(&sigma2, &rp.beta));
    let term2 = fr_add(&term2, &rp.gamma);
    den = fr_mul(&den, &term2);

    let term3 = fr_add(&w_o, &fr_mul(&sigma3, &rp.beta));
    let term3 = fr_add(&term3, &rp.gamma);
    den = fr_mul(&den, &term3);

    let term4 = fr_add(&w_4, &fr_mul(&sigma4, &rp.beta));
    let term4 = fr_add(&term4, &rp.gamma);
    den = fr_mul(&den, &term4);

    // Subrelation 2: (z_perm + lag_first) * num - (z_perm_shift + lag_last * delta) * den
    let lhs = fr_mul(&fr_add(&z_perm, &lag_first), &num);
    let delta_term = fr_mul(&lag_last, &rp.public_inputs_delta);
    let rhs = fr_mul(&fr_add(&z_perm_shift, &delta_term), &den);
    out[2] = fr_mul(&fr_sub(&lhs, &rhs), d);

    #[cfg(feature = "debug")]
    {
        crate::trace!("===== PERMUTATION RELATION DEBUG =====");
        crate::dbg_fr!("num (grand_product_numerator)", &num);
        crate::dbg_fr!("den (grand_product_denominator)", &den);
        crate::dbg_fr!("public_inputs_delta", &rp.public_inputs_delta);
        crate::dbg_fr!("lag_first", &lag_first);
        crate::dbg_fr!("lag_last", &lag_last);
        crate::dbg_fr!("z_perm", &z_perm);
        crate::dbg_fr!("z_perm_shift", &z_perm_shift);
        crate::dbg_fr!("lhs = (z_perm + lag_first) * num", &lhs);
        crate::dbg_fr!("delta_term = lag_last * delta", &delta_term);
        crate::dbg_fr!("rhs = (z_perm_shift + delta_term) * den", &rhs);
        crate::dbg_fr!("out[2] = (lhs - rhs) * d", &out[2]);
    }

    // Subrelation 3: lag_last * z_perm_shift
    out[3] = fr_mul(&fr_mul(&lag_last, &z_perm_shift), d);
}

/// Accumulate lookup subrelations (indices 4-6)
fn accumulate_lookup(evals: &[Fr], rp: &RelationParameters, out: &mut [Fr], d: &Fr) {
    let w_l = wire(evals, Wire::Wl);
    let w_r = wire(evals, Wire::Wr);
    let w_o = wire(evals, Wire::Wo);
    let w_l_shift = wire(evals, Wire::WlShift);
    let w_r_shift = wire(evals, Wire::WrShift);
    let w_o_shift = wire(evals, Wire::WoShift);

    let q_r = wire(evals, Wire::Qr);
    let q_m = wire(evals, Wire::Qm);
    let q_c = wire(evals, Wire::Qc);
    let q_o = wire(evals, Wire::Qo);
    let q_lookup = wire(evals, Wire::QLookup);

    let table1 = wire(evals, Wire::Table1);
    let table2 = wire(evals, Wire::Table2);
    let table3 = wire(evals, Wire::Table3);
    let table4 = wire(evals, Wire::Table4);

    let lookup_inv = wire(evals, Wire::LookupInverses);
    let lookup_read_counts = wire(evals, Wire::LookupReadCounts);
    let lookup_read_tags = wire(evals, Wire::LookupReadTags);

    #[cfg(feature = "debug")]
    {
        crate::trace!("===== LOOKUP VALUES =====");
        crate::dbg_fr!("q_lookup", &q_lookup);
        crate::dbg_fr!("lookup_inverses", &lookup_inv);
        crate::dbg_fr!("lookup_read_tags", &lookup_read_tags);
        crate::dbg_fr!("lookup_read_counts", &lookup_read_counts);
    }

    // Write term: table1 + γ + table2*η + table3*η² + table4*η³
    let mut write_term = fr_add(&table1, &rp.gamma);
    write_term = fr_add(&write_term, &fr_mul(&table2, &rp.eta));
    write_term = fr_add(&write_term, &fr_mul(&table3, &rp.eta_two));
    write_term = fr_add(&write_term, &fr_mul(&table4, &rp.eta_three));

    // Derived entries
    let derived_2 = fr_add(&w_r, &fr_mul(&q_m, &w_r_shift));
    let derived_3 = fr_add(&w_o, &fr_mul(&q_c, &w_o_shift));

    // Read term
    let mut read_term = fr_add(&w_l, &rp.gamma);
    read_term = fr_add(&read_term, &fr_mul(&q_r, &w_l_shift));
    read_term = fr_add(&read_term, &fr_mul(&derived_2, &rp.eta));
    read_term = fr_add(&read_term, &fr_mul(&derived_3, &rp.eta_two));
    read_term = fr_add(&read_term, &fr_mul(&q_o, &rp.eta_three));

    // inv_exists = read_tags + q_lookup - read_tags * q_lookup
    let inv_exists = fr_sub(
        &fr_add(&lookup_read_tags, &q_lookup),
        &fr_mul(&lookup_read_tags, &q_lookup),
    );

    // Subrelation 4: (read_term * write_term * inv - inv_exists) * d
    let product = fr_mul(&fr_mul(&read_term, &write_term), &lookup_inv);
    out[4] = fr_mul(&fr_sub(&product, &inv_exists), d);

    // Subrelation 5: q_lookup * (write_term * inv) - read_counts * (read_term * inv)
    // Solidity: read_inverse = LOOKUP_INVERSES * write_term
    //           write_inverse = LOOKUP_INVERSES * read_term
    //           accumulatorOne = Q_LOOKUP * read_inverse - READ_COUNTS * write_inverse
    let read_inverse = fr_mul(&lookup_inv, &write_term); // inv * write = read_inverse in Solidity
    let write_inverse = fr_mul(&lookup_inv, &read_term); // inv * read = write_inverse in Solidity
    let lhs5 = fr_mul(&q_lookup, &read_inverse);
    let rhs5 = fr_mul(&lookup_read_counts, &write_inverse);
    out[5] = fr_sub(&lhs5, &rhs5);

    #[cfg(feature = "debug")]
    {
        crate::trace!("===== LOOKUP SUBREL[5] TRACE =====");
        crate::dbg_fr!("q_lookup", &q_lookup);
        crate::dbg_fr!("read_inverse (inv*write)", &read_inverse);
        crate::dbg_fr!("write_inverse (inv*read)", &write_inverse);
        crate::dbg_fr!("lhs = q_lookup * read_inverse", &lhs5);
        crate::dbg_fr!("rhs = read_counts * write_inverse", &rhs5);
        crate::dbg_fr!("out[5] = lhs - rhs", &out[5]);
    }

    // NOTE: bb 0.87 removed the read_tag_boolean subrelation (was index 6)
    // Lookup now only has 2 subrelations (indices 4-5)
}

/// Accumulate range/delta-range subrelations (indices 6-9 in bb 0.87)
fn accumulate_range(evals: &[Fr], out: &mut [Fr], d: &Fr) {
    let w_l = wire(evals, Wire::Wl);
    let w_r = wire(evals, Wire::Wr);
    let w_o = wire(evals, Wire::Wo);
    let w_4 = wire(evals, Wire::W4);
    let w_l_shift = wire(evals, Wire::WlShift);
    let q_range = wire(evals, Wire::QRange);

    #[cfg(feature = "debug")]
    {
        crate::dbg_fr!("q_range", &q_range);
    }

    let deltas = [
        fr_sub(&w_r, &w_l),
        fr_sub(&w_o, &w_r),
        fr_sub(&w_4, &w_o),
        fr_sub(&w_l_shift, &w_4),
    ];

    let neg_one = fr_neg(&SCALAR_ONE);
    let neg_two = fr_neg(&fr_from_u64(2));
    let neg_three = fr_neg(&fr_from_u64(3));

    // Solidity uses indices 7, 8, 9, 10 for range relations
    for i in 0..4 {
        // delta * (delta - 1) * (delta - 2) * (delta - 3)
        let mut acc = deltas[i];
        acc = fr_mul(&acc, &fr_add(&deltas[i], &neg_one));
        acc = fr_mul(&acc, &fr_add(&deltas[i], &neg_two));
        acc = fr_mul(&acc, &fr_add(&deltas[i], &neg_three));
        out[6 + i] = fr_mul(&fr_mul(&acc, &q_range), d);
    }
}

/// Accumulate elliptic subrelations (indices 11-12)
fn accumulate_elliptic(evals: &[Fr], out: &mut [Fr], d: &Fr) {
    let x1 = wire(evals, Wire::Wr);
    let y1 = wire(evals, Wire::Wo);
    let x2 = wire(evals, Wire::WlShift);
    let y2 = wire(evals, Wire::W4Shift);
    let x3 = wire(evals, Wire::WrShift);
    let y3 = wire(evals, Wire::WoShift);

    let q_sign = wire(evals, Wire::Ql);
    let q_double = wire(evals, Wire::Qm);
    let q_elliptic = wire(evals, Wire::QElliptic);

    #[cfg(feature = "debug")]
    {
        crate::dbg_fr!("q_elliptic", &q_elliptic);
    }

    let delta_x = fr_sub(&x2, &x1);
    let y1_sq = fr_mul(&y1, &y1);

    // Point addition identity
    let y2_sq = fr_mul(&y2, &y2);
    let y1y2 = fr_mul(&fr_mul(&y1, &y2), &q_sign);

    // x_add_id = (x3 + x2 + x1) * delta_x² - y2² - y1² + 2*y1*y2*sign
    let x_sum = fr_add(&fr_add(&x3, &x2), &x1);
    let dx_sq = fr_mul(&delta_x, &delta_x);
    let mut x_add_id = fr_mul(&x_sum, &dx_sq);
    x_add_id = fr_sub(&x_add_id, &y2_sq);
    x_add_id = fr_sub(&x_add_id, &y1_sq);
    x_add_id = fr_add(&x_add_id, &fr_add(&y1y2, &y1y2));

    // y_add_id = (y1 + y3) * delta_x + (x3 - x1) * (y2*sign - y1)
    let y_diff = fr_sub(&fr_mul(&y2, &q_sign), &y1);
    let y_add_id = fr_add(
        &fr_mul(&fr_add(&y1, &y3), &delta_x),
        &fr_mul(&fr_sub(&x3, &x1), &y_diff),
    );

    // Point doubling identity
    let b_neg = fr_from_u64(17); // BN254 b = -17

    // x_double_id = (x3 + 2*x1) * 4*y1² - 9*(y1² + b)*x1
    let y1_sq_4 = fr_add(&fr_add(&y1_sq, &y1_sq), &fr_add(&y1_sq, &y1_sq));
    let x_pow_4 = fr_mul(&fr_add(&y1_sq, &b_neg), &x1);
    let x_pow_4_9 = fr_mul(&x_pow_4, &fr_from_u64(9));
    let x_double_id = fr_sub(
        &fr_mul(&fr_add(&x3, &fr_add(&x1, &x1)), &y1_sq_4),
        &x_pow_4_9,
    );

    // y_double_id = 3*x1² * (x1 - x3) - 2*y1 * (y1 + y3)
    let x1_sq_3 = fr_mul(&fr_add(&fr_add(&x1, &x1), &x1), &x1);
    let y1_2 = fr_add(&y1, &y1);
    let y_double_id = fr_sub(
        &fr_mul(&x1_sq_3, &fr_sub(&x1, &x3)),
        &fr_mul(&y1_2, &fr_add(&y1, &y3)),
    );

    // Combine with selectors
    // bb 0.87 uses indices 10 and 11
    let add_factor = fr_mul(&fr_mul(&fr_sub(&SCALAR_ONE, &q_double), &q_elliptic), d);
    let double_factor = fr_mul(&fr_mul(&q_double, &q_elliptic), d);

    out[10] = fr_add(
        &fr_mul(&x_add_id, &add_factor),
        &fr_mul(&x_double_id, &double_factor),
    );
    out[11] = fr_add(
        &fr_mul(&y_add_id, &add_factor),
        &fr_mul(&y_double_id, &double_factor),
    );
}

/// Accumulate memory/auxiliary subrelations (indices 12-17 in bb 0.87)
/// Full implementation from Solidity verifier including non-native field and limb accumulator
fn accumulate_aux(evals: &[Fr], rp: &RelationParameters, out: &mut [Fr], d: &Fr) {
    let w_l = wire(evals, Wire::Wl);
    let w_r = wire(evals, Wire::Wr);
    let w_o = wire(evals, Wire::Wo);
    let w_4 = wire(evals, Wire::W4);
    let w_l_shift = wire(evals, Wire::WlShift);
    let w_r_shift = wire(evals, Wire::WrShift);
    let w_o_shift = wire(evals, Wire::WoShift);
    let w_4_shift = wire(evals, Wire::W4Shift);

    let q_c = wire(evals, Wire::Qc);
    let q_l = wire(evals, Wire::Ql);
    let q_r = wire(evals, Wire::Qr);
    let q_o = wire(evals, Wire::Qo);
    let q_m = wire(evals, Wire::Qm);
    let q_4 = wire(evals, Wire::Q4);
    let q_arith = wire(evals, Wire::QArith);
    let q_aux = wire(evals, Wire::QAux);

    // Constants for limb arithmetic
    // LIMB_SIZE = 2^68
    let limb_size = fr_from_hex("0x100000000000000000");
    // SUBLIMB_SHIFT = 2^14
    let sublimb_shift = fr_from_hex("0x4000");

    // =========== NON-NATIVE FIELD IDENTITY ===========
    // limb_subproduct = w_l * w_r_shift + w_l_shift * w_r
    let limb_subproduct_1 = fr_add(&fr_mul(&w_l, &w_r_shift), &fr_mul(&w_l_shift, &w_r));

    // non_native_field_gate_2 = ((w_l * w_4 + w_r * w_o - w_o_shift) * LIMB_SIZE - w_4_shift + limb_subproduct) * q_4
    let mut nnf_gate_2 = fr_add(&fr_mul(&w_l, &w_4), &fr_mul(&w_r, &w_o));
    nnf_gate_2 = fr_sub(&nnf_gate_2, &w_o_shift);
    nnf_gate_2 = fr_mul(&nnf_gate_2, &limb_size);
    nnf_gate_2 = fr_sub(&nnf_gate_2, &w_4_shift);
    nnf_gate_2 = fr_add(&nnf_gate_2, &limb_subproduct_1);
    nnf_gate_2 = fr_mul(&nnf_gate_2, &q_4);

    // limb_subproduct updated = limb_subproduct * LIMB_SIZE + w_l_shift * w_r_shift
    let limb_subproduct_2 = fr_add(
        &fr_mul(&limb_subproduct_1, &limb_size),
        &fr_mul(&w_l_shift, &w_r_shift),
    );

    // non_native_field_gate_1 = (limb_subproduct - (w_o + w_4)) * q_o
    let nnf_gate_1 = fr_mul(&fr_sub(&limb_subproduct_2, &fr_add(&w_o, &w_4)), &q_o);

    // non_native_field_gate_3 = (limb_subproduct + w_4 - (w_o_shift + w_4_shift)) * q_m
    let nnf_gate_3 = fr_mul(
        &fr_sub(
            &fr_add(&limb_subproduct_2, &w_4),
            &fr_add(&w_o_shift, &w_4_shift),
        ),
        &q_m,
    );

    // non_native_field_identity = (gate_1 + gate_2 + gate_3) * q_r
    let non_native_field_identity = fr_mul(
        &fr_add(&fr_add(&nnf_gate_1, &nnf_gate_2), &nnf_gate_3),
        &q_r,
    );

    // =========== LIMB ACCUMULATOR IDENTITY ===========
    // limb_accumulator_1 = ((((w_r_shift * 2^14 + w_l_shift) * 2^14 + w_o) * 2^14 + w_r) * 2^14 + w_l - w_4) * q_4
    let mut limb_acc_1 = fr_mul(&w_r_shift, &sublimb_shift);
    limb_acc_1 = fr_add(&limb_acc_1, &w_l_shift);
    limb_acc_1 = fr_mul(&limb_acc_1, &sublimb_shift);
    limb_acc_1 = fr_add(&limb_acc_1, &w_o);
    limb_acc_1 = fr_mul(&limb_acc_1, &sublimb_shift);
    limb_acc_1 = fr_add(&limb_acc_1, &w_r);
    limb_acc_1 = fr_mul(&limb_acc_1, &sublimb_shift);
    limb_acc_1 = fr_add(&limb_acc_1, &w_l);
    limb_acc_1 = fr_sub(&limb_acc_1, &w_4);
    limb_acc_1 = fr_mul(&limb_acc_1, &q_4);

    // limb_accumulator_2 = ((((w_o_shift * 2^14 + w_r_shift) * 2^14 + w_l_shift) * 2^14 + w_4) * 2^14 + w_o - w_4_shift) * q_m
    let mut limb_acc_2 = fr_mul(&w_o_shift, &sublimb_shift);
    limb_acc_2 = fr_add(&limb_acc_2, &w_r_shift);
    limb_acc_2 = fr_mul(&limb_acc_2, &sublimb_shift);
    limb_acc_2 = fr_add(&limb_acc_2, &w_l_shift);
    limb_acc_2 = fr_mul(&limb_acc_2, &sublimb_shift);
    limb_acc_2 = fr_add(&limb_acc_2, &w_4);
    limb_acc_2 = fr_mul(&limb_acc_2, &sublimb_shift);
    limb_acc_2 = fr_add(&limb_acc_2, &w_o);
    limb_acc_2 = fr_sub(&limb_acc_2, &w_4_shift);
    limb_acc_2 = fr_mul(&limb_acc_2, &q_m);

    // limb_accumulator_identity = (limb_acc_1 + limb_acc_2) * q_o
    let limb_accumulator_identity = fr_mul(&fr_add(&limb_acc_1, &limb_acc_2), &q_o);

    // =========== MEMORY IDENTITY ===========
    // Memory record check: w_o * eta_three + w_r * eta_two + w_l * eta + q_c - w_4
    let mut memory_record_check = fr_mul(&w_o, &rp.eta_three);
    memory_record_check = fr_add(&memory_record_check, &fr_mul(&w_r, &rp.eta_two));
    memory_record_check = fr_add(&memory_record_check, &fr_mul(&w_l, &rp.eta));
    memory_record_check = fr_add(&memory_record_check, &q_c);
    let partial_record_check = memory_record_check;
    memory_record_check = fr_sub(&memory_record_check, &w_4);

    // Index delta and record delta
    let index_delta = fr_sub(&w_l_shift, &w_l);
    let record_delta = fr_sub(&w_4_shift, &w_4);

    // index_is_monotonically_increasing = index_delta * (index_delta - 1)
    let index_is_monotonic = fr_mul(&index_delta, &fr_sub(&index_delta, &SCALAR_ONE));

    // adjacent_values_match_if_adjacent_indices_match = (-index_delta + 1) * record_delta
    let neg_index_plus_one = fr_add(&fr_neg(&index_delta), &SCALAR_ONE);
    let adjacent_values_match = fr_mul(&neg_index_plus_one, &record_delta);

    // ROM selector: q_l * q_r * q_aux * domainSep
    let rom_selector = fr_mul(&fr_mul(&q_l, &q_r), &fr_mul(&q_aux, d));

    // Subrel[13]: adjacent_values_match * rom_selector
    out[13] = fr_mul(&adjacent_values_match, &rom_selector);

    // Subrel[14]: index_is_monotonic * rom_selector
    out[14] = fr_mul(&index_is_monotonic, &rom_selector);

    // ROM consistency check identity = memory_record_check * (q_l * q_r)
    let rom_consistency = fr_mul(&memory_record_check, &fr_mul(&q_l, &q_r));

    // RAM: access type = w_4 - partial_record_check (0 or 1 for honest prover)
    let access_type = fr_sub(&w_4, &partial_record_check);
    // access_check = access_type * (access_type - 1)
    let access_check = fr_mul(&access_type, &fr_sub(&access_type, &SCALAR_ONE));

    // next_gate_access_type = w_4_shift - (w_o_shift * eta_three + w_r_shift * eta_two + w_l_shift * eta)
    let mut next_gate_access_type = fr_mul(&w_o_shift, &rp.eta_three);
    next_gate_access_type = fr_add(&next_gate_access_type, &fr_mul(&w_r_shift, &rp.eta_two));
    next_gate_access_type = fr_add(&next_gate_access_type, &fr_mul(&w_l_shift, &rp.eta));
    next_gate_access_type = fr_sub(&w_4_shift, &next_gate_access_type);

    // value_delta = w_o_shift - w_o
    let value_delta = fr_sub(&w_o_shift, &w_o);

    // adjacent_values_match_if_adjacent_indices_match_and_next_access_is_read
    // = (-index_delta + 1) * value_delta * (-next_gate_access_type + 1)
    let neg_next_plus_one = fr_add(&fr_neg(&next_gate_access_type), &SCALAR_ONE);
    let ram_adjacent = fr_mul(
        &fr_mul(&neg_index_plus_one, &value_delta),
        &neg_next_plus_one,
    );

    // next_gate_access_type_is_boolean = next_gate_access_type * (next_gate_access_type - 1)
    let next_gate_access_boolean = fr_mul(
        &next_gate_access_type,
        &fr_sub(&next_gate_access_type, &SCALAR_ONE),
    );

    // RAM selector: q_arith * q_aux * domainSep (NOT q_o!)
    let ram_selector = fr_mul(&q_arith, &fr_mul(&q_aux, d));

    // Subrel[15]: ram_adjacent * ram_selector
    out[15] = fr_mul(&ram_adjacent, &ram_selector);

    // Subrel[16]: index_is_monotonic * ram_selector
    out[16] = fr_mul(&index_is_monotonic, &ram_selector);

    // Subrel[17]: next_gate_access_boolean * ram_selector
    out[17] = fr_mul(&next_gate_access_boolean, &ram_selector);

    // RAM consistency check identity = access_check * q_arith
    let ram_consistency = fr_mul(&access_check, &q_arith);

    // Timestamp delta = w_r_shift - w_r
    let timestamp_delta = fr_sub(&w_r_shift, &w_r);

    // RAM timestamp check identity = (-index_delta + 1) * timestamp_delta - w_o
    let ram_timestamp_check = fr_sub(&fr_mul(&neg_index_plus_one, &timestamp_delta), &w_o);

    // memory_identity = rom_consistency + ram_timestamp_check * (q_4 * q_l) + memory_record_check * (q_m * q_l) + ram_consistency
    let mut memory_identity = rom_consistency;
    memory_identity = fr_add(
        &memory_identity,
        &fr_mul(&ram_timestamp_check, &fr_mul(&q_4, &q_l)),
    );
    memory_identity = fr_add(
        &memory_identity,
        &fr_mul(&memory_record_check, &fr_mul(&q_m, &q_l)),
    );
    memory_identity = fr_add(&memory_identity, &ram_consistency);

    // =========== AUXILIARY IDENTITY (evals[12]) ===========
    // auxiliary_identity = memory_identity + non_native_field_identity + limb_accumulator_identity
    // then multiply by (q_aux * domainSep)
    let auxiliary_identity = fr_add(
        &fr_add(&memory_identity, &non_native_field_identity),
        &limb_accumulator_identity,
    );
    out[12] = fr_mul(&auxiliary_identity, &fr_mul(&q_aux, d));
}

// NOTE: accumulate_nnf removed in bb 0.87 (Q_NNF no longer exists)

/// Accumulate Poseidon External subrelations (indices 19-22 in bb 0.87)
fn accumulate_poseidon_external(evals: &[Fr], out: &mut [Fr], d: &Fr) {
    let w_l = wire(evals, Wire::Wl);
    let w_r = wire(evals, Wire::Wr);
    let w_o = wire(evals, Wire::Wo);
    let w_4 = wire(evals, Wire::W4);

    let q_l = wire(evals, Wire::Ql);
    let q_r = wire(evals, Wire::Qr);
    let q_o = wire(evals, Wire::Qo);
    let q_4 = wire(evals, Wire::Q4);

    let w_l_shift = wire(evals, Wire::WlShift);
    let w_r_shift = wire(evals, Wire::WrShift);
    let w_o_shift = wire(evals, Wire::WoShift);
    let w_4_shift = wire(evals, Wire::W4Shift);

    let q_pos_ext = wire(evals, Wire::QPoseidon2External);

    #[cfg(feature = "debug")]
    {
        crate::dbg_fr!("q_poseidon2_external", &q_pos_ext);
    }

    // S-box inputs: s_i = w_i + q_i
    let s1 = fr_add(&w_l, &q_l);
    let s2 = fr_add(&w_r, &q_r);
    let s3 = fr_add(&w_o, &q_o);
    let s4 = fr_add(&w_4, &q_4);

    // S-box: u = s^5
    let u1 = pow5(&s1);
    let u2 = pow5(&s2);
    let u3 = pow5(&s3);
    let u4 = pow5(&s4);

    // External round MDS matrix
    let t0 = fr_add(&u1, &u2);
    let t1 = fr_add(&u3, &u4);
    let t2 = fr_add(&fr_add(&u2, &u2), &t1);
    let t3 = fr_add(&fr_add(&u4, &u4), &t0);

    let v4 = fr_add(&fr_add(&fr_add(&t1, &t1), &fr_add(&t1, &t1)), &t3);
    let v2 = fr_add(&fr_add(&fr_add(&t0, &t0), &fr_add(&t0, &t0)), &t2);
    let v1 = fr_add(&t3, &v2);
    let v3 = fr_add(&t2, &v4);

    // External subrelations (indices 18-21 in bb 0.87)
    out[18] = fr_mul(&fr_mul(&fr_sub(&v1, &w_l_shift), &q_pos_ext), d);
    out[19] = fr_mul(&fr_mul(&fr_sub(&v2, &w_r_shift), &q_pos_ext), d);
    out[20] = fr_mul(&fr_mul(&fr_sub(&v3, &w_o_shift), &q_pos_ext), d);
    out[21] = fr_mul(&fr_mul(&fr_sub(&v4, &w_4_shift), &q_pos_ext), d);
}

/// Accumulate Poseidon Internal subrelations (indices 22-25 in bb 0.87)
fn accumulate_poseidon_internal(evals: &[Fr], out: &mut [Fr], d: &Fr) {
    let w_l = wire(evals, Wire::Wl);
    let w_r = wire(evals, Wire::Wr);
    let w_o = wire(evals, Wire::Wo);
    let w_4 = wire(evals, Wire::W4);

    let q_l = wire(evals, Wire::Ql);

    let w_l_shift = wire(evals, Wire::WlShift);
    let w_r_shift = wire(evals, Wire::WrShift);
    let w_o_shift = wire(evals, Wire::WoShift);
    let w_4_shift = wire(evals, Wire::W4Shift);

    let q_pos_int = wire(evals, Wire::QPoseidon2Internal);

    // S-box only on first element: s1 = w_l + q_l
    let s1 = fr_add(&w_l, &q_l);
    let u1 = pow5(&s1);

    // Other elements pass through
    let u2 = w_r;
    let u3 = w_o;
    let u4 = w_4;

    let u_sum = fr_add(&fr_add(&u1, &u2), &fr_add(&u3, &u4));

    // Internal diagonal matrix constants from Solidity/Barretenberg
    // INTERNAL_MATRIX_DIAGONAL = [
    //   0x10dc6e9c006ea38b04b1e03b4bd9490c0d03f98929ca1d7fb56821fd19d3b6e7,
    //   0x0c28145b6a44df3e0149b3d0a30b3bb599df9756d4dd9b84a86b38cfb45a740b,
    //   0x00544b8338791518b2c7645a50392798b21f75bb60e3596170067d00141cac15,
    //   0x222c01175718386f2e2e82eb122789e352e105a3b8fa852613bc534433ee428b
    // ]
    let diag0 = crate::field::fr_from_hex(
        "10dc6e9c006ea38b04b1e03b4bd9490c0d03f98929ca1d7fb56821fd19d3b6e7",
    );
    let diag1 = crate::field::fr_from_hex(
        "0c28145b6a44df3e0149b3d0a30b3bb599df9756d4dd9b84a86b38cfb45a740b",
    );
    let diag2 = crate::field::fr_from_hex(
        "00544b8338791518b2c7645a50392798b21f75bb60e3596170067d00141cac15",
    );
    let diag3 = crate::field::fr_from_hex(
        "222c01175718386f2e2e82eb122789e352e105a3b8fa852613bc534433ee428b",
    );

    // v_i = u_i * DIAG[i] + u_sum
    let v1 = fr_add(&fr_mul(&u1, &diag0), &u_sum);
    let v2 = fr_add(&fr_mul(&u2, &diag1), &u_sum);
    let v3 = fr_add(&fr_mul(&u3, &diag2), &u_sum);
    let v4 = fr_add(&fr_mul(&u4, &diag3), &u_sum);

    // Internal subrelations (indices 22-25 in bb 0.87)
    out[22] = fr_mul(&fr_mul(&fr_sub(&v1, &w_l_shift), &q_pos_int), d);
    out[23] = fr_mul(&fr_mul(&fr_sub(&v2, &w_r_shift), &q_pos_int), d);
    out[24] = fr_mul(&fr_mul(&fr_sub(&v3, &w_o_shift), &q_pos_int), d);
    out[25] = fr_mul(&fr_mul(&fr_sub(&v4, &w_4_shift), &q_pos_int), d);
}

/// Compute x^5 for Poseidon S-box
#[inline]
fn pow5(x: &Fr) -> Fr {
    let x2 = fr_mul(x, x);
    let x4 = fr_mul(&x2, &x2);
    fr_mul(&x4, x)
}

/// Batch all subrelations with alpha challenges
fn batch_subrelations(evals: &[Fr], alphas: &[Fr]) -> Fr {
    #[cfg(feature = "debug")]
    {
        crate::trace!("===== BATCHING =====");
        crate::trace!(
            "NUM_SUBRELATIONS = {}, alphas.len() = {}",
            evals.len(),
            alphas.len()
        );
        crate::trace!("Expected: 26 subrels, 25 alphas (bb 0.87)");
        // Verify first term computation
        let first_two = fr_add(&evals[0], &fr_mul(&evals[1], &alphas[0]));
        crate::dbg_fr!("verify: evals[0] + evals[1]*alpha[0]", &first_two);
    }

    let mut acc = evals[0];
    for (i, alpha) in alphas.iter().enumerate() {
        if i >= evals.len() - 1 {
            break; // Prevent index out of bounds
        }
        let term = fr_mul(&evals[i + 1], alpha);
        #[cfg(feature = "debug")]
        if i < 3 {
            crate::dbg_fr!(&format!("evals[{}]", i + 1), &evals[i + 1]);
            crate::dbg_fr!(&format!("alphas[{}]", i), alpha);
            crate::dbg_fr!(&format!("term[{}]", i), &term);
        }
        acc = fr_add(&acc, &term);
        #[cfg(feature = "debug")]
        if i < 3 {
            crate::dbg_fr!(&format!("batch after term {}", i + 1), &acc);
        }
    }

    #[cfg(feature = "debug")]
    {
        crate::dbg_fr!("batch_result", &acc);
    }

    acc
}

/// Accumulate all relation evaluations
///
/// This is the main entry point for relation evaluation.
/// It computes all 28 subrelations and batches them with alpha challenges.
pub fn accumulate_relation_evaluations(
    evals: &[Fr],
    rp: &RelationParameters,
    alphas: &[Fr],
    pow_partial: &Fr,
) -> Fr {
    // Debug: print all evals
    #[cfg(feature = "debug")]
    {
        crate::trace!("===== ALL {} SUMCHECK EVALS =====", evals.len());
        for (i, e) in evals.iter().enumerate() {
            if i < 15 {
                crate::dbg_fr!(&format!("eval[{:2}]", i), e);
            }
        }
    }

    let mut out = vec![SCALAR_ZERO; NUM_SUBRELATIONS];

    accumulate_arithmetic(evals, &mut out, pow_partial);
    accumulate_permutation(evals, rp, &mut out, pow_partial);
    accumulate_lookup(evals, rp, &mut out, pow_partial);
    accumulate_range(evals, &mut out, pow_partial);
    accumulate_elliptic(evals, &mut out, pow_partial);
    accumulate_aux(evals, rp, &mut out, pow_partial);
    // Note: bb 0.87 removed accumulate_nnf (Q_NNF)
    accumulate_poseidon_external(evals, &mut out, pow_partial);
    accumulate_poseidon_internal(evals, &mut out, pow_partial);

    // Debug: print all subrelation values for comparison with Solidity
    #[cfg(feature = "debug")]
    {
        crate::trace!("===== RUST SUBRELATION VALUES =====");
        for (i, v) in out.iter().enumerate() {
            crate::dbg_fr!(&format!("subrel[{:2}]", i), v);
        }
    }

    batch_subrelations(&out, alphas)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow5() {
        let x = fr_from_u64(2);
        let result = pow5(&x);
        let expected = fr_from_u64(32); // 2^5 = 32
        assert_eq!(result, expected);
    }

    #[test]
    fn test_wire_index() {
        // Wire enum indices match Solidity verifier's WIRE enum (bb 0.87)
        assert_eq!(Wire::Qm as usize, 0);
        assert_eq!(Wire::QAux as usize, 10);
        assert_eq!(Wire::Wl as usize, 27);
        assert_eq!(Wire::ZPermShift as usize, 39);
    }
}
