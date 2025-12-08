//! BN254 operations using Solana syscalls
//!
//! All curve arithmetic is performed via `solana-bn254` syscalls,
//! which are available in both on-chain programs and `solana-program-test`.

use crate::errors::Bn254Error;
use crate::types::{Scalar, G1, G2};
use solana_bn254::prelude::{
    alt_bn128_g1_addition_be, alt_bn128_g1_multiplication_be, alt_bn128_pairing_be,
};

extern crate alloc;
use alloc::format;
use alloc::vec::Vec;

/// Performs G1 addition using the alt_bn128_g1_addition_be syscall.
pub fn g1_add(a: &G1, b: &G1) -> Result<G1, Bn254Error> {
    let mut input = [0u8; 128];
    input[..64].copy_from_slice(a);
    input[64..].copy_from_slice(b);

    let result = alt_bn128_g1_addition_be(&input)
        .map_err(|e| Bn254Error::SyscallError(format!("G1 addition failed: {:?}", e)))?;

    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    Ok(out)
}

/// Performs G1 scalar multiplication using the alt_bn128_g1_multiplication_be syscall.
pub fn g1_mul(point: &G1, scalar: &Scalar) -> Result<G1, Bn254Error> {
    let mut input = [0u8; 96];
    input[..64].copy_from_slice(point);
    input[64..].copy_from_slice(scalar);

    let result = alt_bn128_g1_multiplication_be(&input)
        .map_err(|e| Bn254Error::SyscallError(format!("G1 multiplication failed: {:?}", e)))?;

    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    Ok(out)
}

/// Performs G1 subtraction (a - b = a + (-b))
pub fn g1_sub(a: &G1, b: &G1) -> Result<G1, Bn254Error> {
    let neg_b = g1_neg(b)?;
    g1_add(a, &neg_b)
}

/// Negates a G1 point (negate y coordinate)
pub fn g1_neg(point: &G1) -> Result<G1, Bn254Error> {
    // For BN254, negation is (x, -y) where -y is computed mod p
    // p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
    let p = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c,
        0xfd, 0x47,
    ];

    let mut result = *point;

    // Negate y: y' = p - y (if y != 0)
    let y = &point[32..64];
    let is_zero = y.iter().all(|&b| b == 0);

    if !is_zero {
        // Compute p - y using big-endian subtraction
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let diff = p[i] as i16 - y[i] as i16 - borrow;
            if diff < 0 {
                result[32 + i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                result[32 + i] = diff as u8;
                borrow = 0;
            }
        }
    }

    Ok(result)
}

/// Performs a multi-pairing check using the alt_bn128_pairing_be syscall.
/// Returns true if ∏ e(a_i, b_i) == 1 (identity in GT)
pub fn pairing_check(pairs: &[(G1, G2)]) -> Result<bool, Bn254Error> {
    if pairs.is_empty() {
        return Ok(true);
    }

    let mut input = Vec::with_capacity(pairs.len() * 192);
    for (g1, g2) in pairs {
        input.extend_from_slice(g1);
        input.extend_from_slice(g2);
    }

    let result = alt_bn128_pairing_be(&input)
        .map_err(|e| Bn254Error::SyscallError(format!("Pairing check failed: {:?}", e)))?;

    // The syscall returns 32 bytes, with 0x01 in the last byte if the pairing check passes
    if result.len() != 32 {
        return Err(Bn254Error::PairingFailed);
    }

    Ok(result[31] == 1)
}

/// G1 scalar multiplication alias
pub fn g1_scalar_mul(point: &G1, scalar: &Scalar) -> Result<G1, Bn254Error> {
    g1_mul(point, scalar)
}

/// Returns the G1 generator point (1, 2)
pub fn g1_generator() -> G1 {
    crate::types::G1_GENERATOR
}

/// Performs a multi-scalar multiplication (MSM) for G1 points.
/// Computes ∑ scalars[i] * points[i]
pub fn g1_msm(points: &[G1], scalars: &[Scalar]) -> Result<G1, Bn254Error> {
    if points.len() != scalars.len() {
        return Err(Bn254Error::InvalidG1);
    }

    if points.is_empty() {
        return Ok([0u8; 64]); // Identity
    }

    let mut acc = g1_mul(&points[0], &scalars[0])?;
    for i in 1..points.len() {
        let term = g1_mul(&points[i], &scalars[i])?;
        acc = g1_add(&acc, &term)?;
    }

    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::G1_IDENTITY;

    #[test]
    fn test_g1_neg_identity() {
        let neg = g1_neg(&G1_IDENTITY).unwrap();
        assert_eq!(neg, G1_IDENTITY);
    }

    // Note: Tests that use syscalls will only work in solana-program-test environment
    // For unit tests, we test the pure logic parts
}
