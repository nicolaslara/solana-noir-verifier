//! Scalar field arithmetic for BN254
//!
//! Implements Fr (scalar field) operations using 4 x 64-bit limbs.
//! All operations are performed modulo the scalar field order r.

use crate::types::{Fr, SCALAR_ZERO};

/// BN254 scalar field modulus r
/// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
pub const R: [u64; 4] = [
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// R^2 mod r (for Montgomery multiplication)
pub const R2: [u64; 4] = [
    0x1bb8e645ae216da7,
    0x53fe3ab1e35c59e3,
    0x8c49833d53bb8085,
    0x0216d0b17f4e44a5,
];

/// -r^{-1} mod 2^64 (Montgomery constant)
pub const INV: u64 = 0xc2e1f593efffffff;

/// Convert 32-byte big-endian Fr to 4 x u64 limbs (little-endian limbs)
#[inline]
pub fn fr_to_limbs(fr: &Fr) -> [u64; 4] {
    [
        u64::from_be_bytes([
            fr[24], fr[25], fr[26], fr[27], fr[28], fr[29], fr[30], fr[31],
        ]),
        u64::from_be_bytes([
            fr[16], fr[17], fr[18], fr[19], fr[20], fr[21], fr[22], fr[23],
        ]),
        u64::from_be_bytes([fr[8], fr[9], fr[10], fr[11], fr[12], fr[13], fr[14], fr[15]]),
        u64::from_be_bytes([fr[0], fr[1], fr[2], fr[3], fr[4], fr[5], fr[6], fr[7]]),
    ]
}

/// Convert 4 x u64 limbs (little-endian) to 32-byte big-endian Fr
#[inline]
pub fn limbs_to_fr(limbs: &[u64; 4]) -> Fr {
    let mut fr = [0u8; 32];
    let b0 = limbs[0].to_be_bytes();
    let b1 = limbs[1].to_be_bytes();
    let b2 = limbs[2].to_be_bytes();
    let b3 = limbs[3].to_be_bytes();
    fr[24..32].copy_from_slice(&b0);
    fr[16..24].copy_from_slice(&b1);
    fr[8..16].copy_from_slice(&b2);
    fr[0..8].copy_from_slice(&b3);
    fr
}

/// Reduce a 256-bit value mod r
/// This is equivalent to Solidity's FrLib.fromBytes32
/// Note: The input can be any 256-bit value, which may be up to ~5x larger than r
#[inline]
pub fn fr_reduce(a: &Fr) -> Fr {
    let mut limbs = fr_to_limbs(a);

    // Keep subtracting r until result < r
    // In worst case, hash output is ~2^256 which is ~5.8 * r
    // So we need at most 6 iterations
    loop {
        let (result, borrow) = sbb_limbs(&limbs, &R);
        if borrow != 0 {
            // limbs < r, we're done
            break;
        }
        // limbs >= r, continue with result
        limbs = result;
    }

    limbs_to_fr(&limbs)
}

/// Subtract with borrow, returning (result, borrow)
#[inline]
fn sbb_limbs(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], u64) {
    let mut result = [0u64; 4];
    let mut borrow = 0u64;

    for i in 0..4 {
        let (diff1, borrow1) = a[i].overflowing_sub(b[i]);
        let (diff2, borrow2) = diff1.overflowing_sub(borrow);
        result[i] = diff2;
        borrow = (borrow1 as u64) | (borrow2 as u64);
    }

    (result, borrow)
}

/// Add two field elements: a + b mod r
pub fn fr_add(a: &Fr, b: &Fr) -> Fr {
    let a_limbs = fr_to_limbs(a);
    let b_limbs = fr_to_limbs(b);
    let result = add_mod(&a_limbs, &b_limbs);
    limbs_to_fr(&result)
}

/// Subtract two field elements: a - b mod r
pub fn fr_sub(a: &Fr, b: &Fr) -> Fr {
    let a_limbs = fr_to_limbs(a);
    let b_limbs = fr_to_limbs(b);
    let result = sub_mod(&a_limbs, &b_limbs);
    limbs_to_fr(&result)
}

/// Negate a field element: -a mod r
pub fn fr_neg(a: &Fr) -> Fr {
    if *a == SCALAR_ZERO {
        return SCALAR_ZERO;
    }
    let a_limbs = fr_to_limbs(a);
    let result = sub_mod(&R, &a_limbs);
    limbs_to_fr(&result)
}

/// Multiply two field elements: a * b mod r
pub fn fr_mul(a: &Fr, b: &Fr) -> Fr {
    let a_limbs = fr_to_limbs(a);
    let b_limbs = fr_to_limbs(b);
    let result = mul_mod_wide(&a_limbs, &b_limbs);
    limbs_to_fr(&result)
}

/// Square a field element: a^2 mod r
pub fn fr_square(a: &Fr) -> Fr {
    fr_mul(a, a)
}

/// Compute multiplicative inverse: a^{-1} mod r
/// Returns None if a is zero
pub fn fr_inv(a: &Fr) -> Option<Fr> {
    if *a == SCALAR_ZERO {
        return None;
    }
    // Use Fermat's little theorem: a^{-1} = a^{r-2} mod r
    let a_limbs = fr_to_limbs(a);
    let result = pow_mod(&a_limbs, &R_MINUS_2);
    Some(limbs_to_fr(&result))
}

/// Divide two field elements: a / b mod r
/// Returns None if b is zero
pub fn fr_div(a: &Fr, b: &Fr) -> Option<Fr> {
    let b_inv = fr_inv(b)?;
    Some(fr_mul(a, &b_inv))
}

/// Check if a field element is zero
pub fn fr_is_zero(a: &Fr) -> bool {
    *a == SCALAR_ZERO
}

/// Convert u64 to Fr
pub fn fr_from_u64(val: u64) -> Fr {
    let mut fr = SCALAR_ZERO;
    let bytes = val.to_be_bytes();
    fr[24..32].copy_from_slice(&bytes);
    fr
}

/// Convert a hex string (without 0x prefix) to Fr
/// The hex string should be 64 characters (32 bytes)
pub fn fr_from_hex(hex: &str) -> Fr {
    let mut fr = SCALAR_ZERO;
    // Pad with zeros if shorter than 64 chars
    let padded = format!("{:0>64}", hex);
    for (i, chunk) in padded.as_bytes().chunks(2).enumerate() {
        let s = core::str::from_utf8(chunk).unwrap_or("00");
        let byte = u8::from_str_radix(s, 16).unwrap_or(0);
        fr[i] = byte;
    }
    fr
}

// --- Internal functions for limb arithmetic ---

/// r - 2 (for computing inverse via Fermat's little theorem)
const R_MINUS_2: [u64; 4] = [
    0x43e1f593efffffff, // limb 0 (least significant)
    0x2833e84879b97091, // limb 1
    0xb85045b68181585d, // limb 2
    0x30644e72e131a029, // limb 3 (most significant)
];

/// Add two 256-bit numbers, returning a + b mod r
fn add_mod(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (sum, overflow) = add_with_carry(a, b);
    if overflow || gte(&sum, &R) {
        sub_no_borrow(&sum, &R)
    } else {
        sum
    }
}

/// Subtract two 256-bit numbers, returning a - b mod r
fn sub_mod(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    if gte(a, b) {
        sub_no_borrow(a, b)
    } else {
        // a < b, so compute r - (b - a)
        let diff = sub_no_borrow(b, a);
        sub_no_borrow(&R, &diff)
    }
}

/// Multiply two 256-bit numbers mod r using widening multiplication
fn mul_mod_wide(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    // First compute full 512-bit product
    let mut wide = [0u64; 8];

    for i in 0..4 {
        let mut carry = 0u64;
        for j in 0..4 {
            let (lo, hi) = mul_with_carry(a[j], b[i], wide[i + j], carry);
            wide[i + j] = lo;
            carry = hi;
        }
        wide[i + 4] = carry;
    }

    // Now reduce mod r
    reduce_512(&wide)
}

/// 2^256 mod r
/// r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
const TWO_256_MOD_R: [u64; 4] = [
    0xac96341c4ffffffb, // limb 0 (least significant)
    0x36fc76959f60cd29, // limb 1
    0x666ea36f7879462e, // limb 2
    0x0e0a77c19a07df2f, // limb 3 (most significant)
];

/// Reduce a 512-bit number mod r
fn reduce_512(wide: &[u64; 8]) -> [u64; 4] {
    // Split into low (256 bits) and high (256 bits)
    let mut low = [wide[0], wide[1], wide[2], wide[3]];
    let mut high = [wide[4], wide[5], wide[6], wide[7]];

    // result = low + high * (2^256 mod r)
    // Since high * (2^256 mod r) could still be > r, we may need multiple iterations

    while !is_zero_4(&high) {
        // Compute high * TWO_256_MOD_R
        let product = mul_wide_4x4(&high, &TWO_256_MOD_R);

        // Add product's low part to low
        let (sum, overflow) =
            add_with_carry(&low, &[product[0], product[1], product[2], product[3]]);
        low = sum;

        // New high is product's high part plus overflow
        high = [product[4], product[5], product[6], product[7]];
        if overflow {
            // Add 1 to high
            let (new_high, _) = add_with_carry(&high, &[1, 0, 0, 0]);
            high = new_high;
        }
    }

    // Final reduction to ensure low < r
    while gte(&low, &R) {
        low = sub_no_borrow(&low, &R);
    }

    low
}

fn is_zero_4(a: &[u64; 4]) -> bool {
    a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == 0
}

/// Multiply two 256-bit numbers to get 512-bit result (no reduction)
fn mul_wide_4x4(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut result = [0u64; 8];

    for i in 0..4 {
        let mut carry = 0u64;
        for j in 0..4 {
            let (lo, hi) = mul_with_carry(a[j], b[i], result[i + j], carry);
            result[i + j] = lo;
            carry = hi;
        }
        result[i + 4] = carry;
    }

    result
}

/// Compute a^exp mod r using square-and-multiply
fn pow_mod(base: &[u64; 4], exp: &[u64; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    result[0] = 1; // result = 1

    let mut base_pow = *base;

    for i in 0..4 {
        let mut e = exp[i];
        for _ in 0..64 {
            if e & 1 == 1 {
                result = mul_mod_wide(&result, &base_pow);
            }
            base_pow = mul_mod_wide(&base_pow, &base_pow);
            e >>= 1;
        }
    }

    result
}

/// Add two 256-bit numbers with carry
fn add_with_carry(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], bool) {
    let mut result = [0u64; 4];
    let mut carry = 0u64;

    for i in 0..4 {
        let (sum1, c1) = a[i].overflowing_add(b[i]);
        let (sum2, c2) = sum1.overflowing_add(carry);
        result[i] = sum2;
        carry = (c1 as u64) + (c2 as u64);
    }

    (result, carry > 0)
}

/// Subtract b from a (assumes a >= b)
fn sub_no_borrow(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    let mut borrow = 0u64;

    for i in 0..4 {
        let (diff1, b1) = a[i].overflowing_sub(b[i]);
        let (diff2, b2) = diff1.overflowing_sub(borrow);
        result[i] = diff2;
        borrow = (b1 as u64) + (b2 as u64);
    }

    result
}

/// Check if a >= b
fn gte(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true // equal
}

/// Multiply two u64 with carry: (a * b + c + carry) = (hi, lo)
fn mul_with_carry(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let product = (a as u128) * (b as u128) + (c as u128) + (carry as u128);
    (product as u64, (product >> 64) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SCALAR_ONE;

    #[test]
    fn test_fr_add_simple() {
        let a = fr_from_u64(10);
        let b = fr_from_u64(20);
        let c = fr_add(&a, &b);
        assert_eq!(c, fr_from_u64(30));
    }

    #[test]
    fn test_fr_sub_simple() {
        let a = fr_from_u64(30);
        let b = fr_from_u64(10);
        let c = fr_sub(&a, &b);
        assert_eq!(c, fr_from_u64(20));
    }

    #[test]
    fn test_fr_mul_simple() {
        let a = fr_from_u64(6);
        let b = fr_from_u64(7);
        let c = fr_mul(&a, &b);
        assert_eq!(c, fr_from_u64(42));
    }

    #[test]
    fn test_fr_neg() {
        let a = fr_from_u64(1);
        let neg_a = fr_neg(&a);
        let sum = fr_add(&a, &neg_a);
        assert_eq!(sum, SCALAR_ZERO);
    }

    #[test]
    fn test_fr_inv() {
        let a = fr_from_u64(7);
        let a_inv = fr_inv(&a).unwrap();
        let product = fr_mul(&a, &a_inv);
        assert_eq!(product, SCALAR_ONE);
    }

    #[test]
    fn test_fr_div() {
        let a = fr_from_u64(42);
        let b = fr_from_u64(7);
        let c = fr_div(&a, &b).unwrap();
        assert_eq!(c, fr_from_u64(6));
    }

    #[test]
    fn test_fr_zero_inv() {
        assert!(fr_inv(&SCALAR_ZERO).is_none());
    }

    #[test]
    fn test_fr_conversion_roundtrip() {
        let original = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ];
        let limbs = fr_to_limbs(&original);
        let back = limbs_to_fr(&limbs);
        assert_eq!(original, back);
    }

    #[test]
    fn test_fr_sub_underflow() {
        // Test subtraction that wraps around modulus
        let a = fr_from_u64(5);
        let b = fr_from_u64(10);
        let c = fr_sub(&a, &b); // Should be r - 5
        let d = fr_add(&c, &b); // Should be r - 5 + 10 = 5
        assert_eq!(d, a);
    }
}
