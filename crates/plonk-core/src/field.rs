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

/// Montgomery one: 1 in Montgomery form = R mod r
pub const MONT_ONE: [u64; 4] = [
    0xac96341c4ffffffb,
    0x36fc76959f60cd29,
    0x666ea36f7879462e,
    0x0e0a77c19a07df2f,
];

// ============================================================================
// FrLimbs: Internal field representation in Montgomery form
// ============================================================================
//
// This type stores field elements as 4 x u64 limbs in Montgomery form.
// All arithmetic operations work directly on this representation, avoiding
// the overhead of converting to/from bytes for every operation.
//
// Montgomery form: a' = a * R mod r, where R = 2^256 mod r
// Multiplication: mont_mul(a', b') = a * b * R mod r (still in Montgomery form)
//
// Only convert to bytes (Fr) at boundaries: proof parsing, public inputs, etc.

extern crate alloc;
use alloc::vec::Vec;

/// Field element in Montgomery form (4 x u64 limbs, little-endian)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrLimbs(pub [u64; 4]);

impl FrLimbs {
    /// Zero in Montgomery form
    pub const ZERO: FrLimbs = FrLimbs([0, 0, 0, 0]);

    /// One in Montgomery form
    pub const ONE: FrLimbs = FrLimbs(MONT_ONE);

    /// Create from bytes (Fr), converting to Montgomery form
    #[inline]
    pub fn from_bytes(fr: &Fr) -> Self {
        let limbs = fr_to_limbs(fr);
        FrLimbs(to_mont(&limbs))
    }

    /// Convert to bytes (Fr), converting from Montgomery form
    #[inline]
    pub fn to_bytes(&self) -> Fr {
        let normal = from_mont(&self.0);
        limbs_to_fr(&normal)
    }

    /// Create from raw limbs that are already in Montgomery form
    #[inline]
    pub const fn from_mont_limbs(limbs: [u64; 4]) -> Self {
        FrLimbs(limbs)
    }

    /// Get raw limbs (in Montgomery form)
    #[inline]
    pub const fn as_limbs(&self) -> &[u64; 4] {
        &self.0
    }

    /// Serialize to raw bytes (no Montgomery conversion)
    /// Stores the 4 u64 limbs in little-endian order
    /// Use this for storing FrLimbs in account state between transactions
    #[inline]
    pub fn to_raw_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, limb) in self.0.iter().enumerate() {
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        bytes
    }

    /// Deserialize from raw bytes (no Montgomery conversion)
    /// Reads 4 u64 limbs in little-endian order
    /// Use this for loading FrLimbs from account state between transactions
    #[inline]
    pub fn from_raw_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut limb_bytes = [0u8; 8];
            limb_bytes.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
            limbs[i] = u64::from_le_bytes(limb_bytes);
        }
        FrLimbs(limbs)
    }

    /// Add: a + b mod r
    #[inline]
    pub fn add(&self, other: &FrLimbs) -> FrLimbs {
        FrLimbs(add_mod(&self.0, &other.0))
    }

    /// Subtract: a - b mod r
    #[inline]
    pub fn sub(&self, other: &FrLimbs) -> FrLimbs {
        FrLimbs(sub_mod(&self.0, &other.0))
    }

    /// Negate: -a mod r
    #[inline]
    pub fn neg(&self) -> FrLimbs {
        if self.0 == [0, 0, 0, 0] {
            FrLimbs::ZERO
        } else {
            FrLimbs(sub_mod(&R, &self.0))
        }
    }

    /// Multiply: a * b mod r (single Montgomery multiplication!)
    #[inline]
    pub fn mul(&self, other: &FrLimbs) -> FrLimbs {
        // Since both inputs are in Montgomery form (a' = a*R, b' = b*R),
        // mont_mul(a', b') = a' * b' * R^-1 = a*R * b*R * R^-1 = a*b*R
        // which is a*b in Montgomery form. Perfect!
        FrLimbs(mont_mul(&self.0, &other.0))
    }

    /// Square: a^2 mod r
    #[inline]
    pub fn square(&self) -> FrLimbs {
        self.mul(self)
    }

    /// Multiplicative inverse: a^{-1} mod r
    /// Returns None if a is zero
    #[inline]
    pub fn inv(&self) -> Option<FrLimbs> {
        if self.0 == [0, 0, 0, 0] {
            return None;
        }
        // Convert out of Montgomery form, invert, convert back
        let normal = from_mont(&self.0);
        let inv_normal = binary_ext_gcd_inv(&normal);
        Some(FrLimbs(to_mont(&inv_normal)))
    }

    /// Check if zero
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }
}

// ============================================================================
// SmallFrArray: Stack-allocated array to replace Vec in hot paths
// ============================================================================

/// Maximum log_n we support (proofs are padded to this)
pub const MAX_LOG_N: usize = 32;

/// Stack-allocated array of FrLimbs - avoids heap allocation overhead
/// Use instead of Vec<FrLimbs> in hot paths where capacity is bounded
#[derive(Clone, Copy)]
pub struct SmallFrArray<const N: usize> {
    data: [FrLimbs; N],
    len: usize,
}

impl<const N: usize> SmallFrArray<N> {
    /// Create empty array
    #[inline(always)]
    pub const fn new() -> Self {
        SmallFrArray {
            data: [FrLimbs::ZERO; N],
            len: 0,
        }
    }

    /// Push element (panics if full in debug, UB in release)
    #[inline(always)]
    pub fn push(&mut self, x: FrLimbs) {
        debug_assert!(self.len < N, "SmallFrArray overflow");
        self.data[self.len] = x;
        self.len += 1;
    }

    /// Get slice of populated elements
    #[inline(always)]
    pub fn as_slice(&self) -> &[FrLimbs] {
        &self.data[..self.len]
    }

    /// Get mutable slice of populated elements
    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [FrLimbs] {
        &mut self.data[..self.len]
    }

    /// Current length
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Is empty
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get element by index
    #[inline(always)]
    pub fn get(&self, idx: usize) -> Option<&FrLimbs> {
        if idx < self.len {
            Some(&self.data[idx])
        } else {
            None
        }
    }

    /// Index access (panics if out of bounds in debug)
    #[inline(always)]
    pub fn at(&self, idx: usize) -> &FrLimbs {
        debug_assert!(idx < self.len, "SmallFrArray index out of bounds");
        &self.data[idx]
    }

    /// Mutable index access
    #[inline(always)]
    pub fn at_mut(&mut self, idx: usize) -> &mut FrLimbs {
        debug_assert!(idx < self.len, "SmallFrArray index out of bounds");
        &mut self.data[idx]
    }

    /// Set length (for pre-sized arrays)
    #[inline(always)]
    pub fn set_len(&mut self, len: usize) {
        debug_assert!(len <= N, "SmallFrArray set_len overflow");
        self.len = len;
    }
}

impl<const N: usize> core::ops::Index<usize> for SmallFrArray<N> {
    type Output = FrLimbs;
    #[inline(always)]
    fn index(&self, idx: usize) -> &FrLimbs {
        &self.data[idx]
    }
}

impl<const N: usize> core::ops::IndexMut<usize> for SmallFrArray<N> {
    #[inline(always)]
    fn index_mut(&mut self, idx: usize) -> &mut FrLimbs {
        &mut self.data[idx]
    }
}

/// Batch inversion for FrLimbs using Montgomery's trick
/// Given [a0, a1, ..., an-1], computes [1/a0, 1/a1, ..., 1/an-1] with only ONE inversion
pub fn batch_inv_limbs(inputs: &[FrLimbs]) -> Option<Vec<FrLimbs>> {
    let n = inputs.len();
    if n == 0 {
        return Some(Vec::new());
    }

    // Check for zeros
    for inp in inputs {
        if inp.is_zero() {
            return None;
        }
    }

    if n == 1 {
        return Some(vec![inputs[0].inv()?]);
    }

    // Step 1: Compute prefix products
    let mut prefix = Vec::with_capacity(n);
    prefix.push(FrLimbs::ONE);
    for i in 0..n - 1 {
        prefix.push(prefix[i].mul(&inputs[i]));
    }

    // Step 2: Compute product of all inputs and invert it
    let all_product = prefix[n - 1].mul(&inputs[n - 1]);
    let mut inv_suffix = all_product.inv()?;

    // Step 3: Walk backwards to compute each inverse
    let mut result = vec![FrLimbs::ZERO; n];
    for i in (0..n).rev() {
        result[i] = prefix[i].mul(&inv_suffix);
        if i > 0 {
            inv_suffix = inv_suffix.mul(&inputs[i]);
        }
    }

    Some(result)
}

// ============================================================================
// Montgomery Arithmetic (faster modular multiplication)
// ============================================================================

/// Montgomery multiplication: computes a * b * R^-1 mod r
/// If inputs are in Montgomery form (a' = a*R, b' = b*R), output is (a*b)*R (also in Montgomery form)
#[inline(never)]
fn mont_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    // CIOS (Coarsely Integrated Operand Scanning) Montgomery multiplication
    let mut t = [0u64; 5]; // 5 limbs to handle overflow

    for i in 0..4 {
        // Multiply-accumulate: t += a * b[i]
        let mut carry = 0u64;
        for j in 0..4 {
            let (lo, hi) = mac(t[j], a[j], b[i], carry);
            t[j] = lo;
            carry = hi;
        }
        let (t4, _) = t[4].overflowing_add(carry);
        t[4] = t4;

        // Montgomery reduction step
        let m = t[0].wrapping_mul(INV);

        // t += m * r
        carry = 0;
        let (_, hi) = mac(t[0], m, R[0], 0);
        carry = hi;

        for j in 1..4 {
            let (lo, hi) = mac(t[j], m, R[j], carry);
            t[j - 1] = lo;
            carry = hi;
        }
        let (lo, hi) = t[4].overflowing_add(carry);
        t[3] = lo;
        t[4] = hi as u64;
    }

    // Final reduction
    let mut result = [t[0], t[1], t[2], t[3]];
    if t[4] != 0 || gte(&result, &R) {
        result = sub_no_borrow(&result, &R);
    }
    result
}

/// Convert to Montgomery form: a -> a * R mod r
#[inline]
fn to_mont(a: &[u64; 4]) -> [u64; 4] {
    mont_mul(a, &R2)
}

/// Convert from Montgomery form: a' -> a' * R^-1 mod r = a
#[inline]
fn from_mont(a: &[u64; 4]) -> [u64; 4] {
    mont_mul(a, &[1, 0, 0, 0])
}

/// Multiply-accumulate: a + b * c + carry -> (lo, hi)
#[inline(always)]
fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let product = (a as u128) + (b as u128) * (c as u128) + (carry as u128);
    (product as u64, (product >> 64) as u64)
}

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
/// Uses Montgomery multiplication for efficiency.
///
/// By converting to Montgomery form first, we only need ONE mont_mul:
/// - Convert a -> a' = a*R (via mont_mul(a, R²))
/// - Convert b -> b' = b*R (via mont_mul(b, R²))
/// - Multiply: mont_mul(a', b') = a*R * b*R * R⁻¹ = a*b*R
/// - Convert back: mont_mul(result, 1) = a*b*R * R⁻¹ = a*b
///
/// Total: 2 conversions + 1 mul + 1 conversion = 4 mont_mul
/// But if inputs are already Fr (not Montgomery), we can be smarter:
/// - mont_mul(a, b) = a * b * R⁻¹
/// - mont_mul(result, R²) = a * b * R⁻¹ * R² * R⁻¹ = a * b
/// Total: 2 mont_mul (current approach)
pub fn fr_mul(a: &Fr, b: &Fr) -> Fr {
    let a_limbs = fr_to_limbs(a);
    let b_limbs = fr_to_limbs(b);

    // mont_mul(a, b) = a * b * R^-1 mod r
    // mont_mul(result, R2) = a * b * R^-1 * R^2 * R^-1 = a * b mod r
    let ab_div_r = mont_mul(&a_limbs, &b_limbs);
    let result = mont_mul(&ab_div_r, &R2);

    limbs_to_fr(&result)
}

/// Square a field element: a^2 mod r
pub fn fr_square(a: &Fr) -> Fr {
    fr_mul(a, a)
}

/// Compute multiplicative inverse: a^{-1} mod r using binary extended GCD
/// This is much faster than Fermat's theorem on BPF (O(n) vs O(n^2) for naive impl)
/// Returns None if a is zero
pub fn fr_inv(a: &Fr) -> Option<Fr> {
    if *a == SCALAR_ZERO {
        return None;
    }

    // Binary extended GCD algorithm
    // Computes x such that a * x ≡ 1 (mod r)
    let a_limbs = fr_to_limbs(a);
    let result = binary_ext_gcd_inv(&a_limbs);
    Some(limbs_to_fr(&result))
}

/// Batch inversion using Montgomery's trick
/// Given [a0, a1, ..., an-1], computes [1/a0, 1/a1, ..., 1/an-1] with only ONE inversion
///
/// Algorithm:
/// 1. Compute prefix products: P[i] = a[0] * a[1] * ... * a[i-1]
/// 2. Invert only P[n]: inv_all = 1 / (a[0] * a[1] * ... * a[n-1])
/// 3. Walk backwards: a[i]^{-1} = P[i] * (product of a[j]^{-1} for j > i)
///
/// Cost: 3n-3 multiplications + 1 inversion (instead of n inversions)
pub fn batch_inv(inputs: &[Fr]) -> Option<Vec<Fr>> {
    let n = inputs.len();
    if n == 0 {
        return Some(Vec::new());
    }

    // Check for zeros
    for inp in inputs {
        if *inp == SCALAR_ZERO {
            return None;
        }
    }

    if n == 1 {
        return Some(vec![fr_inv(&inputs[0])?]);
    }

    // Step 1: Compute prefix products
    // prefix[i] = inputs[0] * inputs[1] * ... * inputs[i-1]
    let mut prefix = Vec::with_capacity(n);
    prefix.push(crate::types::SCALAR_ONE);
    for i in 0..n - 1 {
        prefix.push(fr_mul(&prefix[i], &inputs[i]));
    }

    // Step 2: Compute product of all inputs and invert it
    let all_product = fr_mul(&prefix[n - 1], &inputs[n - 1]);
    let mut inv_suffix = fr_inv(&all_product)?;

    // Step 3: Walk backwards to compute each inverse
    // inv[i] = prefix[i] * inv_suffix
    // Then update inv_suffix = inv_suffix * inputs[i]
    let mut result = vec![SCALAR_ZERO; n];
    for i in (0..n).rev() {
        result[i] = fr_mul(&prefix[i], &inv_suffix);
        if i > 0 {
            inv_suffix = fr_mul(&inv_suffix, &inputs[i]);
        }
    }

    Some(result)
}

/// Binary extended GCD for modular inverse
/// Much faster than Fermat's theorem on BPF
fn binary_ext_gcd_inv(a: &[u64; 4]) -> [u64; 4] {
    // BN254 scalar field modulus r
    const R: [u64; 4] = [
        0x43e1f593f0000001,
        0x2833e84879b97091,
        0xb85045b68181585d,
        0x30644e72e131a029,
    ];

    let mut u = *a;
    let mut v = R;
    let mut x1 = [1u64, 0, 0, 0];
    let mut x2 = [0u64; 4];

    // Continue until u = 1
    while !is_one(&u) && !is_one(&v) {
        // While u is even
        while (u[0] & 1) == 0 {
            shr1(&mut u);
            if (x1[0] & 1) == 0 {
                shr1(&mut x1);
            } else {
                add_assign(&mut x1, &R);
                shr1(&mut x1);
            }
        }

        // While v is even
        while (v[0] & 1) == 0 {
            shr1(&mut v);
            if (x2[0] & 1) == 0 {
                shr1(&mut x2);
            } else {
                add_assign(&mut x2, &R);
                shr1(&mut x2);
            }
        }

        // If u >= v: u = u - v, x1 = x1 - x2
        if ge(&u, &v) {
            sub_assign(&mut u, &v);
            sub_mod_assign(&mut x1, &x2, &R);
        } else {
            sub_assign(&mut v, &u);
            sub_mod_assign(&mut x2, &x1, &R);
        }
    }

    if is_one(&u) {
        x1
    } else {
        x2
    }
}

/// Check if limbs equal 1
fn is_one(a: &[u64; 4]) -> bool {
    a[0] == 1 && a[1] == 0 && a[2] == 0 && a[3] == 0
}

/// Shift right by 1 (divide by 2)
fn shr1(a: &mut [u64; 4]) {
    a[0] = (a[0] >> 1) | (a[1] << 63);
    a[1] = (a[1] >> 1) | (a[2] << 63);
    a[2] = (a[2] >> 1) | (a[3] << 63);
    a[3] >>= 1;
}

/// Add b to a in place (no modular reduction)
fn add_assign(a: &mut [u64; 4], b: &[u64; 4]) {
    let (r0, c0) = a[0].overflowing_add(b[0]);
    let (r1, c1) = a[1].overflowing_add(b[1]);
    let (r1, c1b) = r1.overflowing_add(c0 as u64);
    let (r2, c2) = a[2].overflowing_add(b[2]);
    let (r2, c2b) = r2.overflowing_add((c1 || c1b) as u64);
    let (r3, _) = a[3].overflowing_add(b[3]);
    let (r3, _) = r3.overflowing_add((c2 || c2b) as u64);
    a[0] = r0;
    a[1] = r1;
    a[2] = r2;
    a[3] = r3;
}

/// Subtract b from a in place (assumes a >= b)
fn sub_assign(a: &mut [u64; 4], b: &[u64; 4]) {
    let (r0, borrow0) = a[0].overflowing_sub(b[0]);
    let (r1, borrow1) = a[1].overflowing_sub(b[1]);
    let (r1, borrow1b) = r1.overflowing_sub(borrow0 as u64);
    let (r2, borrow2) = a[2].overflowing_sub(b[2]);
    let (r2, borrow2b) = r2.overflowing_sub((borrow1 || borrow1b) as u64);
    let (r3, _) = a[3].overflowing_sub(b[3]);
    let (r3, _) = r3.overflowing_sub((borrow2 || borrow2b) as u64);
    a[0] = r0;
    a[1] = r1;
    a[2] = r2;
    a[3] = r3;
}

/// Subtract b from a mod m (handles underflow by adding m)
fn sub_mod_assign(a: &mut [u64; 4], b: &[u64; 4], m: &[u64; 4]) {
    if ge(a, b) {
        sub_assign(a, b);
    } else {
        // a < b, so compute a + m - b
        add_assign(a, m);
        sub_assign(a, b);
    }
}

/// Compare a >= b
fn ge(a: &[u64; 4], b: &[u64; 4]) -> bool {
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
/// Karatsuba multiplication for 4x4 limbs -> 8 limbs
/// Reduces from 16 64-bit multiplications to ~12 (25% fewer)
fn mul_wide_4x4(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    // Split into high and low 128-bit halves (2 limbs each)
    // a = a_hi * 2^128 + a_lo
    // b = b_hi * 2^128 + b_lo
    let a_lo = [a[0], a[1]];
    let a_hi = [a[2], a[3]];
    let b_lo = [b[0], b[1]];
    let b_hi = [b[2], b[3]];

    // Karatsuba:
    // z0 = a_lo * b_lo
    // z2 = a_hi * b_hi
    // z1 = (a_lo + a_hi) * (b_lo + b_hi) - z0 - z2
    // result = z2 * 2^256 + z1 * 2^128 + z0

    let z0 = mul_2x2(&a_lo, &b_lo); // 4 limbs
    let z2 = mul_2x2(&a_hi, &b_hi); // 4 limbs

    // Compute (a_lo + a_hi) and (b_lo + b_hi) with potential carry
    let (a_sum, a_carry) = add_2x2(&a_lo, &a_hi);
    let (b_sum, b_carry) = add_2x2(&b_lo, &b_hi);

    // z1_base = (a_lo + a_hi) * (b_lo + b_hi)
    let z1_base = mul_2x2(&a_sum, &b_sum);

    // Handle carries: if a_carry, add b_sum * 2^128; if b_carry, add a_sum * 2^128
    // These are at most 128-bit additions to the high part
    let mut z1_extra = [0u64; 4];
    if a_carry {
        z1_extra = add_4x4_no_overflow(&z1_extra, &[0, 0, b_sum[0], b_sum[1]]);
    }
    if b_carry {
        z1_extra = add_4x4_no_overflow(&z1_extra, &[0, 0, a_sum[0], a_sum[1]]);
    }
    if a_carry && b_carry {
        // Both carries: add 2^256, but that's in even higher bits - we can ignore for z1's position
        z1_extra[2] = z1_extra[2].wrapping_add(1);
    }

    // z1 = z1_base + z1_extra - z0 - z2
    let z1_with_extra = add_4x4_no_overflow(&z1_base, &z1_extra);
    let z1_minus_z0 = sub_4x4_with_borrow(&z1_with_extra, &z0);
    let z1 = sub_4x4_with_borrow(&z1_minus_z0, &z2);

    // Assemble result: z2 * 2^256 + z1 * 2^128 + z0
    let mut result = [0u64; 8];

    // Add z0 at position 0
    result[0] = z0[0];
    result[1] = z0[1];
    result[2] = z0[2];
    result[3] = z0[3];

    // Add z1 at position 2 (shifted by 128 bits = 2 limbs)
    let (r2, c2) = result[2].overflowing_add(z1[0]);
    result[2] = r2;
    let (r3, c3) = result[3].overflowing_add(z1[1]);
    let (r3, c3b) = r3.overflowing_add(c2 as u64);
    result[3] = r3;
    let c3_total = (c3 || c3b) as u64;
    let (r4, c4) = z1[2].overflowing_add(c3_total);
    result[4] = r4;
    let (r5, c5) = z1[3].overflowing_add(c4 as u64);
    result[5] = r5;

    // Add z2 at position 4 (shifted by 256 bits = 4 limbs)
    let (r4b, c4b) = result[4].overflowing_add(z2[0]);
    result[4] = r4b;
    let (r5b, c5b) = result[5].overflowing_add(z2[1]);
    let (r5b, c5c) = r5b.overflowing_add(c4b as u64);
    result[5] = r5b;
    let c5_total = (c5b || c5c || c5) as u64;
    let (r6, c6) = z2[2].overflowing_add(c5_total);
    result[6] = r6;
    result[7] = z2[3].wrapping_add(c6 as u64);

    result
}

/// Multiply two 2-limb (128-bit) numbers -> 4 limbs (256 bits)
/// Uses schoolbook for the base case (4 64-bit multiplications)
#[inline(always)]
fn mul_2x2(a: &[u64; 2], b: &[u64; 2]) -> [u64; 4] {
    let mut result = [0u64; 4];

    // Schoolbook multiplication for 2x2 limbs
    for i in 0..2 {
        let mut carry = 0u64;
        for j in 0..2 {
            let (lo, hi) = mul64(a[j], b[i], result[i + j], carry);
            result[i + j] = lo;
            carry = hi;
        }
        result[i + 2] = carry;
    }

    result
}

/// Multiply two u64 with accumulator and carry: a*b + c + carry -> (lo, hi)
#[inline(always)]
fn mul64(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let product = (a as u128) * (b as u128) + (c as u128) + (carry as u128);
    (product as u64, (product >> 64) as u64)
}

/// Add two 2-limb numbers, return result and carry
#[inline(always)]
fn add_2x2(a: &[u64; 2], b: &[u64; 2]) -> ([u64; 2], bool) {
    let (r0, c0) = a[0].overflowing_add(b[0]);
    let (r1, c1) = a[1].overflowing_add(b[1]);
    let (r1, c2) = r1.overflowing_add(c0 as u64);
    ([r0, r1], c1 || c2)
}

/// Add two 4-limb numbers without overflow tracking
#[inline(always)]
fn add_4x4_no_overflow(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (r0, c0) = a[0].overflowing_add(b[0]);
    let (r1, c1) = a[1].overflowing_add(b[1]);
    let (r1, c1b) = r1.overflowing_add(c0 as u64);
    let (r2, c2) = a[2].overflowing_add(b[2]);
    let (r2, c2b) = r2.overflowing_add((c1 || c1b) as u64);
    let (r3, _) = a[3].overflowing_add(b[3]);
    let (r3, _) = r3.overflowing_add((c2 || c2b) as u64);
    [r0, r1, r2, r3]
}

/// Subtract two 4-limb numbers (a - b), assumes a >= b or wraps
#[inline(always)]
fn sub_4x4_with_borrow(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (r0, borrow0) = a[0].overflowing_sub(b[0]);
    let (r1, borrow1) = a[1].overflowing_sub(b[1]);
    let (r1, borrow1b) = r1.overflowing_sub(borrow0 as u64);
    let (r2, borrow2) = a[2].overflowing_sub(b[2]);
    let (r2, borrow2b) = r2.overflowing_sub((borrow1 || borrow1b) as u64);
    let (r3, _) = a[3].overflowing_sub(b[3]);
    let (r3, _) = r3.overflowing_sub((borrow2 || borrow2b) as u64);
    [r0, r1, r2, r3]
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

    // ===== FrLimbs tests =====

    #[test]
    fn test_fr_limbs_roundtrip() {
        // Test that FrLimbs <-> Fr conversion is lossless
        let original = fr_from_u64(12345678);
        let limbs = FrLimbs::from_bytes(&original);
        let back = limbs.to_bytes();
        assert_eq!(original, back);
    }

    #[test]
    fn test_fr_limbs_add() {
        let a = FrLimbs::from_bytes(&fr_from_u64(10));
        let b = FrLimbs::from_bytes(&fr_from_u64(20));
        let c = a.add(&b);
        assert_eq!(c.to_bytes(), fr_from_u64(30));
    }

    #[test]
    fn test_fr_limbs_sub() {
        let a = FrLimbs::from_bytes(&fr_from_u64(30));
        let b = FrLimbs::from_bytes(&fr_from_u64(10));
        let c = a.sub(&b);
        assert_eq!(c.to_bytes(), fr_from_u64(20));
    }

    #[test]
    fn test_fr_limbs_mul() {
        let a = FrLimbs::from_bytes(&fr_from_u64(6));
        let b = FrLimbs::from_bytes(&fr_from_u64(7));
        let c = a.mul(&b);
        assert_eq!(c.to_bytes(), fr_from_u64(42));
    }

    #[test]
    fn test_fr_limbs_mul_consistency() {
        // Test that FrLimbs::mul matches fr_mul
        let a = fr_from_u64(123456);
        let b = fr_from_u64(789012);
        let expected = fr_mul(&a, &b);

        let a_limbs = FrLimbs::from_bytes(&a);
        let b_limbs = FrLimbs::from_bytes(&b);
        let result = a_limbs.mul(&b_limbs).to_bytes();

        assert_eq!(result, expected);
    }

    #[test]
    fn test_fr_limbs_neg() {
        let a = FrLimbs::from_bytes(&fr_from_u64(1));
        let neg_a = a.neg();
        let sum = a.add(&neg_a);
        assert!(sum.is_zero());
    }

    #[test]
    fn test_fr_limbs_inv() {
        let a = FrLimbs::from_bytes(&fr_from_u64(7));
        let a_inv = a.inv().unwrap();
        let product = a.mul(&a_inv);
        assert_eq!(product.to_bytes(), SCALAR_ONE);
    }

    #[test]
    fn test_fr_limbs_inv_consistency() {
        // Test that FrLimbs::inv matches fr_inv
        let a = fr_from_u64(12345);
        let expected = fr_inv(&a).unwrap();

        let a_limbs = FrLimbs::from_bytes(&a);
        let result = a_limbs.inv().unwrap().to_bytes();

        assert_eq!(result, expected);
    }

    #[test]
    fn test_batch_inv_limbs() {
        // Test batch inversion for FrLimbs
        let values: Vec<FrLimbs> = (1..=5)
            .map(|i| FrLimbs::from_bytes(&fr_from_u64(i)))
            .collect();

        let inverted = batch_inv_limbs(&values).unwrap();

        // Verify each inverse
        for (val, inv) in values.iter().zip(inverted.iter()) {
            let product = val.mul(inv);
            assert_eq!(product.to_bytes(), SCALAR_ONE);
        }
    }

    #[test]
    fn test_batch_inv_limbs_consistency() {
        // Test that batch_inv_limbs matches batch_inv
        let values: Vec<Fr> = (1..=5).map(|i| fr_from_u64(i)).collect();
        let expected = batch_inv(&values).unwrap();

        let limbs_values: Vec<FrLimbs> = values.iter().map(|v| FrLimbs::from_bytes(v)).collect();
        let result: Vec<Fr> = batch_inv_limbs(&limbs_values)
            .unwrap()
            .iter()
            .map(|l| l.to_bytes())
            .collect();

        assert_eq!(result, expected);
    }
}
