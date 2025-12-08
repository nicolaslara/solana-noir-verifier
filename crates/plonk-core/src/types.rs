//! Core types for UltraHonk verification
//!
//! Uses raw byte arrays matching Solana BN254 syscall format.

/// A 32-byte scalar field element (Fr for BN254).
/// Stored in big-endian format.
pub type Scalar = [u8; 32];

/// Alias for Scalar (field element)
pub type Fr = Scalar;

/// A 64-byte G1 point (uncompressed, big-endian x || y).
pub type G1 = [u8; 64];

/// A 128-byte G2 point (uncompressed, big-endian).
pub type G2 = [u8; 128];

/// Scalar representing zero
pub const SCALAR_ZERO: Scalar = [0u8; 32];

/// Scalar representing one
pub const SCALAR_ONE: Scalar = {
    let mut s = [0u8; 32];
    s[31] = 1;
    s
};

/// G1 identity point (point at infinity)
/// For BN254, the identity is represented as (0, 0)
pub const G1_IDENTITY: G1 = [0u8; 64];

/// BN254 G1 generator point
/// x = 1, y = 2
pub const G1_GENERATOR: G1 = {
    let mut g = [0u8; 64];
    g[31] = 1; // x = 1
    g[63] = 2; // y = 2
    g
};

/// BN254 scalar field modulus (r)
/// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
pub const FR_MODULUS: Scalar = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// BN254 base field modulus (q)
/// q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
pub const FQ_MODULUS: Scalar = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_sizes() {
        assert_eq!(core::mem::size_of::<Scalar>(), 32);
        assert_eq!(core::mem::size_of::<G1>(), 64);
        assert_eq!(core::mem::size_of::<G2>(), 128);
    }

    #[test]
    fn test_scalar_one() {
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(SCALAR_ONE, expected);
    }
}
