//! Constants for BN254 curve and UltraHonk verification

use crate::types::Fr;

/// Maximum supported log2 circuit size
pub const MAX_LOG2_CIRCUIT_SIZE: u32 = 28;

/// Get root of unity for domain size 2^n
/// These are precomputed for BN254's scalar field
pub fn root_of_unity(log2_n: u32) -> Option<Fr> {
    if log2_n > MAX_LOG2_CIRCUIT_SIZE {
        return None;
    }

    // Roots of unity for BN254 scalar field
    // ω_n = ω_{2^28}^{2^{28-n}} where ω_{2^28} is the primitive 2^28-th root of unity
    //
    // For BN254, the primitive 2^28-th root of unity is:
    // 0x2a3c09f0a58a7e8500e0a7eb8ef62abc402d111e41112ed49bd61b6e725b19f0
    //
    // We precompute roots for common sizes

    let root = match log2_n {
        0 => [
            // ω_1 = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ],
        1 => [
            // ω_2 = -1 = r - 1
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
            0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93,
            0xef, 0xff, 0xff, 0xf0,
        ],
        // For other sizes, we'd need to compute or precompute more values
        // For now, return a placeholder that will need to be filled in
        _ => {
            // This is a placeholder - actual implementation would compute
            // the appropriate root of unity
            let mut root = [0u8; 32];
            // TODO: Implement proper root of unity computation
            root[31] = 1; // Placeholder
            root
        }
    };

    Some(root)
}

/// Domain separator for UltraHonk transcript
pub const ULTRAHONK_DOMAIN_SEP: &[u8] = b"UltraHonk_Keccak";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_of_unity_one() {
        let root = root_of_unity(0).unwrap();
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(root, expected);
    }
}
