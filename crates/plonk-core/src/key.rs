//! Verification key parsing for bb UltraHonk (Keccak)
//!
//! ## VK Formats
//!
//! ### New format (bb v0.84.0+, 1760 bytes):
//! - [0..8]: circuit_size as 64-bit big-endian
//! - [8..16]: log2_circuit_size as 64-bit big-endian  
//! - [16..24]: num_public_inputs as 64-bit big-endian
//! - [24..32]: pub_inputs_offset as 64-bit big-endian
//! - [32..1760]: 27 G1 commitments (64 bytes each)
//!
//! ### Old format (legacy, 1888 bytes):
//! - [0..32]: log2(circuit_size) as 32-byte big-endian field
//! - [32..64]: log2(domain_size) as 32-byte big-endian field
//! - [64..96]: num_public_inputs as 32-byte big-endian field
//! - [96..1888]: 28 G1 commitments (64 bytes each)

use crate::errors::KeyError;
use crate::types::G1;

extern crate alloc;
use alloc::vec::Vec;

/// New VK size (bb v0.84.0+): 32-byte header + 27 G1 points
pub const VK_SIZE_NEW: usize = 32 + 27 * 64; // 1760 bytes

/// Old VK size (legacy): 96-byte header + 28 G1 points  
pub const VK_SIZE_OLD: usize = 96 + 28 * 64; // 1888 bytes

/// Number of commitments in new format
pub const VK_NUM_COMMITMENTS_NEW: usize = 27;

/// Number of commitments in old format
pub const VK_NUM_COMMITMENTS_OLD: usize = 28;

/// Parsed verification key for UltraHonk
///
/// Note: commitments are stored on the heap (Vec) to avoid BPF stack overflow.
/// The fixed-size array was 1,792 bytes which consumed almost half the 4KB frame limit.
#[derive(Debug, Clone)]
pub struct VerificationKey {
    /// Log2 of circuit size
    pub log2_circuit_size: u32,
    /// Log2 of domain size (FFT domain) - only in old format, computed in new
    pub log2_domain_size: u32,
    /// Number of public inputs
    pub num_public_inputs: u32,
    /// Public inputs offset (new format only)
    pub pub_inputs_offset: u32,
    /// G1 commitments to selector and permutation polynomials (heap-allocated)
    /// New format has 27, old format has 28
    pub commitments: Vec<G1>,
    /// Number of actual commitments (27 or 28)
    pub num_commitments: usize,
}

impl VerificationKey {
    /// Parse VK from bb binary format (auto-detects version)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        match bytes.len() {
            VK_SIZE_NEW => Self::from_bytes_new(bytes),
            VK_SIZE_OLD => Self::from_bytes_old(bytes),
            _ => Err(KeyError::InvalidSize {
                expected: VK_SIZE_NEW, // Report new as expected
                actual: bytes.len(),
            }),
        }
    }

    /// Parse VK from new format (bb v0.84.0+, 1760 bytes)
    fn from_bytes_new(bytes: &[u8]) -> Result<Self, KeyError> {
        // Header: 4 × 8-byte big-endian u64
        let circuit_size = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]) as u32;

        let log2_circuit_size = u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]) as u32;

        let num_public_inputs = u64::from_be_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]) as u32;

        let pub_inputs_offset = u64::from_be_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]) as u32;

        // Validate
        if log2_circuit_size > 30 {
            return Err(KeyError::InvalidCircuitSize);
        }

        // Verify circuit_size matches log2
        if circuit_size != (1 << log2_circuit_size) {
            return Err(KeyError::InvalidCircuitSize);
        }

        // Parse G1 commitments (27 in new format) - heap allocated
        let mut commitments = Vec::with_capacity(VK_NUM_COMMITMENTS_NEW);
        let mut offset = 32;
        for _ in 0..VK_NUM_COMMITMENTS_NEW {
            let mut commitment = [0u8; 64];
            commitment.copy_from_slice(&bytes[offset..offset + 64]);
            commitments.push(commitment);
            offset += 64;
        }

        // Compute log2_domain_size (not in new format, estimate from circuit size)
        // In new format, domain_size is typically the next power of 2 >= circuit_size
        let log2_domain_size = log2_circuit_size;

        Ok(VerificationKey {
            log2_circuit_size,
            log2_domain_size,
            num_public_inputs,
            pub_inputs_offset,
            commitments,
            num_commitments: VK_NUM_COMMITMENTS_NEW,
        })
    }

    /// Parse VK from old format (legacy, 1888 bytes)
    fn from_bytes_old(bytes: &[u8]) -> Result<Self, KeyError> {
        // Parse header fields (each is 32 bytes, value in last 4 bytes)
        let log2_circuit_size = read_u32_from_field(&bytes[0..32])?;
        let log2_domain_size = read_u32_from_field(&bytes[32..64])?;
        let num_public_inputs = read_u32_from_field(&bytes[64..96])?;

        // Validate
        if log2_circuit_size > 30 {
            return Err(KeyError::InvalidCircuitSize);
        }
        if log2_domain_size > 30 {
            return Err(KeyError::InvalidDomainSize);
        }

        // Parse G1 commitments (28 in old format) - heap allocated
        let mut commitments = Vec::with_capacity(VK_NUM_COMMITMENTS_OLD);
        let mut offset = 96;
        for _ in 0..VK_NUM_COMMITMENTS_OLD {
            let mut commitment = [0u8; 64];
            commitment.copy_from_slice(&bytes[offset..offset + 64]);
            commitments.push(commitment);
            offset += 64;
        }

        Ok(VerificationKey {
            log2_circuit_size,
            log2_domain_size,
            num_public_inputs,
            pub_inputs_offset: 0, // Not in old format
            commitments,
            num_commitments: VK_NUM_COMMITMENTS_OLD,
        })
    }

    /// Get circuit size (2^log2_circuit_size)
    pub fn circuit_size(&self) -> u32 {
        1 << self.log2_circuit_size
    }

    /// Get domain size (2^log2_domain_size)
    pub fn domain_size(&self) -> u32 {
        1 << self.log2_domain_size
    }
}

/// Read a u32 from a 32-byte big-endian field (value in last 4 bytes)
fn read_u32_from_field(bytes: &[u8]) -> Result<u32, KeyError> {
    if bytes.len() != 32 {
        return Err(KeyError::InvalidFieldSize);
    }

    // Check that high bytes are zero
    for &b in &bytes[..28] {
        if b != 0 {
            return Err(KeyError::FieldOverflow);
        }
    }

    Ok(u32::from_be_bytes([
        bytes[28], bytes[29], bytes[30], bytes[31],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u32_from_field() {
        let mut field = [0u8; 32];
        field[31] = 1;
        assert_eq!(read_u32_from_field(&field).unwrap(), 1);

        field[31] = 0;
        field[30] = 1;
        assert_eq!(read_u32_from_field(&field).unwrap(), 256);
    }

    #[test]
    fn test_vk_from_bytes_wrong_size() {
        let bytes = [0u8; 100];
        assert!(matches!(
            VerificationKey::from_bytes(&bytes),
            Err(KeyError::InvalidSize { .. })
        ));
    }

    #[test]
    fn test_vk_from_bytes_valid_old_format() {
        // Test OLD format (1888 bytes)
        let mut bytes = [0u8; VK_SIZE_OLD];
        // log2_circuit_size = 6 (at byte 31 in 32-byte field)
        bytes[31] = 6;
        // log2_domain_size = 17 (at byte 63)
        bytes[63] = 17;
        // num_public_inputs = 1 (at byte 95)
        bytes[95] = 1;

        let vk = VerificationKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk.log2_circuit_size, 6);
        assert_eq!(vk.log2_domain_size, 17);
        assert_eq!(vk.num_public_inputs, 1);
        assert_eq!(vk.circuit_size(), 64);
        assert_eq!(vk.domain_size(), 131072);
        assert_eq!(vk.num_commitments, VK_NUM_COMMITMENTS_OLD);
    }

    #[test]
    fn test_vk_from_bytes_valid_new_format() {
        // Test NEW format (1760 bytes)
        let mut bytes = [0u8; VK_SIZE_NEW];
        // Header: 4 × 8-byte big-endian u64
        // circuit_size = 64 (at bytes 0-7)
        bytes[7] = 64;
        // log2_circuit_size = 6 (at bytes 8-15)
        bytes[15] = 6;
        // num_public_inputs = 1 (at bytes 16-23)
        bytes[23] = 1;
        // pub_inputs_offset = 1 (at bytes 24-31)
        bytes[31] = 1;

        let vk = VerificationKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk.log2_circuit_size, 6);
        assert_eq!(vk.num_public_inputs, 1);
        assert_eq!(vk.pub_inputs_offset, 1);
        assert_eq!(vk.circuit_size(), 64);
        assert_eq!(vk.num_commitments, VK_NUM_COMMITMENTS_NEW);
    }
}
