//! Verification key parsing for bb 3.0 UltraHonk (Keccak)
//!
//! VK format (1888 bytes):
//! - [0..32]: log2(circuit_size) as 32-byte big-endian
//! - [32..64]: log2(domain_size) as 32-byte big-endian  
//! - [64..96]: num_public_inputs as 32-byte big-endian
//! - [96..1888]: 28 G1 commitments (64 bytes each)

use crate::errors::KeyError;
use crate::types::G1;
use crate::{VK_NUM_COMMITMENTS, VK_SIZE};

/// Parsed verification key for UltraHonk
#[derive(Debug, Clone)]
pub struct VerificationKey {
    /// Log2 of circuit size
    pub log2_circuit_size: u32,
    /// Log2 of domain size (FFT domain)
    pub log2_domain_size: u32,
    /// Number of public inputs
    pub num_public_inputs: u32,
    /// G1 commitments to selector and permutation polynomials
    pub commitments: [G1; VK_NUM_COMMITMENTS],
}

impl VerificationKey {
    /// Parse VK from bb 3.0 binary format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != VK_SIZE {
            return Err(KeyError::InvalidSize {
                expected: VK_SIZE,
                actual: bytes.len(),
            });
        }

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

        // Parse G1 commitments
        let mut commitments = [[0u8; 64]; VK_NUM_COMMITMENTS];
        let mut offset = 96;
        for commitment in commitments.iter_mut() {
            commitment.copy_from_slice(&bytes[offset..offset + 64]);
            offset += 64;
        }

        Ok(VerificationKey {
            log2_circuit_size,
            log2_domain_size,
            num_public_inputs,
            commitments,
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
    fn test_vk_from_bytes_valid() {
        let mut bytes = [0u8; VK_SIZE];
        // log2_circuit_size = 6
        bytes[31] = 6;
        // log2_domain_size = 17
        bytes[63] = 17;
        // num_public_inputs = 1
        bytes[95] = 1;

        let vk = VerificationKey::from_bytes(&bytes).unwrap();
        assert_eq!(vk.log2_circuit_size, 6);
        assert_eq!(vk.log2_domain_size, 17);
        assert_eq!(vk.num_public_inputs, 1);
        assert_eq!(vk.circuit_size(), 64);
        assert_eq!(vk.domain_size(), 131072);
    }
}
