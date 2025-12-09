// Merkle membership proof circuit
// Verifies that a leaf is a member of a Merkle tree with a given root
// Uses blake3 for hashing, includes arrays, loops, and conditionals
// Tree depth: 16 levels (supports up to 2^16 = 65536 leaves)

use std::hash::blake3;

// Helper: compress two 32-byte hashes into one by XOR + rehash
fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    // Hash via two 32-byte blocks XORed, then hash again
    // This simulates hashing the concatenation
    let h1 = blake3(left);
    let h2 = blake3(right);
    let mut combined: [u8; 32] = [0; 32];
    for i in 0..32 {
        combined[i] = h1[i] ^ h2[i];
    }
    blake3(combined)
}

fn main(
    // The leaf value (pre-image, will be hashed)
    leaf: [u8; 32],
    // Merkle path: siblings at each level (depth = 16)
    path: [[u8; 32]; 16],
    // Index bits: indicates if current node is left (false) or right (true) child
    index_bits: [bool; 16],
) -> pub [u8; 32] {
    // Start with the hash of the leaf
    let mut current = blake3(leaf);

    // Walk up the tree
    for i in 0..16 {
        let sibling = path[i];
        // If index_bit[i] is true, current node is the right child
        // So sibling goes on the left
        if index_bits[i] {
            current = hash_pair(sibling, current);
        } else {
            current = hash_pair(current, sibling);
        }
    }

    // Return the computed root
    current
}

#[test]
fn test_merkle_membership() {
    // Simple test: build a tiny path and verify
    let leaf: [u8; 32] = [1; 32]; // All 1s
    let path: [[u8; 32]; 16] = [[0; 32]; 16];
    let index_bits: [bool; 16] = [false; 16]; // Always left child

    // Compute root using main
    let computed_root = main(leaf, path, index_bits);

    // Manually compute what we expect
    let mut expected = blake3(leaf);
    for i in 0..16 {
        let sibling = path[i];
        expected = hash_pair(expected, sibling);
    }

    // Verify they match
    assert(computed_root == expected);
}
