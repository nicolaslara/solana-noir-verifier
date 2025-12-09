// Hash batch circuit: process multiple blocks with blake3
// This creates a hash-heavy constraint set to test different gadgets

use std::hash::blake3;

fn main(messages: [u8; 1024], expected_hash: pub [u8; 32]) {
    // Chunk the 1024 bytes into 32-byte blocks and hash them iteratively
    let mut acc: [u8; 32] = [0; 32];

    for i in 0..32 {
        let mut block: [u8; 32] = [0; 32];
        for j in 0..32 {
            block[j] = messages[i * 32 + j];
        }
        // Hash the block
        let h = blake3(block);
        // XOR fold into accumulator to force use of all hashes
        for k in 0..32 {
            acc[k] = acc[k] ^ h[k];
        }
    }

    assert(acc == expected_hash);
}

#[test]
fn test_main() {
    // Create a simple test message
    let mut messages: [u8; 1024] = [0; 1024];
    for i in 0..1024 {
        messages[i] = (i % 256) as u8;
    }

    // Compute expected hash (same logic as main)
    let mut acc: [u8; 32] = [0; 32];
    for i in 0..32 {
        let mut block: [u8; 32] = [0; 32];
        for j in 0..32 {
            block[j] = messages[i * 32 + j];
        }
        let h = blake3(block);
        for k in 0..32 {
            acc[k] = acc[k] ^ h[k];
        }
    }

    main(messages, acc);
}
