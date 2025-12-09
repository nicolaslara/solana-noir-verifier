# UltraHonk Verification on Solana

This experiment tests UltraHonk (Noir/Barretenberg) proof verification on Solana.

## Overview

| Metric        | Value                    |
| ------------- | ------------------------ |
| Proof Size    | 16,224 bytes             |
| VK Size       | 1,760 bytes              |
| Public Inputs | Variable (32 bytes each) |
| Min Buffer    | ~16.3 KB (for 1 PI)      |

Since UltraHonk proofs are ~16KB (way over Solana's ~1232 byte tx limit), we use **account-based storage**:

1. Create a proof buffer account
2. Upload proof in ~900-byte chunks
3. Call verify instruction

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    PROOF BUFFER ACCOUNT                          │
├─────────────────────────────────────────────────────────────────┤
│ Header (5 bytes)                                                 │
│   [0]:     status (0=empty, 1=uploading, 2=ready)               │
│   [1..3]:  proof_length (u16 LE)                                │
│   [3..5]:  public_inputs_count (u16 LE)                         │
├─────────────────────────────────────────────────────────────────┤
│ Public Inputs (num_pi × 32 bytes)                               │
│   Each public input is a 32-byte big-endian field element       │
├─────────────────────────────────────────────────────────────────┤
│ Proof Data (16,224 bytes)                                       │
│   UltraHonk ZK proof from bb 0.87                               │
└─────────────────────────────────────────────────────────────────┘
```

## Instructions

| Instruction    | Data Format                           | Description                           |
| -------------- | ------------------------------------- | ------------------------------------- |
| 0: InitBuffer  | `[0, num_pi_lo, num_pi_hi]`           | Initialize buffer for N public inputs |
| 1: UploadChunk | `[1, offset_lo, offset_hi, ...chunk]` | Upload proof data at offset           |
| 2: Verify      | `[2]`                                 | Verify proof from buffer              |

## Quick Start

### Run Tests (using solana-program-test)

```bash
cd programs/ultrahonk-verifier
cargo test -- --nocapture
```

Expected output:

```
✅ UltraHonk proof verified successfully on Solana!
✅ Tampered proof correctly rejected!
```

### Test on Surfpool

1. Start Surfpool:

```bash
surfpool start
```

2. Build and deploy:

```bash
cd programs/ultrahonk-verifier
cargo build-sbf
solana program deploy target/deploy/ultrahonk_verifier.so --url http://127.0.0.1:18899
```

3. Run verification script:

```bash
cd scripts/solana
npm install
node verify.mjs
```

## Compute Units

The verification uses Solana's BN254 syscalls for cryptographic operations:

| Operation     | Syscall                  | Approx CU |
| ------------- | ------------------------ | --------- |
| G1 Addition   | alt_bn128_addition       | ~500      |
| G1 Scalar Mul | alt_bn128_multiplication | ~12,500   |
| Pairing Check | alt_bn128_pairing        | ~113,000  |

**Total estimated: 300-400K CU** (will measure on Surfpool)

## Files

```
solana-noir-verifier/
├── programs/
│   └── ultrahonk-verifier/
│       ├── Cargo.toml
│       ├── src/lib.rs         # Solana program
│       └── tests/             # Integration tests
├── scripts/
│   └── solana/
│       ├── verify.mjs         # Surfpool verification script
│       └── package.json
└── docs/
    └── solana-testing.md      # This file
```

## Comparison with Groth16

| Metric        | UltraHonk          | Groth16     |
| ------------- | ------------------ | ----------- |
| Proof Size    | 16,224 bytes       | 256 bytes   |
| VK Size       | 1,760 bytes        | 576 bytes   |
| Trusted Setup | Universal          | Per-circuit |
| Estimated CU  | ~300-400K          | ~81K        |
| Fits in Tx    | ❌ (needs account) | ✅          |

UltraHonk is larger but:

- Universal trusted setup (no ceremony per circuit)
- Supports Noir language directly
- Better for complex circuits
