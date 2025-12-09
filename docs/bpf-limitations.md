# BPF Limitations for UltraHonk Verification

## Current State (December 2024)

### What Works

- ✅ **Off-chain verification**: All 54+ unit tests pass
- ✅ **Integration tests**: `solana-program-test` simulator passes
- ✅ **Program deployment**: Deploys successfully to Surfpool/Solana
- ✅ **Proof upload**: Account-based chunked upload works
- ✅ **Stack overflow fixed**: Using `#[inline(never)]` and heap allocation
- ✅ **Keccak syscall**: Using `sol_keccak256` for Fiat-Shamir (~100 CUs each)

### What Doesn't Work

- ❌ **On-chain verification**: Exceeds 1.4M compute unit limit

## Compute Unit Analysis

| Metric        | Value                   |
| ------------- | ----------------------- |
| CUs requested | 1,400,000               |
| CUs consumed  | 1,399,850+              |
| Failure point | `generate_challenges()` |
| Status        | **Exceeded limit**      |

### Breakdown of Where CUs Go

```
Program setup:           ~1,000 CUs
VK parsing:              ~1,200 CUs
Proof parsing:           ~500 CUs
Challenge generation:    ~1,396,000+ CUs ← BOTTLENECK
  - Keccak hashes (75+): ~7,500 CUs (syscall-optimized)
  - Field operations:    ~1,388,000+ CUs ← ACTUAL PROBLEM
```

**UltraHonk verification needs >1.4M CUs (Solana's per-transaction maximum).**

## The Real Problem: Field Arithmetic

While we optimized Keccak hashing with syscalls, the bottleneck is **pure Rust field operations**:

### Challenge Generation Operations

| Operation           | Count | Notes                                  |
| ------------------- | ----- | -------------------------------------- |
| `challenge_split()` | ~75   | Each involves Keccak + field reduction |
| `fr_mul`            | ~200+ | Modular multiplication (expensive)     |
| `fr_add/fr_sub`     | ~300+ | Modular addition/subtraction           |
| `fr_div`            | ~20+  | Modular division (very expensive)      |

### Why Field Operations Are Expensive

Unlike BN254 curve operations (which use syscalls), **field arithmetic is pure Rust**:

```rust
// Each fr_mul does 512-bit multiplication + Barrett reduction
// ~500-1000 CUs per multiplication
pub fn fr_mul(a: &Fr, b: &Fr) -> Fr {
    let a_limbs = fr_to_limbs(a);
    let b_limbs = fr_to_limbs(b);
    let result = mul_mod_wide(&a_limbs, &b_limbs);
    limbs_to_fr(&result)
}

// Each fr_div does extended Euclidean algorithm
// ~2000-5000 CUs per division
pub fn fr_div(a: &Fr, b: &Fr) -> Option<Fr> {
    let b_inv = fr_inv(b)?;  // This is very expensive!
    Some(fr_mul(a, &b_inv))
}
```

### Comparison: Why Groth16 Works

| Aspect                    | Groth16                      | UltraHonk                     |
| ------------------------- | ---------------------------- | ----------------------------- |
| Proof size                | 192 bytes                    | 16,224 bytes                  |
| Field ops in verification | ~20                          | ~500+                         |
| Curve ops in verification | 4 pairings                   | 70+ scalar muls + 1 pairing   |
| Total CUs                 | ~350,000                     | >1,400,000                    |
| Library                   | `groth16-solana` (optimized) | `plonk-core` (reference impl) |

Groth16 verification is dominated by pairing checks (syscalls), while UltraHonk has extensive field arithmetic in sumcheck.

## Potential Solutions

### 1. Split Verification Across Multiple Transactions (Recommended)

Store intermediate state in accounts and verify in phases:

```
Transaction 1: Generate challenges → save to account
Transaction 2: Verify sumcheck → save result to account
Transaction 3: Compute pairing points → save to account
Transaction 4: Final pairing check → return result
```

This is how Light Protocol handles complex ZK verification on Solana.

### 2. Precompute More Off-Chain

Move expensive computations to the prover:

- Pre-compute all challenges
- Pre-compute `public_input_delta`
- Include intermediate values in proof

Requires protocol modifications.

### 3. Wait for Solana Improvements

- Higher CU limits per transaction
- Field arithmetic syscalls (like BN254 curve ops)
- Better BPF compiler optimizations

### 4. Use a Different Proof System

For Solana, consider:

- **Groth16**: ~350K CUs, already works
- **STARK**: Potentially splittable, hash-based
- **Plonky2**: Designed for recursive verification

## Technical Details

### BPF Constraints

| Resource         | Limit           |
| ---------------- | --------------- |
| Stack per frame  | 4 KB            |
| Total heap       | 32 KB           |
| Compute Units    | 1,400,000 (max) |
| Transaction size | ~1,232 bytes    |

### What We Tried

1. ✅ **Keccak syscalls**: `solana-keccak-hasher` (~100 CUs vs ~2000 for software)
2. ✅ **Heap allocation**: `Box<[[u8; 64]; 27]>` for VK commitments
3. ✅ **Stack frame breaking**: `#[inline(never)]` on all major functions
4. ❌ **Field operation optimization**: Still software, still expensive

## Integration Test vs Real BPF

| Environment           | Behavior                                |
| --------------------- | --------------------------------------- |
| `solana-program-test` | Uses native Rust, no CU limits enforced |
| Real BPF/Surfpool     | Strict 1.4M CU cap per transaction      |

The `solana-program-test` framework simulates but doesn't enforce real BPF constraints.

## References

- [Solana Compute Budget](https://solana.com/docs/core/fees#compute-budget)
- [Light Protocol ZK on Solana](https://github.com/Lightprotocol/light-protocol)
- [BN254 Syscalls](https://docs.solana.com/developing/runtime-facilities/programs#bn254)
- [groth16-solana](https://github.com/Lightprotocol/groth16-solana)
