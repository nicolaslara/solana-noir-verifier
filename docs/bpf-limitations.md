# BPF Limitations for UltraHonk Verification

## Current State (December 2024)

### What Works

- ✅ **Off-chain verification**: All 54+ unit tests pass
- ✅ **Integration tests**: `solana-program-test` simulator passes
- ✅ **Program deployment**: Deploys successfully to Surfpool/Solana
- ✅ **Proof upload**: Account-based chunked upload works
- ✅ **Stack overflow fixed**: Using `#[inline(never)]` and heap allocation
- ✅ **Keccak syscall**: Using `sol_keccak256` for Fiat-Shamir (~100 CUs each)
- ✅ **Challenge generation**: Split into 6 sub-phases, all succeed!

### Challenge Generation Results (WORKING!) 🎉

After Montgomery multiplication optimization:

| Phase     | Description            | CUs (Montgomery) |
| --------- | ---------------------- | ---------------- |
| 1a        | eta/beta/gamma         | 6,209            |
| 1b        | alphas + gates         | 15,018           |
| 1c        | sumcheck 0-13          | 12,935           |
| 1d        | sumcheck 14-27 + final | 23,831           |
| 1e1       | delta part 1           | **103,952**      |
| 1e2       | delta part 2           | **133,937**      |
| **Total** | **6 transactions**     | **~296K CUs**    |

**7x improvement** from Montgomery multiplication!

### What Doesn't Work Yet

- ❌ **Phase 2 (Sumcheck verification)**: Exceeds 1.4M CUs - needs splitting into sub-phases
- ❌ **Phase 3 (MSM)**: Not yet tested
- ❌ **Phase 4 (Pairing)**: Not yet tested

### Phase 2 Analysis (December 2024)

CU logging revealed that **sumcheck rounds alone exceed 1.4M CUs**:

```
Program log: Sumcheck: before rounds
Program consumption: 1,396,940 units remaining
[exceeded during rounds - never reached relations]
```

With batch inversion optimization:

- 28 rounds × ~50K CUs/round = **~1.4M CUs just for rounds**
- Relations accumulation not even reached yet

**Optimizations Applied:**

- ✅ Batch inversion: Reduced 9 inversions → 1 per round (~3x savings)
- ✅ Montgomery multiplication: ~7x improvement on field ops
- ✅ Precomputed I_FR constants: Avoid fr_from_u64 calls

**Still needed:**

- Split sumcheck rounds into sub-phases (2a: rounds 0-9, 2b: rounds 10-19, etc.)

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

## The Real Problem: `fr_mul` is Too Expensive

While we optimized Keccak hashing with syscalls, the bottleneck is **pure Rust field multiplication**:

### The Core Issue

Each `fr_mul` on BPF costs **~20,000-50,000 CUs** because it requires:

1. 256×256 bit multiplication (schoolbook algorithm with 64-bit limbs = 16 multiplications + carries)
2. 512-bit to 256-bit Barrett reduction (more multiplications + divisions)

UltraHonk verification involves **thousands** of `fr_mul` calls across:

- Challenge generation (~200 muls) - now split into 6 TXs ✅
- Delta computation (~50 muls) - split into 2 TXs ✅
- Sumcheck verification (~500+ muls) - exceeds 1.4M CUs ❌
- MSM computation (~1000+ muls) - not yet tested

### `fr_mul` Optimizations

| Optimization            | Status         | Improvement       |
| ----------------------- | -------------- | ----------------- |
| **Karatsuba algorithm** | ✅ Implemented | -12% CUs          |
| **Montgomery form**     | ✅ Implemented | **-87% CUs (7x)** |
| **BPF assembly**        | 🔲 Pending     | Est. 2x more      |
| **Solana syscall**      | 🔲 Proposal    | Est. 10x more     |

#### Montgomery Results (December 2024) 🎉

Montgomery multiplication avoids expensive modular reduction by using shifts instead of division:

| Phase       | Original | Karatsuba | Montgomery | Total Improvement |
| ----------- | -------- | --------- | ---------- | ----------------- |
| 1e1 (delta) | 915K     | 798K      | **104K**   | **-89%**          |
| 1e2 (delta) | 1,068K   | 936K      | **134K**   | **-87%**          |
| **Total**   | ~2M      | ~1.79M    | **~296K**  | **-85%**          |

Challenge generation now uses only **~296K CUs** across 6 transactions!

### Current `fr_mul` Implementation (Montgomery)

```rust
/// Montgomery multiplication: a * b mod r
/// Formula: mont_mul(mont_mul(a, b), R2) = a * b mod r
pub fn fr_mul(a: &Fr, b: &Fr) -> Fr {
    let a_limbs = fr_to_limbs(a);
    let b_limbs = fr_to_limbs(b);

    // mont_mul(a, b) = a * b * R^-1 mod r
    // mont_mul(result, R2) = a * b mod r
    let ab_div_r = mont_mul(&a_limbs, &b_limbs);
    let result = mont_mul(&ab_div_r, &R2);

    limbs_to_fr(&result)
}
```

This uses CIOS (Coarsely Integrated Operand Scanning) Montgomery multiplication,
which avoids expensive division by using only additions and shifts.

### Remaining Field Operations

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

Store intermediate state in accounts and verify in phases.

**Problem**: Even Phase 1 (challenge generation) exceeds 1.4M CUs!

The challenge generation itself must be split:

```
Transaction 1a: eta, beta/gamma challenges       (~200K CUs)
Transaction 1b: alpha + gate challenges          (~200K CUs)
Transaction 1c: sumcheck rounds 0-13             (~400K CUs)
Transaction 1d: sumcheck rounds 14-27 + rest     (~400K CUs)
Transaction 1e: public_input_delta computation   (~300K CUs)
Transaction 2:  verify sumcheck                  (~???K CUs)
Transaction 3:  compute pairing points (MSM)     (~500K CUs)
Transaction 4:  final pairing check              (~100K CUs)
```

**Implementation challenge**: The transcript is stateful. After each challenge:

- The buffer is hashed
- The hash becomes the next "previousChallenge"
- This chains all challenges together for Fiat-Shamir security

We must serialize/deserialize transcript state between transactions.

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
4. ✅ **Karatsuba multiplication**: ~12% improvement in `fr_mul`
5. ✅ **Montgomery multiplication**: **~87% improvement** in `fr_mul` (7x faster!)
6. ✅ **Binary Extended GCD for `fr_inv`**: Much faster than Fermat's Little Theorem
7. ✅ **Batch inversion for sumcheck**: **38% savings** (1,065K → 655K CUs per 2 rounds)
8. ✅ **Sumcheck splitting**: 2 rounds per TX, ~650K CUs each, works!
9. ⏳ **MSM splitting**: Phase 3 exceeds 1.4M CUs, needs splitting

### Batch Inversion Results (A/B Tested)

| Sumcheck Round Mode | CUs per 2 rounds | Savings |
|---------------------|------------------|---------|
| Individual inversions (9 per round) | ~1,065K | baseline |
| Batch inversion (1 per round) | ~655K | **-38%** |

This validates the optimization from `docs/suggested-optimizations.md`.

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
