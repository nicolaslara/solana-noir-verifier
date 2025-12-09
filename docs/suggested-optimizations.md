# Optimization Guide - Solana Noir Verifier

This document tracks field arithmetic and verification optimizations for the UltraHonk verifier on Solana.

## Implementation Status

| Optimization                        | Status  | Actual Result                                    |
| ----------------------------------- | ------- | ------------------------------------------------ |
| **1. Batch inversion for sumcheck** | ✅ DONE | **38% savings** (1,065K → 655K CUs per 2 rounds) |
| 2. Precompute I_FR constants        | ✅ DONE | Avoids fr_from_u64 calls                         |
| 3. Montgomery multiplication        | ✅ DONE | **7x faster** field muls                         |
| 4. Binary Extended GCD              | ✅ DONE | Much faster than Fermat                          |
| 5. Shplemini rho^k precompute       | ✅ DONE | Avoids O(k) exponentiation per shifted wire      |
| 6. Shplemini batch inversion (3b2)  | ✅ DONE | Batched gemini + libra denominators              |
| 7. Batch inv fold denoms (3b1)      | ✅ DONE | **60% savings** (1,337K → 534K CUs)              |
| 8. **FrLimbs in sumcheck**          | ✅ DONE | **17.5% savings** per round (1.3M → 1.07M CUs)   |
| 9. **FrLimbs in shplemini**         | ✅ DONE | **16% savings** (2.95M → 2.48M CUs)              |
| 10. **Zero-copy Proof**             | ✅ DONE | **54% CU savings** in Phase 1 (619K → 287K)      |
| 11. Relation batching               | ⏳ TODO | Factor common challenge combos (~50-80k CUs)     |
| 12. Challenge fr_reduce tuning      | ⏳ TODO | ~40-75k CUs via Montgomery reduction             |
| 13. BPF assembly for mont_mul       | 💡 IDEA | Up to ~2x more on fr_mul (high effort)           |
| 14. **Audit other copies**          | 🔍 TODO | May have similar wins elsewhere                  |

---

## Current Performance (Dec 2024)

**Post-Montgomery + FrLimbs world:**

| Metric                          | Value         |
| ------------------------------- | ------------- |
| `fr_mul` (Montgomery+Karatsuba) | ~500-700 CUs  |
| `fr_add/sub`                    | ~100-200 CUs  |
| `fr_inv` (binary GCD)           | ~3-4k CUs     |
| Challenge generation (1 tx)     | ~287k CUs     |
| Sumcheck (6 rounds/tx)          | ~1.35M CUs    |
| Full verification (log_n=12)    | **6.64M CUs** |
| Transaction count               | **9 txs**     |

---

## 0. Baseline: What's Actually Optimized

From the codebase (December 2024):

### Already Optimized ✅

- **Challenge generation**: ~296k CUs total over 6 txs with Montgomery muls
- **Sumcheck rounds**: Batch inversion + FrLimbs splitting (2 rounds/tx ≈ 655k CUs)
- **`fr_mul`**: Montgomery + Karatsuba in `field.rs`
- **`fr_inv`**: Binary extended GCD (much faster than Fermat)
- **Batch inversion**: Available in `field.rs` and used in sumcheck + shplemini
- **FrLimbs representation**: Implemented in both `sumcheck.rs` and `shplemini.rs`
- **End-to-end UltraHonk verification**: Working with multi-TX phases

### Code Locations

- Field core: `crates/plonk-core/src/field.rs` – all scalar ops, `FrLimbs` type
- Sumcheck: `crates/plonk-core/src/sumcheck.rs` – FrLimbs-native barycentric
- Shplemini + MSM: `crates/plonk-core/src/shplemini.rs` – FrLimbs phases 3a/3b
- BN254 syscalls: `crates/plonk-core/src/ops.rs`

---

## 1. ✅ DONE: FrLimbs Representation (Systemic Win)

### What We Implemented

Introduced `FrLimbs` in `field.rs` – a `[u64; 4]` type in Montgomery form:

```rust
#[derive(Copy, Clone)]
pub struct FrLimbs(pub [u64; 4]); // little-endian, in Montgomery form

impl FrLimbs {
    #[inline(always)]
    pub fn add(&self, other: &FrLimbs) -> FrLimbs { /* add_mod + conditional sub */ }
    #[inline(always)]
    pub fn mul(&self, other: &FrLimbs) -> FrLimbs { /* single mont_mul */ }
    #[inline(always)]
    pub fn sub(&self, other: &FrLimbs) -> FrLimbs { /* sub_mod */ }
    pub fn square(&self) -> FrLimbs { /* optimized squaring */ }
    // etc…
}
```

### Where It's Used

1. **Sumcheck** (`sumcheck.rs`):

   - `next_target_l()` – fully FrLimbs-native barycentric interpolation
   - Precomputed `I_FR_LIMBS`, `BARY_8_LIMBS`, `BARY_9_LIMBS` constants
   - `update_pow_l()` – FrLimbs power updates

2. **Shplemini** (`shplemini.rs`):
   - `shplemini_phase3a()` – weights + scalar accumulation in FrLimbs
   - `shplemini_phase3b1()` – folding rounds with batch inversion
   - `shplemini_phase3b2()` – gemini loop + libra in FrLimbs
   - All `r_pows`, denominators, and accumulators use FrLimbs

### Actual Results

| Component           | Before FrLimbs | After FrLimbs | Savings  |
| ------------------- | -------------- | ------------- | -------- |
| Sumcheck (Phase 2)  | ~5.0M CUs      | ~3.8M CUs     | **24%**  |
| Shplemini (Phase 3) | ~2.95M CUs     | ~2.48M CUs    | **16%**  |
| **Total**           | ~8.7M CUs      | ~6.65M CUs    | **~20%** |

---

## 2. ✅ DONE: Shplemini rho^k Precomputation

### What Was Fixed

Previously, for each shifted commitment we computed `ρ^k` with O(k) multiplications:

```rust
// OLD CODE - O(k) per shifted wire
        for _ in 0..shifted_rho_idx {
            shifted_rho_pow = fr_mul(&shifted_rho_pow, &challenges.rho);
}
```

Now we precompute all rho powers once:

```rust
// NEW CODE - O(1) lookup
const MAX_RHO_POWERS: usize = 45;
let mut rho_pows = [SCALAR_ZERO; MAX_RHO_POWERS];
rho_pows[0] = SCALAR_ONE;
rho_pows[1] = challenges.rho;
for i in 2..MAX_RHO_POWERS {
    rho_pows[i] = fr_mul(&rho_pows[i - 1], &challenges.rho);
}
// Later: rho_pows[shifted_rho_idx] directly
```

### Savings

- Avoided ~195 extra multiplications per proof (37+38+39+40+41)
- Estimated **~135-150k CUs saved** in MSM phase

---

## 3. ✅ DONE: Batch Inversions in Shplemini

### Phase 3b1: Fold Denominators

All fold denominators `den[j] = r^(2^(j-1)) * (1 - u[j-1]) + u[j-1]` are batched:

```rust
let mut fold_denoms_l: Vec<FrLimbs> = Vec::with_capacity(log_n);
for j in 1..=log_n {
    let den = r_pows_l[j-1].mul(&one_minus_u).add(&u);
    fold_denoms_l.push(den);
}
let fold_den_invs_l = batch_inv_limbs(&fold_denoms_l)?;
```

**Result**: ~60% savings (1,337K → 534K CUs)

### Phase 3b2: Gemini + Libra Denominators

All `z ± r^j` and libra denominators batched together:

```rust
let mut all_denoms_l: Vec<FrLimbs> = Vec::new();
// Gemini: z - r^j and z + r^j for j = 1..log_n-1
for i in 0..num_non_dummy {
    all_denoms_l.push(shplonk_z_l.sub(&r_pows_l[i+1]));
    all_denoms_l.push(shplonk_z_l.add(&r_pows_l[i+1]));
}
// Libra: z - r, z - g*r
if proof.is_zk {
    all_denoms_l.push(shplonk_z_l.sub(&gemini_r_l));
    all_denoms_l.push(shplonk_z_l.sub(&subgroup_generator_l.mul(&gemini_r_l)));
}
let all_invs_l = batch_inv_limbs(&all_denoms_l)?;
```

**Result**: ~40 individual inversions → 1 batch inversion (~90-140k CUs saved)

---

## 4. 🔍 TODO: Audit Unnecessary Copies

### Discovery

The zero-copy `Proof` change revealed that **data copying costs significant CUs**:

| Metric      | Before (Vec<u8>) | After (&[u8]) | Savings  |
| ----------- | ---------------- | ------------- | -------- |
| Phase 1 CUs | 619K             | 287K          | **54%**  |
| Heap usage  | ~16KB            | ~0            | **100%** |

This is NOT just about heap limit - the copy operation itself was burning ~330K CUs!

### Investigation Points

Audit codebase for similar copy patterns that could be eliminated:

1. **VK parsing** (`key.rs`): Does `VerificationKey::from_bytes()` copy unnecessarily?

   - Current: Returns owned `VerificationKey` with `Vec<G1>` commitments
   - Potential: Zero-copy with `&'a [u8]` reference to embedded bytes

2. **Public inputs** (`lib.rs`): `Vec<Fr>` allocation in phase functions

   - Current: `public_inputs.push(arr)` copies each 32-byte Fr
   - Potential: Iterate over slices directly without collecting

3. **State reconstruction** (`phased.rs`): Challenge reconstruction patterns

   - Check if we're copying when we could borrow

4. **Relations evaluation** (`relations.rs`): Wire value access patterns
   - Are we copying Fr values when iterating evaluations?

### How to Audit

```bash
# Find Vec allocations in hot paths
grep -n "Vec<Fr>\|Vec<G1>\|to_vec()\|.clone()" crates/plonk-core/src/*.rs
```

### Expected Impact

If similar patterns exist in Phase 2/3, could see **100-500k CU savings**.

---

## 5. ⏳ TODO: Relations Accumulation Factoring

### Current State

`relations.rs` accumulates 26 UltraHonk subrelations. Many share common patterns:

- `β * something + γ`
- `η^i * something`
- Same evaluations `w_i(z)`, `w_i(-z)` used multiple times

### Optimization

Introduce a "relations context" struct that precomputes challenge combos once:

```rust
struct RelationsContext {
    beta_times_separator: Fr,
    gamma_plus_beta_eta: Fr,
    eta_pows: [Fr; MAX_ETA_POWERS],
    // etc.
}
```

### Expected Improvement

Relations are ~300-400k CUs total. Factoring could save **~50-80k CUs** (15-20%).

---

## 6. ⏳ TODO: Challenge `fr_reduce` Tuning

### Current State

`fr_reduce` in `field.rs` uses loop-based subtraction:

```rust
pub fn fr_reduce(a: &Fr) -> Fr {
    let mut limbs = fr_to_limbs(a);
    loop {
        let (result, borrow) = sbb_limbs(&limbs, &R);
        if borrow != 0 { break; }
        limbs = result;
    }
    limbs_to_fr(&limbs)
}
```

Called ~75 times per proof for challenge generation.

### Optimization Options

1. **Montgomery reduction**: Multiply by R² and do single mont_mul
2. **Constant-time conditional subtract**: Based on high limb value

### Expected Improvement

~40-75k CUs saved (75 calls × ~500-1000 CU reduction each)

---

## 7. 💡 IDEA: BPF Assembly for `mont_mul`

### Current State

Montgomery multiplication is ~500-700 CUs post-optimization.

### Potential

Hand-tuned BPF/LLVM-intrinsic version could potentially get to 350-400 CUs:

- Avoid redundant loads/stores
- Use `u128` multiplications efficiently
- Inline the reduction tightly

### Impact

At ~1,400 muls/proof: ~1,400 × 300 = **~420k CUs saved**

**Complexity**: High. Only pursue if still over budget after other optimizations.

---

## 8. Phase Packing Opportunities

### Current Transaction Structure (log_n=12)

| Phase            | CUs       | TXs   |
| ---------------- | --------- | ----- |
| 1. Challenges    | ~287k     | **1** |
| 2. Sumcheck      | ~3.82M    | 3     |
| 3. MSM/Shplemini | ~2.48M    | 4     |
| 4. Pairing       | ~55k      | 1     |
| **Total**        | **6.64M** | **9** |

### With Further Optimizations

If we land copy elimination audit + relations factoring (~200-500k CUs saved):

- Phase 3 might consolidate further (3 TXs?)
- Could reduce total from 9 to ~7-8 transactions

---

## 9. Minor Cleanups (Free Wins)

These are in the tens of k CUs range but easy to implement:

### 8.1 Ensure All Constants Are Truly Const

✅ Done for sumcheck (`I_FR_LIMBS`, `BARY_*_LIMBS`)
⏳ Check relations for similar opportunities

### 8.2 Avoid Recomputing Small Differences

Store `chi_minus[i]` arrays once and reuse (already done in batch inversion refactor)

### 8.3 Keep Tiny Wrappers Inline

`#[inline(always)]` on `fr_square`, `fr_neg`, etc. for Solana builds

---

## Priorities

If you need more CU savings, tackle in this order:

1. **Audit unnecessary copies** → potentially **100-500k CUs** (medium effort, high ROI!)
2. **Relations accumulation factoring** → ~50-80k CUs (medium effort)
3. **Challenge `fr_reduce` tuning** → ~40-75k CUs (low effort)
4. **BPF assembly for `mont_mul`** → up to ~400k CUs (high effort, last resort)

---

## CU Usage by Circuit Size

| Circuit              | log_n | PIs | Total CUs | TXs   |
| -------------------- | ----- | --- | --------- | ----- |
| simple_square        | 12    | 1   | **6.64M** | **9** |
| iterated_square_100  | 12    | 1   | ~6.64M    | 9     |
| fib_chain_100        | 12    | 1   | ~6.64M    | 9     |
| iterated_square_1000 | 13    | 1   | ~7.0M     | 9     |
| iterated_square_10k  | 14    | 1   | ~7.5M     | 9     |
| hash_batch           | 17    | 32  | ~8.9M     | 10    |
| merkle_membership    | 18    | 32  | ~9.3M     | 10    |

**Key observations:**

- Same proof size (16,224 bytes) regardless of circuit due to `CONST_PROOF_SIZE_LOG_N=28` padding
- log_n=12 circuits have ~identical CUs (most sumcheck rounds are padding)
- More public inputs = more CUs for delta computation (~0.5M per 31 extra PIs)
- FrLimbs optimization: **~20% total CU reduction** across all circuits (~1.7M CUs saved)

---

## Historical Notes

### Original Bottlenecks (Now Resolved)

1. **Naive inversions in sumcheck**: Each barycentric round did 9 individual `fr_inv` calls
   → Fixed with batch inversion (38% savings)

2. **O(k) rho exponentiation**: Shifted wire scalars recomputed `ρ^k` from scratch
   → Fixed with precomputed rho table (~150k CUs saved)

3. **Byte conversion overhead**: Every field op converted `[u8;32]` ↔ `[u64;4]`
   → Fixed with FrLimbs internal representation (~20% total savings)

4. **Individual gemini inversions**: 40+ separate inversions in shplemini
   → Fixed with batched denominators (~90-140k CUs saved)

5. **Proof data copying**: `Proof::from_bytes()` copied 16KB to heap
   → Fixed with zero-copy `&'a [u8]` reference (**54% CU savings in Phase 1**, 17→9 TXs)

### What Made This Possible

- Montgomery multiplication already in place (7x faster than naive)
- Binary extended GCD for inversions (much faster than Fermat)
- Solana BN254 syscalls for pairing (~100 CUs for Keccak, cheap EC ops)
