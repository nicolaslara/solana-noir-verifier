# Optimization Guide - Solana Noir Verifier

This document tracks field arithmetic and verification optimizations for the UltraHonk verifier on Solana.

## Implementation Status

| Optimization                        | Status  | Actual Result                                      |
| ----------------------------------- | ------- | -------------------------------------------------- |
| **1. Batch inversion for sumcheck** | ✅ DONE | **38% savings** (1,065K → 655K CUs per 2 rounds)   |
| 2. Precompute I_FR constants        | ✅ DONE | Avoids fr_from_u64 calls                           |
| 3. Montgomery multiplication        | ✅ DONE | **7x faster** field muls                           |
| 4. Binary Extended GCD              | ✅ DONE | Much faster than Fermat                            |
| 5. Shplemini rho^k precompute       | ✅ DONE | Avoids O(k) exponentiation per shifted wire        |
| 6. Shplemini batch inversion (3b2)  | ✅ DONE | Batched gemini + libra denominators                |
| 7. Batch inv fold denoms (3b1)      | ✅ DONE | **60% savings** (1,337K → 534K CUs)                |
| 8. **FrLimbs in sumcheck**          | ✅ DONE | **17.5% savings** per round (1.3M → 1.07M CUs)     |
| 9. **FrLimbs in shplemini**         | ✅ DONE | **16% savings** (2.95M → 2.48M CUs)                |
| 10. **Zero-copy Proof**             | ✅ DONE | **54% CU savings** in Phase 1 (619K → 287K)        |
| 11. **FrLimbs in relations**        | ✅ DONE | **32% savings** in relations (1.15M → 778K CUs)    |
| 12. **FrLimbs direct storage**      | ✅ DONE | **262K CUs saved** (no Montgomery conv at edges)   |
| 13. SmallFrArray (stack arrays)     | ✅ DONE | **Minimal** (<100 CUs - allocation not bottleneck) |
| 14. Degree-specialized sumcheck     | ⏳ TODO | **~200-400k CUs** (hardcoded degree-1/2/3)         |
| 15. Relations monomial factoring    | ⏳ TODO | ~60-100k CUs (fold α/β/γ into coefficients)        |
| 16. Challenge fr_reduce tuning      | ⏳ TODO | ~40-75k CUs via Montgomery reduction               |
| 17. BPF assembly for mont_mul       | 💡 IDEA | Up to ~400k CUs (high effort, last resort)         |

---

## Current Performance (Dec 2024)

**Post-FrLimbs everywhere (including relations + direct storage):**

| Metric                           | Value          |
| -------------------------------- | -------------- |
| `fr_mul` (Montgomery, **actual**)| **~2,400 CUs** |
| `fr_add/sub`                     | ~100-200 CUs   |
| `fr_inv` (binary GCD)            | ~25K CUs       |

> **Note:** Montgomery multiplication is ~4x more expensive on BPF than originally estimated due to u128 emulation overhead.
| Challenge generation (1 TX)      | ~319k CUs     |
| Sumcheck rounds (6 rounds/TX)    | ~1.35M CUs    |
| Relations accumulation           | ~778k CUs     |
| Shplemini phases (3a+3b1+3b2+3c) | ~2.48M CUs    |
| **Full verification (log_n=16)** | **7.17M CUs** |
| Transaction count                | **9 TXs**     |

**Benchmark circuit:** `sapling_spend` (log_n=16, 4 public inputs)

| Phase             | CUs       | TXs   |
| ----------------- | --------- | ----- |
| 1. Challenges     | 319K      | 1     |
| 2a. Rounds 0-5    | 1,344K    | 1     |
| 2b. Rounds 6-11   | 1,348K    | 1     |
| 2c. Rounds 12-15  | 896K      | 1     |
| 2d. Relations     | 778K      | 1     |
| 3a. Weights       | 456K      | 1     |
| 3b1. Folding      | 459K      | 1     |
| 3b2. Gemini+Libra | 642K      | 1     |
| 3c+4. MSM+Pairing | 926K      | 1     |
| **Total**         | **7.17M** | **9** |

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

## 5. ✅ DONE: FrLimbs in Relations

### What We Implemented

Converted all 26 UltraHonk subrelations in `relations.rs` to use `FrLimbs` internally:

- Created `RelationParametersLimbs` for challenge storage
- Precomputed all constant `FrLimbs` values at compile time
- Ported all `accumulate_*` functions to `accumulate_*_l` variants
- Only convert Fr↔FrLimbs at boundaries

### Actual Results

| Metric          | Before   | After    | Savings  |
| --------------- | -------- | -------- | -------- |
| Relations phase | 1,145K   | 778K     | **32%**  |
| Per-subrelation | ~44K avg | ~30K avg | **~14K** |

---

## 6. ✅ DONE: FrLimbs Direct Storage

### What We Implemented

Store FrLimbs in Montgomery form directly in account state between phases:

```rust
// Added to FrLimbs in field.rs
pub fn to_raw_bytes(&self) -> [u8; 32] { /* serialize Montgomery form */ }
pub fn from_raw_bytes(bytes: &[u8; 32]) -> Self { /* deserialize Montgomery form */ }
```

Result structs now use `Vec<FrLimbs>` instead of `Vec<Fr>`:

```rust
pub struct ShpleminiPhase3aResult {
    pub r_pows: Vec<FrLimbs>,    // Was Vec<Fr>
    pub pos0: FrLimbs,           // Was Fr
    // ...
}
```

### Actual Results

| Phase         | Before | After | Savings   |
| ------------- | ------ | ----- | --------- |
| 3a (weights)  | 536K   | 456K  | **-80K**  |
| 3b1 (folding) | 576K   | 459K  | **-117K** |
| 3b2 (gemini)  | 857K   | 642K  | **-215K** |
| 3c+4 (MSM)    | 775K   | 926K  | +151K\*   |
| **Net**       |        |       | **-262K** |

\*Phase 3c increased because it now does all Fr conversion for MSM syscalls.

---

## 7. ✅ DONE: SmallFrArray (Replace Vec with Stack Arrays)

### What We Implemented

Added `SmallFrArray<N>` type to `field.rs` for stack-allocated arrays:

```rust
pub struct SmallFrArray<const N: usize> {
    data: [FrLimbs; N],
    len: usize,
}
```

Replaced small Vec allocations in `shplemini.rs`:

- Phase 3a: `denoms` (3 elements) → `SmallFrArray<4>`
- Phase 3b1: `fold_denoms_l`, `r2_one_minus_u_l` → `SmallFrArray<MAX_LOG_N>`

### Actual Results

| Metric    | Before  | After   | Diff   |
| --------- | ------- | ------- | ------ |
| Phase 3a  | 455,590 | 455,559 | -31    |
| Phase 3b1 | 459,013 | 459,042 | +29    |
| **Net**   |         |         | **~0** |

**Conclusion:** Allocation overhead is negligible compared to computation.

### Stack Limit Constraint

`SmallFrArray<64>` (2KB) caused stack overflow - Solana's 4KB stack is tight.
Max safe size is ~32 FrLimbs (1KB).

---

## 8. ⏳ TODO: Degree-Specialized Sumcheck

### Current State

`next_target_l()` uses generic barycentric interpolation with 8-9 coefficients:

```rust
// Current: generic barycentric for any degree
fn next_target_l(univariate: &[FrLimbs], u: &FrLimbs) -> FrLimbs {
    // ~10-20 multiplications per round
    barycentric_eval(univariate, u, &I_FR_LIMBS, &BARY_COEFFS)
}
```

### Optimization

UltraHonk's actual univariate degrees are small (1, 2, or 3). Hardcode:

```rust
// Degree-1: h(u) = h0 + (h1 - h0) * u  → 2 muls
fn eval_degree1(h0: &FrLimbs, h1: &FrLimbs, u: &FrLimbs) -> FrLimbs {
    let b = h1.sub(h0);
    h0.add(&b.mul(u))
}

// Degree-2: h(u) = a + u*(b + c*u)  → 3 muls (Horner)
fn eval_degree2(h0: &FrLimbs, h1: &FrLimbs, h2: &FrLimbs, u: &FrLimbs) -> FrLimbs {
    // Derive a, b, c from h(0), h(1), h(2) once
    let a = *h0;
    let c = h2.sub(&h1.add(&h1).sub(h0)); // c = h2 - 2*h1 + h0
    let b = h1.sub(h0).sub(&c);           // b = h1 - h0 - c
    a.add(&u.mul(&b.add(&c.mul(u))))
}
```

### Expected Improvement

From ~10-20 muls/round to 2-4 muls/round = **3-5x faster** per round.

With 16 rounds at ~80k CUs each in evaluation: **~200-400k CUs** saved.

---

## 9. ⏳ TODO: Relations Monomial Factoring

### Current State

Each of 26 subrelations computes its formula independently with repeated wire accesses.

### Optimization

Normalize all relations to a common monomial basis:

```
r_j = Σ c_{j,i} * m_i
```

Where:

- `m_i` = wire values `w_1(z)`, `w_2(z)`, ..., `σ_1(z)`, ...
- `c_{j,i}` = challenge-only coefficients (precompute once)

Then accumulate:

```rust
// Precompute: coeff_for_m[i] = Σ_j α^j * c_{j,i}
let mut acc = FrLimbs::ZERO;
for i in 0..NUM_MONOMIALS {
    acc = acc.add(&coeff_for_m[i].mul(&m[i]));
}
```

### Expected Improvement

Reduces from O(relations × monomials) to O(monomials) multiplications.

**~60-100k CUs** saved in relations phase.

---

## 10. ⏳ TODO: Challenge `fr_reduce` Tuning

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
3. **Return FrLimbs directly**: Skip canonical form, stay in Montgomery

### Expected Improvement

~40-75k CUs saved (75 calls × ~500-1000 CU reduction each)

---

## 11. 💡 IDEA: BPF Assembly for `mont_mul`

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

## 12. Phase Packing Opportunities

### Current Transaction Structure (log_n=16, sapling_spend)

| Phase            | CUs       | TXs   |
| ---------------- | --------- | ----- |
| 1. Challenges    | 319K      | 1     |
| 2. Sumcheck      | 4,367K    | 4     |
| 3+4. MSM+Pairing | 2,482K    | 4     |
| **Total**        | **7.17M** | **9** |

### With Degree-Specialized Sumcheck (~300K saved)

- Phase 2 rounds might fit in fewer TXs
- Could potentially go from 4 → 3 sumcheck TXs

---

## 13. Minor Cleanups (Free Wins)

These are in the tens of k CUs range but easy to implement:

### 13.1 Ensure All Constants Are Truly Const

✅ Done for sumcheck (`I_FR_LIMBS`, `BARY_*_LIMBS`)
✅ Done for relations (precomputed FrLimbs constants)

### 13.2 Branchless Field Operations

Replace conditional branches with masks:

```rust
// Instead of: if borrow != 0 { limbs = result; }
let mask = (borrow as u64).wrapping_sub(1);
for i in 0..4 {
    limbs[i] = (result[i] & mask) | (limbs[i] & !mask);
}
```

### 13.3 Keep Tiny Wrappers Inline

`#[inline(always)]` on `fr_square`, `fr_neg`, etc. for Solana builds

---

## Priorities (Best Bang for Buck)

Tackle in this order:

| Priority | Optimization                    | Effort | Expected CUs Saved  |
| -------- | ------------------------------- | ------ | ------------------- |
| 1        | **Degree-specialized sumcheck** | Medium | **200-400K**        |
| 2        | Relations monomial factoring    | Medium | 60-100K             |
| 3        | Challenge fr_reduce tuning      | Low    | 40-75K              |
| 4        | BPF assembly for mont_mul       | High   | ~400K (last resort) |

**Already tried:**

- SmallFrArray (stack arrays): Implemented but **minimal impact** - allocation overhead negligible vs. computation

---

## CU Usage by Circuit Size

| Circuit              | log_n  | PIs   | Total CUs | TXs   |
| -------------------- | ------ | ----- | --------- | ----- |
| simple_square        | 12     | 1     | ~6.5M     | 9     |
| iterated_square_100  | 12     | 1     | ~6.5M     | 9     |
| fib_chain_100        | 12     | 1     | ~6.5M     | 9     |
| iterated_square_1000 | 13     | 1     | ~6.8M     | 9     |
| iterated_square_10k  | 14     | 1     | ~7.0M     | 9     |
| **sapling_spend**    | **16** | **4** | **7.17M** | **9** |
| hash_batch           | 17     | 32    | ~8.5M     | 10    |
| merkle_membership    | 18     | 32    | ~9.0M     | 10    |

**Key observations:**

- Same proof size (16,224 bytes) regardless of circuit due to `CONST_PROOF_SIZE_LOG_N=28` padding
- Smaller circuits (log_n=12) still run 28 sumcheck rounds (padding overhead!)
- More public inputs = more CUs for delta computation
- **Primary benchmark:** `sapling_spend` (realistic MASP-style circuit)

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
   → Fixed with zero-copy `&'a [u8]` reference (**54% CU savings in Phase 1**)

6. **Relations in Fr format**: Each subrelation converted Fr↔FrLimbs repeatedly
   → Fixed with full FrLimbs port of relations.rs (**32% savings**, 1.15M→778K CUs)

7. **Montgomery conversion at phase boundaries**: State stored Fr, converted to FrLimbs
   → Fixed with raw FrLimbs storage (**262K CUs saved** across phases)

### Optimization Timeline (Dec 2024)

| Date                      | Change                 | CU Impact |
| ------------------------- | ---------------------- | --------- |
| Dec 9                     | FrLimbs relations      | -367K CUs |
| Dec 10                    | FrLimbs direct storage | -262K CUs |
| **Total session savings** | **~630K CUs**          |

### What Made This Possible

- Montgomery multiplication already in place (7x faster than naive)
- Binary extended GCD for inversions (much faster than Fermat)
- Solana BN254 syscalls for pairing (~100 CUs for Keccak, cheap EC ops)
- FrLimbs type with `to_raw_bytes`/`from_raw_bytes` for zero-conversion storage
