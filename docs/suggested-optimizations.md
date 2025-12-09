Here’s what jumps out from the code + your BPF notes, focusing specifically on “math we do a ton of” and how to squeeze CUs out of it.

I’ll give you:

- Where in the code the hotspot lives
- What’s actually expensive there
- A concrete optimization idea
- Rough per‑call CU savings, then scaled by how often it happens per proof (using your own ballpark numbers from `bpf-limitations.md` for fr ops). ([GitHub][1])

---

## 0. Baseline: what’s actually killing you

From `docs/bpf-limitations.md`:

- `fr_mul`: ~500–1000 CUs per call.
- `fr_div`/`fr_inv`: ~2000–5000 CUs per division/inversion.
- Sumcheck verification: ~500+ multiplications, many inversions → Phase 2 currently blows past 1.4M CUs.
- MSM (Shplemini / P0): ~1000+ field muls plus ~70 G1 scalar muls. ([GitHub][1])

Code confirms:

- Field core: `crates/plonk-core/src/field.rs` – all scalar ops, including `fr_mul`, `fr_inv`, `fr_reduce`, etc. ([GitHub][2])
- Sumcheck: `crates/plonk-core/src/sumcheck.rs`. ([GitHub][3])
- Shplemini + MSM: `crates/plonk-core/src/shplemini.rs`. ([GitHub][4])
- BN254 syscalls: `crates/plonk-core/src/ops.rs`. ([GitHub][5])

I’ll assume:

- `fr_mul` ≈ **1k CUs**
- `fr_add/fr_sub` ≈ **300 CUs**
- `fr_inv` ≈ **3–4k CUs**

just to get order-of-magnitude estimates. Adjust proportionally to your actual measurements.

---

## 1. Sumcheck barycentric interpolation – switch to batch inversion (huge win)

**Where**

- `sumcheck.rs::next_target` ([GitHub][3])

**What it does now**

For each round (log_n rounds):

```rust
fn next_target(univariate: &[Fr], chi: &Fr, is_zk: bool) -> Result<Fr, &'static str> {
    let n = if is_zk { 9 } else { 8 };

    // B(χ) = ∏(χ - i)
    let mut b = SCALAR_ONE;
    for i in 0..n {
        let i_fr = fr_from_u64(i as u64);
        let chi_minus_i = fr_sub(chi, &i_fr);
        b = fr_mul(&b, &chi_minus_i);
    }

    // Σ u[i] / (BARY[i] * (χ - i))
    let mut acc = SCALAR_ZERO;
    for i in 0..n {
        let i_fr = fr_from_u64(i as u64);
        let chi_minus_i = fr_sub(chi, &i_fr);
        let bary_i = if is_zk { &BARY_9[i] } else { &BARY_8[i] };
        let denom = fr_mul(bary_i, &chi_minus_i);
        let inv = fr_inv(&denom).ok_or("denominator is zero in barycentric")?;
        let term = fr_mul(&univariate[i], &inv);
        acc = fr_add(&acc, &term);
    }

    Ok(fr_mul(&b, &acc))
}
```

Per **ZK** round (n=9), this is roughly:

- ~18× `fr_sub`
- ~27× `fr_mul`
- ~9× `fr_inv`
- ~9× `fr_add`

The inversions are the killer: ~9 × 3–4k CUs ≈ 27–36k CUs per round just on `fr_inv`.

With `log_n ≈ 19` (e.g. size 524,288 circuit), that’s ~171 inversions total.

**Optimization: batch inversion**

Use the standard “multi-inversion” trick:

1. Compute all denominators `D[i] = BARY[i] * (χ - i)`.
2. Compute prefix products `P[i+1] = P[i] * D[i]`.
3. Invert `P[n]` once: `inv_total = 1 / P[n]`.
4. Walk backwards to get each `D[i]^{-1}` with 2 multiplies per element.

So:

- Current per round: `n` inversions, ~3n multiplies.
- New per round: **1 inversion**, ~4n multiplies.

For n=9:

- Old: 9 inv, 27 mul.
- New: 1 inv, 34 mul.

You _lose_ 7 extra muls, but _save_ 8 inversions.

**CU impact (per round)**

Take a plausible mid-point:

- `fr_mul` ~ 800 CUs, `fr_inv` ~ 3000 CUs.

Old barycentric cost per round:

- inv: 9 × 3000 = 27,000
- mul: 27 × 800 ≈ 21,600
- plus adds/subs (minor)

New:

- inv: 1 × 3000 = 3,000
- mul: 34 × 800 ≈ 27,200

Net saving ≈ (27,000 − 3,000) − (27,200 − 21,600)
= 24,000 − 5,600 ≈ **18,400 CUs per round**.

For `log_n ≈ 19` rounds:

- 18,400 × 19 ≈ 350,000 CUs saved (roughly 0.3–0.4M CUs).

So **sumcheck Phase 2 goes from ~1.4M CUs to around 1.0–1.1M CUs**, _without_ touching protocol-level stuff. That probably means you can fit all of sumcheck into a single transaction instead of splitting.

**Implementation sketch**

- Precompute `i_fr[0..9]` as consts to avoid `fr_from_u64` every time.
- New `batch_inv(&[Fr]) -> Vec<Fr>` implemented in `field.rs`.
- Rewrite `next_target` to:

  - Build `chi_minus[i]` and `den[i] = BARY[i] * chi_minus[i]`.
  - `den_inv = batch_inv(&den)`.
  - Accumulate `acc += u[i] * den_inv[i]`.

---

## 2. Shplemini: rho^k precomputation instead of O(N²) exponentiation (big win)

**Where**

- `shplemini.rs::compute_p0_full`, in the wire commitments / shifted part. ([GitHub][4])

**What it does now (problematic bit)**

For each wire mapping entry:

```rust
for (sol_idx, &our_idx) in wire_mapping.iter().enumerate() {
    let commitment = proof.witness_commitment(our_idx);

    // unshifted scalar part
    let mut scalar = fr_mul(&neg_unshifted, &rho_pow);

    // For shifted commitments (first 5 wires), also add shifted contribution
    if sol_idx < NUMBER_TO_BE_SHIFTED {
        let shifted_rho_idx = NUMBER_UNSHIFTED + 1 + sol_idx; // e.g. 37..41
        let mut shifted_rho_pow = SCALAR_ONE;
        for _ in 0..shifted_rho_idx {
            shifted_rho_pow = fr_mul(&shifted_rho_pow, &challenges.rho);
        }
        let shifted_contrib = fr_mul(&neg_shifted, &shifted_rho_pow);
        scalar = fr_add(&scalar, &shifted_contrib);
    }

    // MSM call
    let scaled = ops::g1_scalar_mul(&commitment, &scalar)?;
    p0 = ops::g1_add(&p0, &scaled)?;
    rho_pow = fr_mul(&rho_pow, &challenges.rho);
}
```

The inner `for _ in 0..shifted_rho_idx` is **O(k)** exponentiation repeated for each shifted commitment. For the 5 shifted commitments you’re doing something like:

- exponents `k ∈ {37, 38, 39, 40, 41}`
- total `fr_mul` just for `rho^k` ≈ 37 + 38 + 39 + 40 + 41 = **195 muls**

And you also already have a running `rho_pow` outside the loop, so this is doubly wasteful.

**Optimization: precompute rho^k table once**

Before MSM:

```rust
// choose max exponent you ever need, e.g. MAX_RHO_POW = NUMBER_UNSHIFTED + 1 + NUMBER_TO_BE_SHIFTED
let max_k = NUMBER_UNSHIFTED + 1 + NUMBER_TO_BE_SHIFTED; // 35 + 1 + 5 = 41
let mut rho_pows = Vec::with_capacity(max_k + 1);
rho_pows.push(SCALAR_ONE);
for i in 1..=max_k {
    let next = fr_mul(&rho_pows[i - 1], &challenges.rho);
    rho_pows.push(next);
}
```

Then inside the wire loop:

```rust
if sol_idx < NUMBER_TO_BE_SHIFTED {
    let shifted_rho_idx = NUMBER_UNSHIFTED + 1 + sol_idx;
    let shifted_rho_pow = rho_pows[shifted_rho_idx];
    let shifted_contrib = fr_mul(&neg_shifted, &shifted_rho_pow);
    scalar = fr_add(&scalar, &shifted_contrib);
}
```

**CU impact**

- Current: ~195 `fr_mul` for these exponents.
- New: ~41 `fr_mul` to precompute up to `rho^41` (we can often reuse this table for other places too).
- Net: ~150 fewer `fr_mul`.

With ~1k CUs per mul, that’s ≈ **150k CUs saved** per proof.

And that’s just from this one loop. If you reuse the same precomputed `rho_pows` for other rho‑powers in Shplemini / relations, you shave even more.

---

## 3. Represent Fr as limbs + Montgomery form (systemic 2–3× on field ops)

You already flagged Montgomery / Karatsuba in the docs; here’s what your current code is doing and what I’d change.

**Where**

- `field.rs` ([GitHub][2])

**Current design**

- Public type: `pub type Fr = [u8; 32];` (big-endian bytes). ([GitHub][6])
- Every `fr_add`, `fr_sub`, `fr_mul`:

  - `fr_to_limbs(fr: &Fr) -> [u64; 4]`
  - run limb arithmetic (`add_mod`, `sub_mod`, `mul_mod_wide` etc.)
  - `limbs_to_fr(&[u64;4]) -> Fr`

- `mul_mod_wide` + `reduce_512` is essentially Barrett-ish reduction in a loop.

So each field op has:

1. 2× `Fr`→limb conversions.
2. 1× limb‑level core operation.
3. 1× limb→`Fr` conversion.

The conversions are not free on BPF – they’re lots of shifts, masks, and stores.

**Optimization 3.1 – keep everything as limbs**

Introduce a “canonical internal” field type:

```rust
#[derive(Copy, Clone)]
pub struct FrLimbs(pub [u64; 4]); // little-endian limbs in Montgomery form eventually
```

Then:

- Rewrite all internal verifier code (`sumcheck`, `relations`, `shplemini`, `transcript`, `delta`) to work with `FrLimbs`.
- Only convert to/from `[u8;32]` at:

  - proof parsing / VK parsing boundaries
  - when writing public inputs / outputs

- On BPF, you can guard this with `cfg(target_os = "solana")` or similar, keeping the byte API for tests.

**Expected per-call improvements**

- `fr_add`/`fr_sub`: drop 3 conversions → likely **2–3× faster** (no byte shuffling).
- `fr_mul`: limb conversion overhead is smaller relative to the 512-bit mul, but still ~10–20% → say **1.1–1.3× faster**.

Given your counts:

- Challenge generation: ~200 mul, ~300 add/sub. ([GitHub][1])
- Sumcheck: ~500+ mul, ~200+ add/sub (from code).
- Shplemini / relations: easily another ~500–800 field ops.

You’re in the ballpark of **O(1000–2000)** field ops per proof. If you shave:

- ~50% off add/sub (~500 calls) → save ~250 field‑op “units”.
- ~15–20% off mul (~700 calls) → save ~100–140 mul‑equivalents.

In CU terms (taking 1k per mul as the normalization), that’s a few hundred thousand CUs across the proof – I’d expect on the order of **200–400k CUs saved** just from this representation change.

**Optimization 3.2 – Montgomery multiplication**

You already have:

```rust
pub const R:  [u64; 4];  // modulus
pub const R2: [u64; 4];  // R^2 mod r
pub const INV: u64;      // -r^{-1} mod 2^64
```

in `field.rs`, which is exactly what you need for Montgomery form. ([GitHub][2])

If you keep all `FrLimbs` always in Montgomery form:

- Multiplication becomes a straight Montgomery reduction (no general 512→256 reduction loop).
- You avoid calling `fr_reduce` all over the place.
- Adds/subs remain cheap (just add then conditional subtract modulus).

I’d expect a further **~1.5× or so reduction in `fr_mul` cost** on top of the limb representation. Combine both and you’re looking at **~2×** speedup on mul and **2–3× on add/sub**.

Scaled across 1000+ muls and 500+ add/sub per proof, you’re easily in “half a million CUs” territory.

---

## 4. Batch inversion in Shplemini (medium–high)

You’re already using `fr_inv` heavily in Shplemini, and binary GCD is a good start. But you repeatedly invert many denominators that are independent.

**Where**

- `shplemini.rs::compute_shplemini_pairing_points` ([GitHub][4])

Key places:

1. `pos0 = 1/(z - r^0)`, `neg0 = 1/(z + r^0)` – 2 inversions.
2. Fold loop over `j in 1..=log_n`:

   - `den_inv = 1 / den_j` → `log_n` inversions.

3. Gemini fold loop `i in 0..CONST_PROOF_SIZE_LOG_N-1` (27 rounds):

   - For non-dummy `i < log_n - 1`:

     - `pos_inv = 1/(z - r^j)`
     - `neg_inv = 1/(z + r^j)`
     - That’s ~`2*(log_n-1)` inversions.

4. Libra denominators: `denom0 = 1/(z - r)`, `denom1 = 1/(z - SUBGROUP_GENERATOR * r)` → 2 inversions.

Total inversions in `compute_shplemini_pairing_points`:

- ≈ 2 (pos/neg0)
- - log_n
- - 2(log_n − 1)
- - 2 (libra)
- = 3·log_n + 2 (for log_n~19, ~59 inversions)

You probably can’t batch _all_ of them because some denominators (`den`) depend on running state (`cur` in the fold), but you _can_ batch all the static-ish `z ± r^j` denominators:

- For `j = 0..log_n` compute `D[j] = (z - r^j)` and `E[j] = (z + r^j)`.
- Batch invert all 2·(log_n+1) of them in one go.
- Use these inverses both:

  - in the initial pos0/neg0,
  - in the gemini fold loop,
  - in the Libra section (for the `z - r` denominator).

That means:

- Inversions for `z ± r^j` go from ~2·(log_n+1) to **1**.
- You keep separate `den_inv` for the fold loop (those depend on `cur`).

If each inversion costs ~3–4 muls in CU terms, and each batch invert uses an extra ~2n muls, it’s still a net win. For log_n ~19:

- Original: ~2\*(19+1)=40 inversions → ~120–200k CUs.
- New: 1 inversion + ~80 extra muls → ~3–4k + ~60–80k ≈ 65–85k.
- So you save something like **~60–130k CUs** inside Shplemini.

Couple that with the rho‑powers fix and Montgomery mul and the whole MSM phase shrinks significantly.

---

## 5. Sumcheck micro-optimizations (smaller, but cheap to do)

Still in `sumcheck.rs` ([GitHub][3])

### 5.1. Precompute i_fr values

Right now you repeatedly call `fr_from_u64(i as u64)` inside both barycentric loops every round.

- n=9, two loops → 18 calls per round × log_n ~19 → 342 calls.
- `fr_from_u64` isn’t massive, but it does byte writes and such.

Just define:

```rust
const I_FR_9: [Fr; 9] = [
    fr_from_u64_const(0), // or hard-coded bytes
    ...
];
```

and index into it. This is a minor CU savings (think tens of k, not hundreds), but basically free to implement.

### 5.2. Avoid recomputing (χ - i) twice

You already compute `chi_minus_i` in both loops:

- First loop (for B(χ))
- Second loop (for denom computation)

If you stick with the current non-batch version for a while, at least:

- Compute all `chi_minus[i]` once in a small `[Fr; 9]` array.
- Reuse in both loops.

Again, this is shaving off `n` subtractions per round, not game-changing, but it’s free once you’re refactoring `next_target` for batch inversion anyway.

---

## 6. Relations accumulation (likely 10–20% gain available)

**Where**

- `sumcheck.rs::accumulate_relations` delegates to `crate::relations::accumulate_relation_evaluations`. ([GitHub][3])
- `relations.rs` comment says: “accumulates all 28 UltraHonk subrelations”. ([GitHub][7])

The actual code is hard to see via this interface, but from Barretenberg’s UltraHonk design we know:

- There are ~26–28 subrelations.
- Most are linear-ish in evaluations and parameters (`eta`, `beta`, `gamma`, `public_inputs_delta`).
- They get combined with powers of `alpha` and `pow_partial`.

Typical pattern in Barretenberg:

```cpp
grand += alpha * (R0 + alpha * (R1 + alpha * (...)))
```

**Optimizations you almost certainly can do:**

1. **Fuse alpha powers**: precompute `alpha_i` as a small array via sequential muls once, and only multiply each subrelation once by the appropriate `alpha_i`.
2. **Factor common parameter combos**:

   - Precompute things like `beta * public_inputs_delta`, `gamma + beta * something`, etc., outside the big loop.

3. **Use limb/Montgomery field ops here as soon as you have them**.
4. **Loop ordering**: if any relations share the same evaluation(s), compute linear combinations first, then multiply by challenge powers, rather than the other way round.

Because this code runs exactly once per proof and touches ~40 sumcheck evaluations:

- Think on the order of a few hundred `fr_mul` and `fr_add`.
- A 20–30% reduction here is maybe **50–100 mul equivalents** → ~50–100k CUs.

Not as dramatic as sumcheck barycentric or rho‑powers, but still worth doing once you’re in there.

---

## 7. Field reduction & fr_reduce (medium)

**Where**

- `field.rs::fr_reduce` – used when squeezing challenges from Keccak, and possibly elsewhere. ([GitHub][2])

Current implementation:

```rust
pub fn fr_reduce(a: &Fr) -> Fr {
    let mut limbs = fr_to_limbs(a);
    // keep subtracting r until result < r
    loop {
        let (result, borrow) = sbb_limbs(&limbs, &R);
        if borrow != 0 { break; }
        limbs = result;
    }
    limbs_to_fr(&limbs)
}
```

For uniformly random 256-bit inputs, `a` is < ~5.8·r, so you need at most ~6 subtractions — but each subtraction is 4 limb ops.

You probably only call this in the transcript, where counts are modest:

- ~75 challenges → ~75 reductions. ([GitHub][1])

But you can still:

- Switch to Montgomery form, so reducing a 256-bit random value becomes: multiply by `R^2` and do one Monty reduction – which may be more predictable and cheaper than looped subtract.
- Or implement a constant‑time conditional subtract sequence based on the high limb value, reducing the worst-case subtract count.

Given there are only ~75 calls per proof, even a 50% speedup is “only” on the order of a few tens of k CUs. Definitely secondary compared to sumcheck/MSM work, but easy enough once you’re doing Monty.

---

## 8. BN254 G1 ops – cheap scalar-side improvements

**Where**

- `ops.rs` – G1 add, scalar mul, MSM wrapper. ([GitHub][5])
- Shplemini MSM: `compute_p0_full`. ([GitHub][4])

You can’t optimize Solana’s `alt_bn128_*` syscalls internally, but you can avoid _extra_ scalar-side field work used to compute the scalars.

We already covered:

- **rho^k precomputation** – big.
- **batch inversion of denominators** – medium.

Other micro-optimizations:

1. **Reuse r^2 powers across Shplemini and Gemini**: you already compute `r_pows` once via `r_pows[i] = r_pows[i-1]^2`. That’s great, and you’re using it in multiple places – keep that pattern for _all_ geometric/challenge sequences.
2. **Avoid temporary Vec allocations** in MSM:

   - You’re already mostly reusing; just ensure you’re not Vec‑allocating per scalar; that looks okay from `compute_p0_full` right now.

You’re doing ~68 G1 scalar muls and 68 G1 adds in Shplemini. G1 ops are syscalls that might be ~a few thousand CUs each, so MSM is likely in the 200–400k CU range. You’re not going to get a 10× here without changing the protocol, but shaving ~20–30% via scalar-side arithmetic simplifications is realistic.

---

## 9. Things you already (mostly) did or are low-priority

Just to avoid re-suggesting things from your doc:

- **Binary extended GCD for `fr_inv`** – already implemented in `field.rs`. Good call. ([GitHub][2])
- **Keccak syscalls** – you’re already using `sol_keccak256` (~100 CUs per hash) and that’s now cheap compared to field ops. ([GitHub][1])
- **Splitting challenge generation across multiple txs** – done (1a–1e). Sumcheck + MSM splitting will still be needed, but the goal here is to minimize splits.
- **Alternative proof systems (Groth16)** – yes, obviously much cheaper on Solana, but orthogonal if your goal is “UltraHonk or bust”.

---

## 10. Prioritized checklist

If I were you, I’d tackle in this order:

1. **Batch inversion in sumcheck barycentric** (`next_target`).

   - Very localized change.
   - Likely saves **~300–400k CUs**.
   - Might be enough to get Phase 2 into a single tx.

2. **Fix rho^k exponentiation in Shplemini’s P0 builder** (`compute_p0_full`).

   - Replace inner `for 0..k` loops with a `rho_pows[]` table.
   - Saves **~150k CUs** just on the wire/shifted scalars, more if reused.

3. **Move Fr to limb+Montgomery representation everywhere inside the verifier**.

   - Bigger refactor, but systemic: expect **2×+ speedup on field ops**.
   - Likely worth hundreds of thousands of CUs per proof.

4. **Batch inversion for `z ± r^j` denominators in Shplemini**.

   - Moderate refactor; additional **~60–130k CUs** possible.

5. **Clean up sumcheck micro-stuff** (precomputed i_fr, reuse `chi_minus_i`, etc.).

   - Small cumulative gains.

6. **Relations accumulation cleanup** (fuse alpha powers, factor params).

   - Maybe 10–20% off that part; not huge but cheap once you’re in there.

If you do (1)–(3), I’d expect:

- Sumcheck verification to comfortably fit into a single 1.4M CU tx.
- MSM + pairing to also be under 1 tx with fewer safety margins.
- Overall proof verification potentially going from “needs ~3+ txs” toward something like 2 txs, maybe 1 in aggressive configurations, depending on your circuit size.

If you want, next step we can do is: for one concrete test circuit in `test-circuits/` (e.g. `iterated_square_4`), walk the code path and build a more exact per-phase op count spreadsheet so you can plug your measured per‑op CUs into it.

[1]: https://github.com/nicolaslara/solana-noir-verifier/raw/phased-experiment/docs/bpf-limitations.md "raw.githubusercontent.com"
[2]: https://github.com/nicolaslara/solana-noir-verifier/raw/phased-experiment/crates/plonk-core/src/field.rs "raw.githubusercontent.com"
[3]: https://github.com/nicolaslara/solana-noir-verifier/raw/phased-experiment/crates/plonk-core/src/sumcheck.rs "raw.githubusercontent.com"
[4]: https://github.com/nicolaslara/solana-noir-verifier/raw/phased-experiment/crates/plonk-core/src/shplemini.rs "raw.githubusercontent.com"
[5]: https://github.com/nicolaslara/solana-noir-verifier/raw/phased-experiment/crates/plonk-core/src/ops.rs "raw.githubusercontent.com"
[6]: https://github.com/nicolaslara/solana-noir-verifier/raw/phased-experiment/crates/plonk-core/src/types.rs "raw.githubusercontent.com"
[7]: https://github.com/nicolaslara/solana-noir-verifier/raw/phased-experiment/crates/plonk-core/src/relations.rs "raw.githubusercontent.com"
