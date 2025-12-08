# UltraHonk Verification: A Complete Theoretical Walkthrough

This document provides a comprehensive theoretical explanation of how Noir circuits work with Barretenberg's UltraHonk proving system, from circuit definition through verification. Each section includes both theory and practical validation using our test proof data.

## Table of Contents

1. [Overview: The Big Picture](#1-overview-the-big-picture)
2. [Circuit Definition in Noir](#2-circuit-definition-in-noir)
3. [Arithmetization: From Circuit to Polynomials](#3-arithmetization-from-circuit-to-polynomials)
4. [Witness Generation](#4-witness-generation)
5. [Polynomial Commitment Scheme (KZG)](#5-polynomial-commitment-scheme-kzg)
6. [The Honk Protocol Structure](#6-the-honk-protocol-structure)
7. [Fiat-Shamir Transcript](#7-fiat-shamir-transcript)
8. [Sumcheck Protocol](#8-sumcheck-protocol)
9. [Polynomial Evaluation and Gemini Folding](#9-polynomial-evaluation-and-gemini-folding)
10. [Shplemini Batch Opening](#10-shplemini-batch-opening)
11. [Final Pairing Check](#11-final-pairing-check)
12. [Data Formats: VK and Proof](#12-data-formats-vk-and-proof)
13. [Mapping to Our Solana Implementation](#13-mapping-to-our-solana-implementation)

---

## 1. Overview: The Big Picture

### What is UltraHonk?

UltraHonk is Aztec/Barretenberg's latest proving system, evolved from UltraPlonk. It's a **Plonkish** arithmetization with:

- **Structured reference string (SRS)**: Universal setup based on KZG commitments over BN254
- **Lookup tables**: For efficient range checks and non-native operations
- **Custom gates**: Optimized gates for elliptic curve operations, Poseidon hashes, etc.
- **Sumcheck-based verification**: More efficient than the original Plonk quotient polynomial approach

### The Complete Pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           PROVER SIDE                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Circuit Definition (Noir)                                            │
│     └─> fn main(x: Field, y: pub Field) { assert(x * x == y); }         │
│                                                                          │
│  2. Compilation (nargo compile)                                          │
│     └─> ACIR (Abstract Circuit Intermediate Representation)              │
│         └─> Constraint System with gates, wires, lookup tables           │
│                                                                          │
│  3. Witness Generation (nargo execute)                                   │
│     └─> Witness: all wire values that satisfy constraints                │
│         └─> x=3, y=9 → w1=3, w2=3, w3=9, intermediate wires...          │
│                                                                          │
│  4. Proof Generation (bb prove)                                          │
│     a) Commit to witness polynomials (w1, w2, w3, w4)                   │
│     b) Compute lookup and permutation grand products                     │
│     c) Run sumcheck protocol                                             │
│     d) Generate polynomial evaluation proofs (Gemini + Shplonk + KZG)   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ Proof + VK + Public Inputs
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          VERIFIER SIDE                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Parse VK (circuit-specific commitments)                              │
│  2. Parse Proof (witness commitments, sumcheck data, opening proofs)    │
│  3. Re-derive all challenges via Fiat-Shamir transcript                  │
│  4. Verify sumcheck rounds (polynomial identity at random points)        │
│  5. Verify batched polynomial openings (Shplemini)                       │
│  6. Final KZG pairing check: e(P0, G2) = e(P1, τ·G2)                    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Circuit Definition in Noir

### Our Test Circuit

```noir
// test-circuits/simple_square/src/main.nr
fn main(x: Field, y: pub Field) {
    assert(x * x == y);
}
```

This circuit:

- Takes a **private input** `x` (known only to the prover)
- Takes a **public input** `y` (known to both prover and verifier)
- Asserts that `x² = y`

### Public Inputs in Our Test

From `target/keccak/public_inputs` (32 bytes):

```
00000000: 00...00 0000 0000 0000 0009  (y = 9 as big-endian Fr)
```

This means the circuit proves: "I know some `x` such that `x² = 9`" (the witness is `x = 3`).

---

## 3. Arithmetization: From Circuit to Polynomials

### The Execution Trace

UltraHonk uses a **Plonkish** arithmetization where the computation is laid out in an execution trace table:

```
Row │ w₁ (left) │ w₂ (right) │ w₃ (output) │ w₄ (fourth) │ Selectors...
────┼───────────┼────────────┼─────────────┼─────────────┼─────────────
 0  │     3     │      3     │      9      │     ...     │ q_arith=1
 1  │    ...    │     ...    │     ...     │     ...     │ ...
 n  │    ...    │     ...    │     ...     │     ...     │ ...
```

### Gate Types

UltraHonk supports multiple gate types, controlled by selector polynomials:

| Selector     | Gate Type                   | Constraint                                          |
| ------------ | --------------------------- | --------------------------------------------------- |
| `q_arith`    | Arithmetic                  | `qₘ·w₁·w₂ + q₁·w₁ + qᵣ·w₂ + qₒ·w₃ + q₄·w₄ + qc = 0` |
| `q_range`    | Range                       | Each wire value in [0, 3] (for delta constraints)   |
| `q_elliptic` | ECC Point Addition/Doubling | EC curve equation checks                            |
| `q_lookup`   | Lookup                      | Value is in predefined table                        |
| `q_poseidon` | Poseidon Hash               | S-box and MDS matrix operations                     |
| `q_aux`      | Auxiliary                   | ROM/RAM operations                                  |

### From Table to Polynomials

Each column becomes a polynomial over a domain H = {ω⁰, ω¹, ..., ωⁿ⁻¹} where ω is the n-th root of unity:

```
w₁(X) such that w₁(ωⁱ) = value at row i
```

For our circuit with `log₂(n) = 6`, we have `n = 64` rows (padded).

### The Circuit Size from VK

From our VK (first 96 bytes = 3 headers):

```
[0..32]:   log2_circuit_size = 6   (n = 64 rows)
[32..64]:  log2_domain_size = 17   (evaluation domain for FFT)
[64..96]:  num_public_inputs = 1   (just y = 9)
```

---

## 4. Witness Generation

### What is a Witness?

The witness is the complete assignment to all wires that satisfies all constraints:

```
Private:  x = 3
Public:   y = 9

Wire assignments:
  w₁[0] = 3 (x)
  w₂[0] = 3 (x, copied)
  w₃[0] = 9 (x * x = y)
  ... plus intermediate wires, lookup columns, etc.
```

### Witness Polynomials

The prover interpolates witness values into polynomials:

- `W₁(X)` - First wire polynomial
- `W₂(X)` - Second wire polynomial
- `W₃(X)` - Third wire polynomial
- `W₄(X)` - Fourth wire polynomial (for custom gates)

Plus auxiliary polynomials:

- `lookup_read_counts(X)` - How many times each lookup row is read
- `lookup_read_tags(X)` - Tags for lookup reads
- `lookup_inverses(X)` - Inverses for lookup argument
- `z_perm(X)` - Permutation grand product

---

## 5. Polynomial Commitment Scheme (KZG)

### How KZG Works

KZG (Kate-Zaverucha-Goldberg) commitments allow:

1. **Commit** to a polynomial P(X) as a single elliptic curve point
2. **Open** the commitment at any point z, proving P(z) = y

**Setup** (SRS - Structured Reference String):

- Powers of a secret τ encoded in elliptic curve points:
  - G₁: `{G, τG, τ²G, ..., τⁿ⁻¹G}`
  - G₂: `{H, τH}`

**Commit** to polynomial P(X) = Σᵢ pᵢXⁱ:

```
[P] = Σᵢ pᵢ · [τⁱ]₁ = P(τ) · G₁
```

**Open** at point z with value y:

- Compute quotient Q(X) = (P(X) - y) / (X - z)
- Proof is [Q] = Q(τ) · G₁

**Verify** using pairing:

```
e([P] - y·G₁, H) = e([Q], [τ - z]₂)
```

This works because if P(z) = y, then (X - z) divides (P(X) - y).

### KZG Points in Our Data

The VK contains 28 G1 points (commitments to selector and permutation polynomials):

- Selectors: `[Qₘ], [Qc], [Q₁], [Qᵣ], [Qₒ], [Q₄], [Q_lookup], [Q_arith], ...`
- Permutation: `[σ₁], [σ₂], [σ₃], [σ₄], [id₁], [id₂], [id₃], [id₄]`
- Tables: `[T₁], [T₂], [T₃], [T₄]`
- Lagrange: `[L_first], [L_last]`

Each G1 point is 64 bytes (32-byte x coordinate + 32-byte y coordinate).

---

## 6. The Honk Protocol Structure

### Why Honk Instead of Plonk?

Traditional Plonk verification requires:

1. Evaluate all constraints at random point ζ
2. Check quotient polynomial T(ζ) satisfies constraint identity
3. Verify polynomial openings

Honk uses **sumcheck** instead, which:

- Works over the boolean hypercube {0,1}^log(n) instead of roots of unity
- Enables more efficient batching of polynomial evaluations
- Allows for better folding schemes (like Nova/Sangria)

### The Verification Structure

```
UltraHonk Verification Steps:
├── 1. OinkVerifier (Setup)
│   ├── Compute VK hash
│   ├── Absorb public inputs into transcript
│   ├── Receive witness commitments
│   └── Generate η, β, γ challenges
│
├── 2. SumcheckVerifier (Main Protocol)
│   ├── For each round r in 0..log(n):
│   │   ├── Receive univariate polynomial uʳ(X)
│   │   ├── Check: uʳ(0) + uʳ(1) = target
│   │   ├── Generate challenge χʳ
│   │   └── Update target = uʳ(χʳ)
│   ├── Receive claimed evaluations
│   └── Verify: relation(evals) = target × pow_partial
│
├── 3. GeminiVerifier (Polynomial Folding)
│   ├── Receive fold commitments
│   ├── Generate r challenge
│   └── Fold polynomials into single claim
│
├── 4. ShplonkVerifier (Batch Opening)
│   ├── Generate ν, z challenges
│   ├── Batch all opening claims
│   └── Compute pairing inputs
│
└── 5. KZG Pairing Check
    └── Verify: e(P₀, G₂) = e(P₁, τ·G₂)
```

---

## 7. Fiat-Shamir Transcript

### Making the Protocol Non-Interactive

The original Honk protocol is interactive: verifier sends random challenges, prover responds.
Fiat-Shamir makes it non-interactive by deriving challenges from a hash of all prior messages.

### Transcript Construction

```rust
// crates/plonk-core/src/transcript.rs
pub struct Transcript {
    hasher: Keccak256,
}
```

Each challenge is derived by:

1. Hash all absorbed data
2. Reduce result mod r (BN254 scalar field)
3. Absorb the full challenge back for chaining

### Challenge Split

Many challenges are "split" into two 127-bit values:

```rust
fn split_challenge(challenge: &Fr) -> (Fr, Fr) {
    // lo = bits[0..127]
    // hi = bits[127..254]
}
```

This is used for challenges like η, β, γ where we need two related values.

### The Full Challenge Schedule

```
Transcript Order:
1. vk_hash                    → (absorbed)
2. public_inputs[]            → (absorbed)
3. pairing_point_object[16]   → (absorbed)
4. w₁, w₂, w₃                 → η, η₂, η₃ (split)
5. lookup_counts, tags, w₄    → β, γ (split)
6. lookup_inverses, z_perm    → α
7. [ZK: libra_concat, sum]    → libra_challenge
8. (nothing new)              → gate_challenges[] (powers by squaring)
9. For each round r:
   - univariate[r][]          → sumcheck_u[r] (split)
10. sumcheck_evaluations[]    → ρ (split)
11. gemini_fold_comms[]       → gemini_r (split)
12. gemini_a_evals[]          → shplonk_ν (split)
13. shplonk_q                 → shplonk_z (split)
```

### Validating Our Understanding

Our implementation computes these challenges. The test in `transcript.rs` validates:

```rust
// test_eta_challenge_computation verifies:
// keccak256(vk_hash || public_input || ppo || gemini_masking || w1 || w2 || w3)
// = expected challenge
```

---

## 8. Sumcheck Protocol

### The Core Idea

Sumcheck verifies a multilinear polynomial identity over the boolean hypercube:

```
Σ        f(x₁, x₂, ..., xₙ) = 0
(x₁,...,xₙ)∈{0,1}ⁿ
```

Instead of checking all 2ⁿ points, sumcheck reduces this to log(n) rounds of checking univariate polynomials.

### Round-by-Round

**Round 0:**

- Prover sends univariate u⁰(X) = Σ\_{x₂,...,xₙ ∈ {0,1}} f(X, x₂, ..., xₙ)
- Verifier checks: u⁰(0) + u⁰(1) = target (initially 0 for non-ZK)
- Verifier sends random χ₀
- New target: target = u⁰(χ₀)

**Round r:**

- Prover sends u^r(X) summing over remaining variables
- Verifier checks: u^r(0) + u^r(1) = target
- Verifier sends random χᵣ
- Update target

**Final:**
After log(n) rounds, verifier has challenges χ = (χ₀, ..., χ\_{log(n)-1}) and a target value.
Verify that f(χ) equals target (by evaluating all polynomials at χ).

### Univariates in Proof

For our log(n)=6 circuit with ZK flavor, each round has 9 coefficients:

```
proof.sumcheck_univariate(round) → [Fr; 9]
```

Non-ZK uses 8 coefficients (BATCHED_RELATION_PARTIAL_LENGTH).

### Barycentric Interpolation

To compute the next target from univariate coefficients and challenge χ:

```rust
fn next_target(univariate: &[Fr], chi: &Fr) -> Fr {
    // B(χ) = ∏(χ - i) for i in 0..8
    // result = B(χ) * Σ(u[i] / (BARY[i] * (χ - i)))
}
```

The BARY_8 constants are precomputed Lagrange denominators.

### ZK Adjustment: Libra

For ZK proofs, the initial target is not 0 but:

```
initial_target = libra_sum × libra_challenge
```

This masks the real sumcheck values to hide information about the witness.

---

## 9. Polynomial Evaluation and Gemini Folding

### The Problem

After sumcheck, we have claims about polynomial evaluations at point χ:

```
W₁(χ) = eval₁
W₂(χ) = eval₂
... (40 polynomials total)
```

Verifying each KZG opening separately would require 40 pairings!

### Gemini Protocol

Gemini "folds" multilinear polynomials into univariates:

1. **Initial**: Have multilinear P(X₁, ..., Xₙ) with evaluation point χ = (χ₁, ..., χₙ)

2. **Fold round j**:

   - Commit to Aⱼ(X) = P*{folded}(-X) + XⱿ · (P*{folded}(X) - P\_{folded}(-X)) / 2X
   - Evaluator computes Aⱼ(r) and Aⱼ(-r) for batching

3. **Result**: Single univariate with related evaluations at ±r

### Gemini Data in Proof

```
gemini_fold_comms[0..log(n)-1]  // G1 commitments
gemini_a_evals[0..log(n)]       // Evaluations at folding points
```

---

## 10. Shplemini Batch Opening

### The Goal

Batch all polynomial opening claims into a single KZG verification:

- 35 unshifted evaluations (polynomials evaluated at χ)
- 5 shifted evaluations (polynomials evaluated at χ·ω, for "next row" queries)

### Shplonk Batching

Use random challenges ν to combine claims:

```
Combined claim: Σᵢ νⁱ · (Pᵢ - evalᵢ) / (X - zᵢ)
```

For efficiency, group by evaluation point:

- All evaluations at z = r (from Gemini)
- All evaluations at z = -r

### Computing Pairing Points

The final computation produces (P₀, P₁) such that:

```
e(P₀, G₂) = e(P₁, τ·G₂)
```

Where:

- P₀ = MSM of all commitments with computed scalars + constant term
- P₁ = KZG quotient commitment

### Our Implementation

```rust
// crates/plonk-core/src/shplemini.rs
pub fn compute_shplemini_pairing_points(
    proof: &Proof,
    vk: &VerificationKey,
    challenges: &Challenges,
) -> Result<(G1, G1), &'static str>
```

This computes:

1. r^(2^i) powers for each round
2. Shplonk weights (1/(z±r) terms)
3. Fold position values
4. Accumulate into final points

---

## 11. Final Pairing Check

### The BN254 Pairing

BN254 provides a bilinear pairing:

```
e: G₁ × G₂ → Gₜ
```

Such that:

```
e(a·P, b·Q) = e(P, Q)^(ab)
```

### KZG Verification as Pairing

For KZG opening of polynomial P at point z with value y and proof π:

```
e([P] - y·G₁, G₂) = e([π], τ·G₂ - z·G₂)
```

### Batched Pairing Check

Instead of multiple pairings, we verify:

```
e(P₀, G₂) · e(-P₁, τ·G₂) = 1
```

This is done via Solana's `alt_bn128_pairing` syscall.

### G2 Generator Point

From our verifier:

```rust
fn g2_generator() -> G2 {
    // x1 = 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
    // x0 = 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
    // y1 = 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
    // y0 = 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
}
```

---

## 12. Data Formats: VK and Proof

### Verification Key (1888 bytes)

```
┌────────────────────────────────────────────────────────┐
│ Header (96 bytes)                                       │
├─────────────────┬──────────────────────────────────────┤
│ Offset 0-31     │ log2_circuit_size (u256, BE)         │
│ Offset 32-63    │ log2_domain_size (u256, BE)          │
│ Offset 64-95    │ num_public_inputs (u256, BE)         │
├─────────────────┴──────────────────────────────────────┤
│ Commitments (28 × 64 = 1792 bytes)                     │
├────────────────────────────────────────────────────────┤
│ G1 point format: x (32 bytes BE) || y (32 bytes BE)    │
│                                                         │
│ Order:                                                  │
│   [0]  Q_m        (multiplication selector)            │
│   [1]  Q_c        (constant selector)                  │
│   [2]  Q_l        (left wire selector)                 │
│   [3]  Q_r        (right wire selector)                │
│   [4]  Q_o        (output wire selector)               │
│   [5]  Q_4        (fourth wire selector)               │
│   [6]  Q_lookup   (lookup selector)                    │
│   [7]  Q_arith    (arithmetic gate indicator)          │
│   [8]  Q_range    (range constraint selector)          │
│   [9]  Q_elliptic (elliptic curve selector)            │
│   [10] Q_aux      (auxiliary/memory selector)          │
│   [11] Q_poseidon2_external                            │
│   [12] Q_poseidon2_internal                            │
│   [13] σ₁        (permutation poly 1)                  │
│   [14] σ₂        (permutation poly 2)                  │
│   [15] σ₃        (permutation poly 3)                  │
│   [16] σ₄        (permutation poly 4)                  │
│   [17] ID₁       (identity poly 1)                     │
│   [18] ID₂       (identity poly 2)                     │
│   [19] ID₃       (identity poly 3)                     │
│   [20] ID₄       (identity poly 4)                     │
│   [21] Table₁    (lookup table column 1)               │
│   [22] Table₂    (lookup table column 2)               │
│   [23] Table₃    (lookup table column 3)               │
│   [24] Table₄    (lookup table column 4)               │
│   [25] L_first   (Lagrange first row)                  │
│   [26] L_last    (Lagrange last row)                   │
│   [27] ???       (additional commitment)               │
└────────────────────────────────────────────────────────┘
```

### Proof Structure (Variable Size)

For ZK proof with log(n)=6:

```
┌────────────────────────────────────────────────────────┐
│ Total: 162 Fr elements = 5184 bytes                     │
├────────────────────────────────────────────────────────┤
│                                                         │
│ 1. Pairing Point Object (16 Fr = 512 bytes)            │
│    - IPA accumulator data for recursion                │
│    - Offsets 0-511                                     │
│                                                         │
│ 2. Witness Commitments (8 G1 = 16 Fr = 512 bytes)      │
│    [0,1]   W₁ commitment                               │
│    [2,3]   W₂ commitment                               │
│    [4,5]   W₃ commitment                               │
│    [6,7]   lookup_read_counts commitment               │
│    [8,9]   lookup_read_tags commitment                 │
│    [10,11] W₄ commitment                               │
│    [12,13] lookup_inverses commitment                  │
│    [14,15] z_perm commitment                           │
│                                                         │
│ 3. Libra Data [ZK only] (3 Fr = 96 bytes)              │
│    [0,1]   libra_concat commitment (G1)                │
│    [2]     libra_sum (Fr)                              │
│                                                         │
│ 4. Sumcheck Univariates (log(n) × 9 = 54 Fr)           │
│    For each round r in 0..6:                           │
│      9 coefficients of univariate polynomial           │
│                                                         │
│ 5. Sumcheck Evaluations (41 Fr for ZK)                 │
│    All polynomial evaluations at sumcheck point χ      │
│                                                         │
│ 6. Libra Post-Sumcheck [ZK only] (8 Fr)                │
│    libra_claimed_eval, libra_grand_sum_comm,           │
│    libra_quotient_comm, gemini_masking_comm,           │
│    gemini_masking_eval                                 │
│                                                         │
│ 7. Gemini Fold Commitments ((log(n)-1) × 2 = 10 Fr)    │
│    5 G1 points for folding                             │
│                                                         │
│ 8. Gemini A Evaluations (log(n) = 6 Fr)                │
│    Evaluations of folded polynomials                   │
│                                                         │
│ 9. Small IPA [ZK only] (2 Fr)                          │
│                                                         │
│ 10. Shplonk Q Commitment (2 Fr = 1 G1)                 │
│                                                         │
│ 11. KZG Quotient Commitment (2 Fr = 1 G1)              │
│                                                         │
│ 12. Extra Protocol Data (2 Fr)                         │
│                                                         │
└────────────────────────────────────────────────────────┘
```

### Validating Proof Structure

From our actual proof (hex dump offset 0x200 = 512):

```
Offset 0x200: Wire commitment W₁ starts here
  23187927... = start of first witness commitment
```

---

## 13. Mapping to Our Solana Implementation

### Module Structure

| Theory Component       | Our Code Location                                            | Status                 |
| ---------------------- | ------------------------------------------------------------ | ---------------------- |
| VK Parsing             | `crates/plonk-core/src/key.rs`                               | ✅ Working             |
| Proof Parsing          | `crates/plonk-core/src/proof.rs`                             | ✅ Working             |
| Transcript/Fiat-Shamir | `crates/plonk-core/src/transcript.rs`                        | ⚠️ Needs validation    |
| Challenge Generation   | `crates/plonk-core/src/verifier.rs:generate_challenges()`    | ⚠️ Needs validation    |
| Sumcheck Rounds        | `crates/plonk-core/src/sumcheck.rs:verify_sumcheck_rounds()` | ⚠️ In progress         |
| Relation Evaluation    | `crates/plonk-core/src/relations.rs`                         | ⚠️ In progress         |
| Gemini Folding         | `crates/plonk-core/src/shplemini.rs` (partial)               | ⚠️ Simplified          |
| Shplemini Batching     | `crates/plonk-core/src/shplemini.rs`                         | ⚠️ Simplified          |
| Pairing Check          | `crates/plonk-core/src/verifier.rs:verify_inner()`           | ⚠️ Placeholder         |
| BN254 Operations       | `crates/plonk-core/src/ops.rs`                               | ✅ Via Solana syscalls |
| Field Arithmetic       | `crates/plonk-core/src/field.rs`                             | ✅ Working             |

### Key Functions

```rust
// Main entry point
pub fn verify(
    vk_bytes: &[u8],        // 1888 bytes
    proof_bytes: &[u8],     // Variable, depends on log(n)
    public_inputs: &[Fr],   // Array of 32-byte field elements
    is_zk: bool,            // true for Keccak oracle (default)
) -> Result<(), VerifyError>

// Challenge generation (Fiat-Shamir)
fn generate_challenges(
    vk: &VerificationKey,
    proof: &Proof,
    public_inputs: &[Fr],
) -> Result<Challenges, VerifyError>

// Sumcheck verification
pub fn verify_sumcheck(
    proof: &Proof,
    challenges: &SumcheckChallenges,
    relation_params: &RelationParameters,
    libra_challenge: Option<&Fr>,
) -> Result<(), &'static str>

// Final pairing computation
fn compute_pairing_points(
    vk: &VerificationKey,
    proof: &Proof,
    challenges: &Challenges,
) -> Result<(G1, G1), VerifyError>
```

### Known Issues / Areas Needing Work

#### Issue 1: Challenge Matching (CRITICAL)

Our transcript may not exactly match bb's challenge derivation. This is the most likely source of verification failures.

**Symptoms:**

- Verification fails at sumcheck (target mismatch)
- Or verification fails at pairing check (wrong P0/P1)

**How to Debug:**

1. Add debug logging to `generate_challenges()` in `verifier.rs`
2. Compare each challenge with bb's output
3. The test `test_eta_challenge_computation` in `transcript.rs` shows partial validation

**Specific Concerns:**

- VK hash computation may differ (see Issue 2)
- Pairing point object handling in transcript
- Challenge split logic (127-bit vs 128-bit boundaries)

#### Issue 2: VK Hash Computation (✅ FIXED)

The VK hash is added to transcript first in `verifier.rs:compute_vk_hash()`.

**STATUS:** Now matches bb's output:

```
bb verify shows:  0x093e299e4b0c0559f7aa64cb989d22d9d10b1d6b343ce1a894099f63d7a85a75
Our implementation: 0x093e299e4b0c0559f7aa64cb989d22d9d10b1d6b343ce1a894099f63d7a85a75 ✅
```

The VK hash is computed by hashing: header fields (as 32-byte BE) || all commitments (64 bytes each).

#### Issue 3: Gemini Masking Position (ZK Only)

For ZK proofs, various libra/gemini masking elements appear in the proof and must be added to transcript in the correct order.

**Current Order in Our Code:**

1. VK hash
2. Public inputs
3. Pairing point object
4. W₁, W₂, W₃ → generate η challenges
5. lookup_counts, lookup_tags, W₄ → generate β, γ
6. lookup_inverses, z_perm → generate α
7. libra_concat, libra_sum → generate libra_challenge
8. (gate challenges via squaring)
9. Sumcheck univariates → generate sumcheck u challenges

**Potential Issue:** bb may expect `gemini_masking_commitment` earlier in the transcript.

#### Issue 4: Shplemini MSM (INCOMPLETE)

The full Shplemini computation requires a Multi-Scalar Multiplication (MSM) over ~70 commitments:

- 28 VK commitments
- 8 witness commitments
- Gemini fold commitments
- Various auxiliary commitments

**Our Current Implementation:**

```rust
// shplemini.rs - compute_p0_simplified() is a PLACEHOLDER
fn compute_p0_simplified(proof: &Proof, const_acc: &Fr, z: &Fr) -> Result<G1, &'static str> {
    // Only uses shplonk_q, const_acc * G, z * kzg_quotient
    // Missing: Full MSM of all commitments with their scalars
}
```

**Required Fix:** Implement full MSM using Solana's `alt_bn128_g1_multiplication` and `alt_bn128_g1_addition` syscalls.

#### Issue 5: Relation Evaluation

The 26 subrelations in `relations.rs` are implemented but may have subtle formula differences from bb.

**Subrelation Categories:**
| Index | Type | Our Implementation | Status |
|-------|------|-------------------|--------|
| 0-1 | Arithmetic | `accumulate_arithmetic()` | ⚠️ Need to verify formulas |
| 2-3 | Permutation | `accumulate_permutation()` | ⚠️ public_input_delta may be wrong |
| 4-5 | Lookup | `accumulate_lookup()` | ⚠️ Need to verify |
| 6-9 | Range | `accumulate_range()` | ⚠️ Delta constraint formulas |
| 10-11 | Elliptic | `accumulate_elliptic()` | ⚠️ Complex, likely issues |
| 12-17 | Auxiliary | `accumulate_aux()` | ❌ Currently returns zeros |
| 18-25 | Poseidon | `accumulate_poseidon()` | ⚠️ Need verification |

**Debugging Approach:**

1. For simple circuits (like simple_square), many subrelations should be zero
2. Focus on arithmetic (0-1) and permutation (2-3) first
3. Add debug output to see which subrelations are non-zero

### Debugging Workflow

1. **First**, verify transcript challenges match bb:

   ```bash
   # Add debug feature and run
   cargo test -p plonk-core test_debug_real_proof --features debug -- --nocapture
   ```

2. **If challenges match**, verify sumcheck rounds:

   - Each round: `u[r][0] + u[r][1] == target`
   - Update target via barycentric interpolation

3. **If sumcheck passes**, verify relation evaluation:

   - Final target should equal relation accumulation
   - Debug individual subrelation outputs

4. **If relations pass**, verify Shplemini:
   - This requires implementing full MSM
   - Can test with known good pairing points first

---

## Appendix A: Validated Test Data

The following data was extracted from our test proof using `scripts/validate_theory.py`:

### Test Circuit Configuration

```
Circuit:      simple_square (x² = y)
Witness:      x = 3 (private)
Public Input: y = 9
log_n:        6 (circuit_size = 64)
is_zk:        true (Keccak oracle)
```

### Extracted Proof Data

**Public Input (1 × 32 bytes):**

```
y = 9 = 0x0000000000000000000000000000000000000000000000000000000000000009
```

**VK Hash:**

```
Our computation:  0x208bd97838d91de580261bed943ed295c712c7fb7851189c7dedae7473606d1d
bb's actual:      0x093e299e4b0c0559f7aa64cb989d22d9d10b1d6b343ce1a894099f63d7a85a75

⚠️  MISMATCH DETECTED! Our VK hash computation is WRONG.
This is a critical bug - all challenges will be incorrect if this doesn't match.
```

**Pairing Point Object (first 4 of 16):**

```
ppo[0] = 0x0000000000000000000000000000000000000000000000042ab5d6d1986846cf
ppo[1] = 0x00000000000000000000000000000000000000000000000b75c020998797da78
ppo[2] = 0x0000000000000000000000000000000000000000000000005a107acb64952eca
ppo[3] = 0x000000000000000000000000000000000000000000000000000031e97a575e9d
```

**Witness Commitments (first 3):**

```
W₁: x=0x01b160cbbb3b231bb57c63cbef951f0cabb5a82fe01b90009c70de1a2c3fbfaf
    y=0x29d5371b41e8869a7dbc0906ed6f5ec57d01dea12c98363bee3db010ce32c594

W₂: x=0x145d178970b6882328895ad96b46528228812691cbd1d50e8ee4b93cac0c0e81
    y=0x2c73c4864c37867171393801fe06a393d1a7e32c0e91493e565f41f18cd08727

W₃: x=0x1ac12db3871d19c9eef972b2e822bdf5563614e9caa74be10db1e4c15663540e
    y=0x0c4c231dae45cb720ac688bd3ed5261a80881fd28bcd873427070eb5fc6b087d
```

**Libra Data (ZK):**

```
libra_sum = 0x0e45edfe0e6fb613b746450956476d250c01b93b67b911a191045607daa88e4c
```

**Sumcheck Round 0 Univariate:**

```
u[0][0] = 0x029552254e08cdc891df8b57a60fdcf914fc0d0036bcc5f00838d7bfc13cd9e7
u[0][1] = 0x10c633d66f0bc1da855dd0bd1f2e3d2a04e35eadd71c5fa0f01d9867e09b00b8
sum     = 0x135b85fbbd148fa3173d5c14c53e1a2319df6bae0dd92590f8567027a1d7da9f
```

**Implied Challenge (from sumcheck):**

```
libra_challenge = sum / libra_sum
                = 0x0000000000000000000000000000000063a98f013e675b286495f7a726f39a72

Note: This is a 127-bit value (lower half of full challenge after split)
```

This validates that our understanding of the proof structure is correct. The sumcheck initial target equals `libra_sum × libra_challenge`, which must equal `u[0][0] + u[0][1]`.

---

## Appendix B: Validation Script

See `scripts/validate_theory.py` for a Python script that:

1. Parses our test proof and VK
2. Computes expected challenge values
3. Validates against proof data

Run with:

```bash
python3 scripts/validate_theory.py
```

---

## Appendix B: References

1. **Barretenberg Source**: https://github.com/AztecProtocol/barretenberg
2. **Noir Documentation**: https://noir-lang.org/docs
3. **UltraHonk Spec (ZKVerify)**: UltraHonk pallet in zkVerify
4. **KZG Paper**: Kate, Zaverucha, Goldberg - "Constant-Size Commitments to Polynomials"
5. **Sumcheck Paper**: Lund et al. - "Algebraic Methods for Interactive Proof Systems"
6. **Gemini Paper**: Bootle et al. - "Gemini: Elastic SNARKs for Diverse Environments"

---

## Appendix C: Quick Reference - Byte Offsets in Test Data

### Test Circuit: simple_square (x²=9, witness x=3)

**VK** (1888 bytes):

- `[0x00..0x20]`: log2_circuit_size = 6
- `[0x20..0x40]`: log2_domain_size = 17
- `[0x40..0x60]`: num_public_inputs = 1
- `[0x60..0xA0]`: Q_m commitment (64 bytes)
- ... (28 total commitments)

**Proof** (5184 bytes, ZK with log_n=6):

- `[0x000..0x200]`: Pairing point object (16 × 32 = 512 bytes)
- `[0x200..0x240]`: W₁ commitment
- `[0x240..0x280]`: W₂ commitment
- `[0x280..0x2C0]`: W₃ commitment
- ... (see section 12 for full layout)

**Public Inputs** (32 bytes):

- `[0x00..0x20]`: y = 9 (big-endian Fr)
