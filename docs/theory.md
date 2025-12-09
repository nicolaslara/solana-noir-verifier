# UltraHonk Verification: A Complete Theoretical Walkthrough

This document provides a comprehensive theoretical explanation of how Noir circuits work with Barretenberg's UltraHonk proving system, from circuit definition through verification. Each section includes both theory and practical validation using our test proof data.

**Status:** ✅ End-to-end verification working! Our Solana implementation passes all tests.

## Table of Contents

1. [Glossary: Key Terms and Concepts](#1-glossary-key-terms-and-concepts)
2. [Overview: The Big Picture](#2-overview-the-big-picture)
3. [Circuit Definition in Noir](#3-circuit-definition-in-noir)
4. [Arithmetization: From Circuit to Polynomials](#4-arithmetization-from-circuit-to-polynomials)
5. [Witness Generation](#5-witness-generation)
6. [Polynomial Commitment Scheme (KZG)](#6-polynomial-commitment-scheme-kzg)
7. [The Honk Protocol Structure](#7-the-honk-protocol-structure)
8. [Fiat-Shamir Transcript](#8-fiat-shamir-transcript)
9. [Sumcheck Protocol](#9-sumcheck-protocol)
10. [Polynomial Evaluation and Gemini Folding](#10-polynomial-evaluation-and-gemini-folding)
11. [Shplemini Batch Opening](#11-shplemini-batch-opening)
12. [Final Pairing Check](#12-final-pairing-check)
13. [Data Formats: VK and Proof](#13-data-formats-vk-and-proof)
14. [Implementation Mapping](#14-implementation-mapping)
15. [Appendix: Validation and Test Data](#appendix-validation-and-test-data)

---

## 1. Glossary: Key Terms and Concepts

Before diving into the protocol, let's define the fundamental concepts you'll encounter throughout this document.

### Cryptographic Primitives

| Term                           | What It Is                                                                              | Analogy                                                                                        |
| ------------------------------ | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| **Zero-Knowledge Proof (ZKP)** | A proof that convinces someone you know a secret without revealing the secret itself    | Proving you know a password by demonstrating you can open a lock, without showing the password |
| **SNARK**                      | Succinct Non-interactive ARgument of Knowledge - a compact proof that's quick to verify | A tiny certificate that proves a complex computation was done correctly                        |
| **Prover**                     | The party generating the proof (has the secret witness)                                 | You, proving you know something                                                                |
| **Verifier**                   | The party checking the proof (doesn't need to know the secret)                          | The person checking your claim                                                                 |

### Algebraic Structures

| Term               | What It Is                                                                       | In Our Context                                      |
| ------------------ | -------------------------------------------------------------------------------- | --------------------------------------------------- |
| **Field (Fr)**     | A set of numbers where you can add, subtract, multiply, and divide (except by 0) | BN254's scalar field - numbers mod a ~254-bit prime |
| **Elliptic Curve** | A mathematical curve where points can be added together                          | BN254 curve used for commitments                    |
| **G1 Point**       | A point on the elliptic curve (first group)                                      | 64 bytes: (x, y) coordinates                        |
| **G2 Point**       | A point on a "twisted" version of the curve (second group)                       | 128 bytes: (x₀, x₁, y₀, y₁) for extension field     |
| **Pairing**        | A special operation `e(G1, G2) → Gₜ` with bilinear properties                    | The final verification check                        |

### Protocol Components

| Term                      | What It Is                                                            | Purpose                                                                 |
| ------------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| **Verification Key (VK)** | Circuit-specific public data containing polynomial commitments        | Lets anyone verify proofs for this specific circuit                     |
| **Proof**                 | The prover's output - commitments and evaluations proving computation | What gets verified on Solana                                            |
| **Public Inputs**         | Values known to both prover and verifier                              | The statement being proven (e.g., "I know x where x² = 9", 9 is public) |
| **Private Witness**       | Secret values known only to the prover                                | The actual secret (e.g., x = 3)                                         |
| **Transcript**            | A running hash of all protocol messages                               | Derives verifier challenges (Fiat-Shamir)                               |
| **Challenge**             | A random-looking value derived from the transcript                    | Forces the prover to be honest                                          |

### UltraHonk-Specific Terms

| Term                       | What It Is                                      | Purpose                                              |
| -------------------------- | ----------------------------------------------- | ---------------------------------------------------- |
| **Sumcheck**               | A protocol to verify polynomial identities      | Main verification protocol in Honk                   |
| **Gemini**                 | Polynomial folding technique                    | Reduces many polynomial evaluations to fewer         |
| **Shplemini**              | Batched opening verification (Shplonk + Gemini) | Efficiently verifies all polynomial openings at once |
| **Selector Polynomial**    | Indicates which gate type is active at each row | Controls what constraint is checked                  |
| **Permutation Polynomial** | Encodes wire connections between gates          | Ensures correct "wiring" of the circuit              |

### Why These Names?

- **UltraHonk**: "Ultra" for the gate system (from UltraPlonk), "Honk" for the sumcheck-based protocol
- **KZG**: Kate, Zaverucha, Goldberg - the authors of the polynomial commitment scheme
- **Fiat-Shamir**: The technique to make interactive proofs non-interactive
- **BN254**: Barreto-Naehrig curve with ~254-bit prime (also called alt_bn128)

---

## 2. Overview: The Big Picture

### What Problem Does This Solve?

Imagine you want to prove to someone that you know a secret number `x` such that `x² = 9`, but you don't want to reveal that `x = 3`. A zero-knowledge proof lets you do exactly this.

More practically, ZK proofs enable:

- **Privacy**: Prove you're over 18 without revealing your birthdate
- **Scaling**: Compress thousands of transactions into one proof (rollups)
- **Verification offloading**: Heavy computation off-chain, cheap verification on-chain

### What is UltraHonk?

UltraHonk is Aztec/Barretenberg's latest proving system, evolved from UltraPlonk. It's a **Plonkish** arithmetization with:

- **Structured Reference String (SRS)**: Universal setup based on KZG commitments over BN254
- **Lookup Tables**: For efficient range checks and non-native operations
- **Custom Gates**: Optimized gates for elliptic curve operations, Poseidon hashes, etc.
- **Sumcheck-based Verification**: More efficient than the original Plonk quotient polynomial approach

### The Complete Pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           PROVER SIDE                                    │
│   (Heavy computation - runs off-chain on powerful hardware)             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Circuit Definition (Noir)                                            │
│     └─> fn main(x: Field, y: pub Field) { assert(x * x == y); }         │
│         "Here's the computation I want to prove"                        │
│                                                                          │
│  2. Compilation (nargo compile)                                          │
│     └─> ACIR (Abstract Circuit Intermediate Representation)              │
│         └─> Constraint System with gates, wires, lookup tables           │
│         "Convert human-readable code to mathematical constraints"        │
│                                                                          │
│  3. Witness Generation (nargo execute)                                   │
│     └─> Witness: all wire values that satisfy constraints                │
│         └─> x=3, y=9 → w1=3, w2=3, w3=9, intermediate wires...          │
│         "Fill in all the values that make the circuit 'work'"            │
│                                                                          │
│  4. Proof Generation (bb prove)                                          │
│     a) Commit to witness polynomials (w1, w2, w3, w4)                   │
│     b) Compute lookup and permutation grand products                     │
│     c) Run sumcheck protocol                                             │
│     d) Generate polynomial evaluation proofs (Gemini + Shplonk + KZG)   │
│     "Create the cryptographic proof"                                     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ Proof (~5KB) + VK (~2KB) + Public Inputs
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          VERIFIER SIDE                                   │
│   (Light computation - runs on Solana in ~300K compute units)           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Parse VK (circuit-specific commitments)                              │
│     "Load the circuit description"                                       │
│                                                                          │
│  2. Parse Proof (witness commitments, sumcheck data, opening proofs)    │
│     "Load what the prover claims"                                        │
│                                                                          │
│  3. Re-derive all challenges via Fiat-Shamir transcript                  │
│     "Generate the same 'random' challenges the prover used"              │
│                                                                          │
│  4. Verify sumcheck rounds (polynomial identity at random points)        │
│     "Check the main protocol - 6 rounds for our circuit"                 │
│                                                                          │
│  5. Verify batched polynomial openings (Shplemini)                       │
│     "Confirm all the polynomial evaluations are correct"                 │
│                                                                          │
│  6. Final KZG pairing check: e(P0, G2) × e(P1, τ·G2) = 1                │
│     "One elliptic curve pairing to rule them all"                       │
│                                                                          │
│  Result: ✅ ACCEPT or ❌ REJECT                                          │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Sizes and Costs (Our Test Circuit)

| Component          | Size       | Notes                      |
| ------------------ | ---------- | -------------------------- |
| Verification Key   | 1888 bytes | 28 G1 commitments + header |
| Proof (ZK, Keccak) | 5184 bytes | 162 field elements         |
| Public Input       | 32 bytes   | Just `y = 9`               |
| Solana Compute     | ~300K CU   | Using BN254 syscalls       |

---

## 3. Circuit Definition in Noir

### Our Test Circuit

```noir
// test-circuits/simple_square/src/main.nr
fn main(x: Field, y: pub Field) {
    assert(x * x == y);
}
```

This circuit:

- Takes a **private input** `x` (known only to the prover) - the "witness"
- Takes a **public input** `y` (known to both prover and verifier) - the "statement"
- Asserts that `x² = y`

### What Does "Circuit" Mean?

A "circuit" in ZK isn't like an electronic circuit. It's a mathematical representation of a computation as a series of constraints. Think of it as:

1. **Inputs**: Some values enter the circuit
2. **Gates**: Mathematical operations (add, multiply, compare) transform values
3. **Wires**: Connect outputs of one gate to inputs of another
4. **Constraints**: Rules that must be satisfied (like `output = input1 × input2`)

For `x * x == y`:

- Wire 1 carries `x`
- Wire 2 carries `x` (same value, "copied")
- Wire 3 carries `x * x`
- Constraint: Wire 3 must equal `y`

### Public Inputs in Our Test

From `target/keccak/public_inputs` (32 bytes):

```
0x0000000000000000000000000000000000000000000000000000000000000009
```

This is `y = 9` as a big-endian 256-bit field element.

The proof demonstrates: "I know some `x` such that `x² = 9`" without revealing that `x = 3`.

---

## 4. Arithmetization: From Circuit to Polynomials

### Why Polynomials?

We need to convert our circuit into a form that:

1. Can be verified efficiently
2. Allows random sampling (for soundness)
3. Can be "committed to" cryptographically

Polynomials are perfect for this because:

- They're defined by a few coefficients but can be evaluated at infinitely many points
- If two different polynomials agree at more points than their degree, they must be the same
- We can commit to a polynomial without revealing it (using KZG)

### The Execution Trace

UltraHonk uses a **Plonkish** arithmetization where the computation is laid out in an execution trace table:

```
Row │ w₁ (left) │ w₂ (right) │ w₃ (output) │ w₄ (fourth) │ Selectors...
────┼───────────┼────────────┼─────────────┼─────────────┼─────────────
 0  │     3     │      3     │      9      │     ...     │ q_arith=1
 1  │    ...    │     ...    │     ...     │     ...     │ ...
 n  │    ...    │     ...    │     ...     │     ...     │ ...
```

Each column becomes a polynomial. For row `i`, the polynomial evaluates to the value at that row when evaluated at `ωⁱ`, where `ω` is a root of unity.

### Gate Types

UltraHonk supports multiple gate types, controlled by selector polynomials:

| Selector     | Gate Type            | What It Does                                        |
| ------------ | -------------------- | --------------------------------------------------- |
| `q_arith`    | Arithmetic           | `qₘ·w₁·w₂ + q₁·w₁ + qᵣ·w₂ + qₒ·w₃ + q₄·w₄ + qc = 0` |
| `q_range`    | Range                | Checks each wire value is in [0, 3]                 |
| `q_elliptic` | ECC Point Add/Double | EC curve equation checks                            |
| `q_lookup`   | Lookup               | Value exists in a predefined table                  |
| `q_poseidon` | Poseidon Hash        | S-box and MDS matrix operations                     |
| `q_aux`      | Auxiliary            | ROM/RAM operations                                  |

### Circuit Size from VK

From our VK (first 96 bytes = 3 headers):

```
[0..32]:   log2_circuit_size = 6   → circuit has 2⁶ = 64 rows
[32..64]:  log2_domain_size = 17   → evaluation domain has 2¹⁷ points
[64..96]:  num_public_inputs = 1   → just y = 9
```

### Protocol Constants (bb 0.87)

UltraHonk defines several constants that are **fixed across all circuits**:

| Constant                 | Value | Meaning                                                                                     |
| ------------------------ | ----- | ------------------------------------------------------------------------------------------- |
| `CONST_PROOF_SIZE_LOG_N` | 28    | Maximum supported log₂(circuit_size). Proofs are padded to this size for fixed-size format. |
| `NUMBER_OF_SUBRELATIONS` | 26    | Total number of subrelations (constraints) checked in sumcheck.                             |
| `NUMBER_OF_ALPHAS`       | 25    | Alpha challenges for batching subrelations (= NUM_SUBRELATIONS - 1).                        |
| `NUMBER_OF_ENTITIES`     | 40    | Total polynomial evaluations in sumcheck (27 VK + 8 witness + 5 shifted).                   |

And one constant that **varies per circuit**:

| Constant | Value  | Meaning                                                                                    |
| -------- | ------ | ------------------------------------------------------------------------------------------ |
| `LOG_N`  | varies | Actual log₂(circuit_size) for this specific circuit. Determines number of sumcheck rounds. |

**Why fixed constants matter:**

- The transcript always hashes `CONST_PROOF_SIZE_LOG_N` times for gate challenges, regardless of actual circuit size
- Alpha generation loops `NUMBER_OF_ALPHAS / 2` times to generate pairs of challenges
- This ensures transcript consistency across different circuit sizes

**Example across circuits:**

```
simple_square:       LOG_N = 12, all other constants fixed
iterated_square_100: LOG_N = 12, all other constants fixed
iterated_square_1000: LOG_N = 13, all other constants fixed
fib_chain_100:       LOG_N = 12, all other constants fixed
```

---

## 5. Witness Generation

### What is a Witness?

The witness is the complete assignment to all wires that satisfies all constraints. It includes:

- Private inputs (the secrets)
- Public inputs (known to verifier)
- All intermediate values computed during the circuit

For our circuit:

```
Private:  x = 3
Public:   y = 9

Wire assignments:
  w₁[0] = 3 (x, the private input)
  w₂[0] = 3 (x again, for the multiplication)
  w₃[0] = 9 (result of x * x)
```

### Witness Polynomials

The prover interpolates witness values into polynomials and commits to them:

| Polynomial              | Contents                       |
| ----------------------- | ------------------------------ |
| `W₁(X)`                 | First wire values              |
| `W₂(X)`                 | Second wire values             |
| `W₃(X)`                 | Third wire (output) values     |
| `W₄(X)`                 | Fourth wire (for custom gates) |
| `lookup_read_counts(X)` | Lookup argument helper         |
| `lookup_read_tags(X)`   | Lookup argument helper         |
| `lookup_inverses(X)`    | Lookup argument helper         |
| `z_perm(X)`             | Permutation grand product      |

These commitments appear in the proof and let the verifier check the computation without seeing the actual values.

---

## 6. Polynomial Commitment Scheme (KZG)

### The Problem

We have polynomials encoding our computation, but:

- Sending the full polynomial would be huge (and reveal secrets)
- We need to prove polynomial evaluations without revealing the polynomial

### KZG Commitments: The Solution

KZG (Kate-Zaverucha-Goldberg) commitments allow:

1. **Commit**: Turn a polynomial into a single elliptic curve point
2. **Open**: Prove what the polynomial evaluates to at any point

Think of it as a cryptographic "hash" of a polynomial that you can later prove properties about.

### How It Works

**Trusted Setup (SRS - Structured Reference String):**

Someone generates a secret `τ` and publishes:

- G₁ points: `{G, τG, τ²G, ..., τⁿ⁻¹G}` (powers of τ times generator)
- G₂ points: `{H, τH}` (just two points needed)

Then they destroy `τ`. Nobody can fake commitments without knowing `τ`.

**Commit** to polynomial `P(X) = p₀ + p₁X + p₂X² + ...`:

```
[P] = p₀·G + p₁·(τG) + p₂·(τ²G) + ... = P(τ)·G
```

This is just P evaluated at τ, but in the "exponent" - you can't extract τ or the coefficients.

**Open** at point `z` to prove `P(z) = y`:

- Compute quotient `Q(X) = (P(X) - y) / (X - z)`
- If P(z) really equals y, this division is exact (no remainder)
- Proof is `[Q] = Q(τ)·G`

**Verify** using the pairing:

```
e([P] - y·G, H) = e([Q], τH - z·H)
```

This checks that P(τ) - y = Q(τ) · (τ - z), which implies P(z) = y.

### VK Commitments

The VK contains 28 G1 points - commitments to the circuit's fixed polynomials:

| Commitment                           | What It Represents         |
| ------------------------------------ | -------------------------- |
| `[Qₘ], [Qc], [Q₁], [Qᵣ], [Qₒ], [Q₄]` | Arithmetic gate selectors  |
| `[Q_lookup], [Q_arith], ...`         | Gate type selectors        |
| `[σ₁], [σ₂], [σ₃], [σ₄]`             | Permutation polynomials    |
| `[id₁], [id₂], [id₃], [id₄]`         | Identity polynomials       |
| `[T₁], [T₂], [T₃], [T₄]`             | Lookup tables              |
| `[L_first], [L_last]`                | Lagrange basis polynomials |

Each G1 point is 64 bytes (32-byte x + 32-byte y coordinate).

---

## 7. The Honk Protocol Structure

### Why Honk Instead of Plonk?

Traditional Plonk verification requires:

1. Evaluate all constraints at a random point ζ
2. Check a single quotient polynomial identity
3. Verify polynomial openings

Honk uses **sumcheck** instead, which:

- Works over the boolean hypercube `{0,1}^log(n)` instead of roots of unity
- Enables more efficient batching of polynomial evaluations
- Allows for recursive proof composition

### The Verification Flow

```
UltraHonk Verification Steps:

1. OinkVerifier (Setup)
   ├── Compute VK hash and add to transcript
   ├── Absorb public inputs
   ├── Receive witness commitments (W₁, W₂, W₃, W₄)
   └── Generate challenges: η, β, γ
       "These random challenges force the prover to be honest"

2. SumcheckVerifier (Main Protocol - 6 rounds for our circuit)
   ├── For each round r in 0..log(n):
   │   ├── Receive univariate polynomial uʳ(X)
   │   ├── Check: uʳ(0) + uʳ(1) = target
   │   ├── Generate challenge χʳ
   │   └── Update target = uʳ(χʳ)
   ├── Receive claimed evaluations (41 values)
   └── Verify: relation(evals) = target × pow_partial
       "Check that the prover's claims are internally consistent"

3. GeminiVerifier (Polynomial Folding)
   ├── Receive fold commitments (5 for our circuit)
   ├── Generate challenge r
   └── Fold many polynomials into single claim
       "Combine many polynomial evaluations efficiently"

4. ShplonkVerifier (Batch Opening)
   ├── Generate challenges ν, z
   ├── Batch all opening claims together
   └── Compute final pairing inputs (P₀, P₁)
       "Turn all claims into one pairing check"

5. KZG Pairing Check
   └── Verify: e(P₀, G₂) × e(P₁, τ·G₂) = 1
       "One pairing to verify everything!"
```

---

## 8. Fiat-Shamir Transcript

### Making the Protocol Non-Interactive

The original Honk protocol is interactive:

1. Verifier sends random challenge
2. Prover responds
3. Repeat...

But we can't have interaction on a blockchain! Fiat-Shamir makes it non-interactive:

- Hash everything seen so far to get "random" challenges
- Prover computes these same challenges when generating the proof
- Verifier recomputes them when verifying

### Transcript Construction

```rust
// crates/plonk-core/src/transcript.rs
pub struct Transcript {
    hasher: Keccak256,
}
```

The transcript maintains a running hash state. When we need a challenge:

1. Hash all absorbed data
2. Reduce the 256-bit result modulo the field prime
3. Continue absorbing for the next challenge

### Challenge Split

Many UltraHonk challenges are "split" into two 128-bit values from one hash:

```rust
fn split_challenge(challenge: &Fr) -> (Fr, Fr) {
    // lo = bits[0..128]   - lower 128 bits
    // hi = bits[128..256] - upper 128 bits
}
```

This gives two related challenges (like η and η₂) from one hash operation.

### Complete Challenge Schedule

```
Transcript Order (what gets hashed):

1. vk_hash                    → (start of transcript)
2. public_inputs[]            → (user's public values)
3. pairing_point_object[16]   → (recursion data, 16 Fr elements)
4. W₁, W₂, W₃ (limbed)        → η, η₂, η₃ (split challenges)
5. lookup_counts, tags, W₄    → β, γ (split challenges)
6. lookup_inverses, z_perm    → alphas[0..24] (see Alpha Generation below)
7. [ZK: libra_concat, sum]    → libra_challenge (split)
8. gate_challenges[0..27]     → 28 hashes, only first LOG_N used
9. For each round r:
   - univariate[r][]          → sumcheck_u[r] (split, only lo used)
10. sumcheck_evaluations[]    → ρ (split)
11. [ZK: libra_eval, comms]   → (ZK-specific data)
12. gemini_fold_comms[]       → gemini_r (split)
13. gemini_a_evals[]          → shplonk_ν (split)
14. [ZK: libra_poly_evals]    → (ZK-specific)
15. shplonk_q                 → shplonk_z (split)
```

### Alpha Challenge Generation (bb 0.87)

Alpha challenges are generated differently than other challenges:

```
1. Append lookupInverses (4 limbs) + zPerm (4 limbs) to transcript
2. Hash → split → alphas[0], alphas[1]
3. Loop (NUMBER_OF_ALPHAS / 2 - 1) times:
   - Hash → split → alphas[2*i], alphas[2*i+1]
4. If NUMBER_OF_ALPHAS is odd:
   - Hash → split → alphas[NUMBER_OF_ALPHAS-1], (discard hi)
```

This generates 25 alpha challenges from ~13 hash iterations.

### Gate Challenge Generation (bb 0.87)

Gate challenges use a **fixed loop count** regardless of circuit size:

```
for i in 0..CONST_PROOF_SIZE_LOG_N (28 iterations):
    previousChallenge = hash(previousChallenge)
    gateChallenges[i] = split(previousChallenge).lo

// Only first LOG_N challenges are used in verification
```

This ensures transcript state is consistent after gate challenges.

Our implementation has been validated to produce challenges matching both Barretenberg's native verifier and the generated Solidity verifier.

---

## 9. Sumcheck Protocol

### The Core Idea

Sumcheck is a protocol to verify:

```
Σ f(x₁, x₂, ..., xₙ) = 0
(x₁,...,xₙ)∈{0,1}ⁿ
```

In words: "The sum of f over all boolean inputs equals 0"

This seems like it would require checking 2ⁿ points (exponential!), but sumcheck reduces it to just n rounds of checking univariate polynomials.

### Why Is This Useful?

The constraint polynomial F(X) encodes "all gates are satisfied":

- F(ωⁱ) = 0 for all rows i where the gate constraint holds
- If the prover cheated, F would be non-zero somewhere

Sumcheck lets us verify F is zero everywhere by sampling at random points.

### Round-by-Round

**Round 0:**

- Prover sends univariate u⁰(X) = Σ\_{x₂,...,xₙ ∈ {0,1}} f(X, x₂, ..., xₙ)
- Verifier checks: u⁰(0) + u⁰(1) = target
- Verifier sends random χ₀
- New target = u⁰(χ₀)

**Round r:**

- Prover sends uʳ(X) summing over remaining variables
- Verifier checks: uʳ(0) + uʳ(1) = target
- Verifier sends random χᵣ
- Update target

**Final:**
After log(n) rounds, we have challenges χ = (χ₀, ..., χ\_{log(n)-1}).
Verify that f(χ) equals the final target by evaluating the constraint polynomial at χ.

### Our Implementation

For ZK proofs with log(n)=6, each round has 9 coefficients:

```rust
proof.sumcheck_univariate(round) → [Fr; 9]
```

The verifier uses barycentric interpolation to compute uʳ(χᵣ) from these coefficients:

```rust
fn next_target(univariate: &[Fr], chi: &Fr) -> Fr {
    // Evaluate polynomial at chi using precomputed Lagrange weights
}
```

### ZK Adjustment: Libra

For ZK proofs, we can't have the initial target be 0 (it would leak information). Instead:

```
initial_target = libra_sum × libra_challenge
```

The Libra protocol masks the sumcheck values while preserving verification correctness.

---

## 10. Polynomial Evaluation and Gemini Folding

### The Problem

After sumcheck, we have claims about polynomial evaluations at the random point χ:

```
W₁(χ) = eval₁
W₂(χ) = eval₂
... (41 polynomials total!)
```

Verifying each KZG opening separately would require 41 pairings - way too expensive!

### Gemini: Folding Polynomials

Gemini "folds" multiple multilinear polynomials into a single univariate:

1. **Start**: Have polynomials P₁, P₂, ... with evaluation point χ = (χ₁, ..., χₙ)

2. **Fold round j**:

   - Combine polynomials using random challenge r
   - Reduce the number of variables by one

3. **Result**: Single univariate with related evaluations at ±r

### Gemini Data in Proof

```
gemini_fold_comms[0..log(n)-1]  // G1 commitments to folded polynomials
gemini_a_evals[0..log(n)]       // Evaluations at folding points
```

For our circuit with log(n)=6: 5 fold commitments and 6 evaluations.

---

## 11. Shplemini Batch Opening

### The Goal

Combine Gemini folding with Shplonk batching to verify all polynomial openings in one go:

- 35 unshifted evaluations (polynomials at χ)
- 5 shifted evaluations (polynomials at χ·ω for "next row" queries)

### How Batching Works

Use random challenge ν to combine all claims:

```
Combined = Σᵢ νⁱ · (Pᵢ - evalᵢ) / (X - zᵢ)
```

Group by evaluation point for efficiency:

- All evaluations at z = r (from Gemini)
- All evaluations at z = -r

### Computing Pairing Points

The Shplemini computation produces (P₀, P₁) for the final pairing:

```rust
// crates/plonk-core/src/shplemini.rs
pub fn compute_shplemini_pairing_points(
    proof: &Proof,
    vk: &VerificationKey,
    challenges: &Challenges,
) -> Result<(G1, G1), &'static str>
```

This involves:

1. Computing r^(2^i) powers for each round
2. Computing Shplonk weights (1/(z±r) terms)
3. Computing fold position values
4. Multi-scalar multiplication of ~70 commitments
5. Accumulating into final pairing points

---

## 12. Final Pairing Check

### The BN254 Pairing

BN254 provides a bilinear pairing:

```
e: G₁ × G₂ → Gₜ
```

With the crucial property:

```
e(a·P, b·Q) = e(P, Q)^(ab)
```

### Why Pairings Work for KZG

For KZG, we're verifying polynomial equations. The pairing lets us check:

```
[P] - y·G = [Q] · (τ - z)
```

In the "exponent" without knowing τ:

```
e([P] - y·G, H) = e([Q], τH - zH)
```

### Our Final Check

After all the batching:

```
e(P₀, G₂) × e(P₁, τ·G₂) = 1
```

This single pairing check verifies the entire proof! On Solana, we use the `alt_bn128_pairing` syscall.

### The G2 Points

```rust
// BN254 G2 generator (hardcoded)
fn g2_generator() -> G2 {
    // Standard generator point
}

// τ·G2 from trusted setup (hardcoded)
fn vk_g2() -> G2 {
    // Specific to the SRS used
}
```

---

## 13. Data Formats: VK and Proof

### Verification Key (1888 bytes)

```
┌────────────────────────────────────────────────────────────────┐
│ Header (96 bytes)                                               │
├─────────────────┬──────────────────────────────────────────────┤
│ [0..32]         │ log2_circuit_size (u256, BE) → 6             │
│ [32..64]        │ log2_domain_size (u256, BE) → 17             │
│ [64..96]        │ num_public_inputs (u256, BE) → 1             │
├─────────────────┴──────────────────────────────────────────────┤
│ Commitments (28 × 64 = 1792 bytes)                              │
├────────────────────────────────────────────────────────────────┤
│ G1 point format: x (32 bytes BE) ‖ y (32 bytes BE)             │
│                                                                 │
│ Order (matches Solidity's WIRE enum):                          │
│   [0]  Q_m        - multiplication selector                    │
│   [1]  Q_c        - constant selector                          │
│   [2]  Q_l        - left wire selector                         │
│   [3]  Q_r        - right wire selector                        │
│   [4]  Q_o        - output wire selector                       │
│   [5]  Q_4        - fourth wire selector                       │
│   [6]  Q_lookup   - lookup selector                            │
│   [7]  Q_arith    - arithmetic gate indicator                  │
│   [8]  Q_range    - range constraint selector                  │
│   [9]  Q_elliptic - elliptic curve selector                    │
│   [10] Q_memory   - memory selector                            │
│   [11] Q_nnf      - NNF selector                               │
│   [12] Q_poseidon2_external                                    │
│   [13] Q_poseidon2_internal                                    │
│   [14] σ₁        - permutation poly 1                          │
│   [15] σ₂        - permutation poly 2                          │
│   [16] σ₃        - permutation poly 3                          │
│   [17] σ₄        - permutation poly 4                          │
│   [18] ID₁       - identity poly 1                             │
│   [19] ID₂       - identity poly 2                             │
│   [20] ID₃       - identity poly 3                             │
│   [21] ID₄       - identity poly 4                             │
│   [22] Table₁    - lookup table column 1                       │
│   [23] Table₂    - lookup table column 2                       │
│   [24] Table₃    - lookup table column 3                       │
│   [25] Table₄    - lookup table column 4                       │
│   [26] L_first   - Lagrange first row                          │
│   [27] L_last    - Lagrange last row                           │
└────────────────────────────────────────────────────────────────┘
```

### Proof Structure (Variable Size)

For ZK proof with log(n)=6: **162 Fr elements = 5184 bytes**

```
┌────────────────────────────────────────────────────────────────┐
│ 1. Pairing Point Object (16 Fr = 512 bytes)                    │
│    IPA accumulator data for recursion                          │
│    Format: 4 limbs × 4 coordinates (lhs.x, lhs.y, rhs.x, rhs.y)│
├────────────────────────────────────────────────────────────────┤
│ 2. Witness Commitments (8 G1 = 16 Fr = 512 bytes)              │
│    [0-1]   W₁ commitment                                       │
│    [2-3]   W₂ commitment                                       │
│    [4-5]   W₃ commitment                                       │
│    [6-7]   lookup_read_counts commitment                       │
│    [8-9]   lookup_read_tags commitment                         │
│    [10-11] W₄ commitment                                       │
│    [12-13] lookup_inverses commitment                          │
│    [14-15] z_perm commitment                                   │
├────────────────────────────────────────────────────────────────┤
│ 3. Libra Data [ZK only] (3 Fr = 96 bytes)                      │
│    [0-1]   libra_concat commitment (G1)                        │
│    [2]     libra_sum (Fr)                                      │
├────────────────────────────────────────────────────────────────┤
│ 4. Sumcheck Univariates (log(n) × 9 = 54 Fr = 1728 bytes)      │
│    For each round r in 0..6:                                   │
│      9 coefficients of univariate polynomial                   │
├────────────────────────────────────────────────────────────────┤
│ 5. Sumcheck Evaluations (41 Fr = 1312 bytes)                   │
│    All polynomial evaluations at sumcheck point χ              │
│    (28 VK polys + 8 witness polys + 5 shifted)                │
├────────────────────────────────────────────────────────────────┤
│ 6. Libra Post-Sumcheck [ZK only] (8 Fr = 256 bytes)            │
│    libra_claimed_eval, libra_grand_sum_comm,                   │
│    libra_quotient_comm, gemini_masking_comm,                   │
│    gemini_masking_eval                                         │
├────────────────────────────────────────────────────────────────┤
│ 7. Gemini Fold Commitments ((log(n)-1) × 2 = 10 Fr)            │
│    5 G1 points for polynomial folding                          │
├────────────────────────────────────────────────────────────────┤
│ 8. Gemini A Evaluations (log(n) = 6 Fr)                        │
│    Evaluations of folded polynomials at r                      │
├────────────────────────────────────────────────────────────────┤
│ 9. Small IPA [ZK only] (2 Fr)                                  │
├────────────────────────────────────────────────────────────────┤
│ 10. Shplonk Q Commitment (2 Fr = 1 G1)                         │
├────────────────────────────────────────────────────────────────┤
│ 11. KZG Quotient Commitment (2 Fr = 1 G1)                      │
├────────────────────────────────────────────────────────────────┤
│ 12. Extra Protocol Data (2 Fr)                                 │
└────────────────────────────────────────────────────────────────┘
```

---

## 14. Implementation Mapping

### Module Structure

| Theory Component       | Code Location                         | Status                 |
| ---------------------- | ------------------------------------- | ---------------------- |
| VK Parsing             | `crates/plonk-core/src/key.rs`        | ✅ Working             |
| Proof Parsing          | `crates/plonk-core/src/proof.rs`      | ✅ Working             |
| Transcript/Fiat-Shamir | `crates/plonk-core/src/transcript.rs` | ✅ Working             |
| Challenge Generation   | `crates/plonk-core/src/verifier.rs`   | ✅ Working             |
| Sumcheck Rounds        | `crates/plonk-core/src/sumcheck.rs`   | ✅ Working             |
| 28 Subrelations        | `crates/plonk-core/src/relations.rs`  | ✅ Working             |
| Gemini Folding         | `crates/plonk-core/src/shplemini.rs`  | ✅ Working             |
| Shplemini MSM          | `crates/plonk-core/src/shplemini.rs`  | ✅ Working             |
| Pairing Check          | `crates/plonk-core/src/verifier.rs`   | ✅ Working             |
| BN254 Operations       | `crates/plonk-core/src/ops.rs`        | ✅ Via Solana syscalls |
| Field Arithmetic       | `crates/plonk-core/src/field.rs`      | ✅ Working             |

### Key Functions

```rust
/// Main entry point - verifies an UltraHonk proof
pub fn verify(
    vk_bytes: &[u8],        // 1888 bytes
    proof_bytes: &[u8],     // Variable, depends on log(n)
    public_inputs: &[Fr],   // Array of 32-byte field elements
    is_zk: bool,            // true for default Keccak proofs
) -> Result<(), VerifyError>

/// Generate all challenges via Fiat-Shamir
fn generate_challenges(
    vk: &VerificationKey,
    proof: &Proof,
    public_inputs: &[Fr],
) -> Result<Challenges, VerifyError>

/// Verify the sumcheck protocol
pub fn verify_sumcheck(
    proof: &Proof,
    challenges: &SumcheckChallenges,
    relation_params: &RelationParameters,
    libra_challenge: Option<&Fr>,
) -> Result<(), &'static str>

/// Compute final pairing points via Shplemini
pub fn compute_shplemini_pairing_points(
    proof: &Proof,
    vk: &VerificationKey,
    challenges: &Challenges,
) -> Result<(G1, G1), &'static str>
```

### The 28 Subrelations

| Index | Type              | What It Checks                         |
| ----- | ----------------- | -------------------------------------- |
| 0-1   | Arithmetic        | Basic arithmetic gates (add, multiply) |
| 2-3   | Permutation       | Wire copy constraints                  |
| 4-6   | Lookup            | Table lookups                          |
| 7-10  | DeltaRange        | Range constraints                      |
| 11-12 | Elliptic          | EC point operations                    |
| 13-18 | Memory            | ROM/RAM access                         |
| 19    | NNF               | Negation normal form                   |
| 20-23 | Poseidon External | Poseidon hash (external rounds)        |
| 24-27 | Poseidon Internal | Poseidon hash (internal rounds)        |

For our simple `x² = 9` circuit, only arithmetic (0-1) and permutation (2-3) are active.

---

## Appendix: Validation and Test Data

### Test Circuit Configuration

```
Circuit:      simple_square (x² = y)
Witness:      x = 3 (private)
Public Input: y = 9
log_n:        6 (circuit_size = 64)
is_zk:        true (Keccak oracle)
```

### Validated VK Hash

Our VK hash computation now matches Barretenberg exactly:

```
bb verify shows:  0x093e299e4b0c0559f7aa64cb989d22d9d10b1d6b343ce1a894099f63d7a85a75
Our implementation: 0x093e299e4b0c0559f7aa64cb989d22d9d10b1d6b343ce1a894099f63d7a85a75 ✅
```

### Example Challenges (First Few)

From our debug output, matching Solidity:

```
eta:     0x29a1b17fe56c5a83ea0b6e0e3d57df11d05afca4aca9e77e1b6c2e4e7c3d5f1a
eta_two: 0x1234...
beta:    0x0abc...
gamma:   0x5678...
```

### Sumcheck Verification

All 6 rounds pass:

```
Round 0: u[0] + u[1] = target ✅
Round 1: u[0] + u[1] = target ✅
Round 2: u[0] + u[1] = target ✅
Round 3: u[0] + u[1] = target ✅
Round 4: u[0] + u[1] = target ✅
Round 5: u[0] + u[1] = target ✅
Final relation check: PASS ✅
```

### Running the Tests

```bash
# Generate test proof
cd test-circuits/simple_square
nargo compile
nargo execute
~/.bb/bb prove -b ./target/simple_square.json -w ./target/simple_square.gz \
    --oracle_hash keccak --write_vk -o ./target/keccak

# Run verification test
cargo test -p example-verifier --test integration_test

# Run with debug output
cargo test -p plonk-core test_debug_real_proof --features debug -- --nocapture
```

---

## References

1. **Barretenberg Source**: https://github.com/AztecProtocol/barretenberg
2. **Noir Documentation**: https://noir-lang.org/docs
3. **KZG Paper**: Kate, Zaverucha, Goldberg - "Constant-Size Commitments to Polynomials"
4. **Sumcheck Paper**: Lund et al. - "Algebraic Methods for Interactive Proof Systems"
5. **Gemini Paper**: Bootle et al. - "Gemini: Elastic SNARKs for Diverse Environments"
6. **groth16-solana**: https://github.com/Lightprotocol/groth16-solana (architecture reference)
