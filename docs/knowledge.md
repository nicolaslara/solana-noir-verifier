# Knowledge Base - Solana Noir Verifier

This document captures learned insights, solutions, and important implementation details discovered during development.

**Status: ✅ Complete!** End-to-end UltraHonk verification working with bb 0.87 / nargo 1.0.0-beta.8.

---

## 🎉 Verification Complete!

**December 2024:** Full UltraHonk verification implemented and tested.

| Metric        | Value                          |
| ------------- | ------------------------------ |
| Unit Tests    | 56 passing                     |
| Test Circuits | 7 verified                     |
| Circuit Sizes | log_n 12-18 (4K to 256K gates) |
| Proof Size    | 16,224 bytes (fixed, ZK)       |
| VK Size       | 1,760 bytes                    |

---

## Toolchain Versions (Current)

```bash
$ nargo --version
nargo version = 1.0.0-beta.8

$ ~/.bb/bb --version
bb - 0.87.0
```

Note: Earlier versions (bb "3.0", nargo 1.0.0-beta.15) used different formats. We now target bb 0.87.x.

---

## Critical Discovery: UltraHonk, Not UltraPlonk

**Noir 1.0+ uses UltraHonk by default, NOT UltraPlonk!**

The `ultraplonk_verifier` reference we studied is for an older proof system. Noir 1.0 has migrated to UltraHonk.

| Aspect     | UltraPlonk (old) | UltraHonk (current) |
| ---------- | ---------------- | ------------------- |
| Proof size | ~2 KB            | 16,224 bytes (ZK)   |
| Transcript | Keccak256        | Poseidon2 or Keccak |
| bb scheme  | N/A (deprecated) | `ultra_honk`        |

## E2E Workflow (Verified Working)

```bash
# 1. Compile circuit
cd test-circuits/simple_square
nargo compile

# 2. Generate witness
nargo execute

# 3. Generate ZK proof (USE KECCAK + ZK for Solana!)
~/.bb/bb prove \
    -b ./target/simple_square.json \
    -w ./target/simple_square.gz \
    --scheme ultra_honk \
    --oracle_hash keccak \
    --zk \
    -o ./target/keccak

# 4. Generate verification key
~/.bb/bb write_vk \
    -b ./target/simple_square.json \
    --scheme ultra_honk \
    --oracle_hash keccak \
    -o ./target/keccak

# 5. Verify externally (sanity check)
~/.bb/bb verify \
    -p ./target/keccak/proof \
    -k ./target/keccak/vk \
    --oracle_hash keccak \
    --zk

# 6. Run Solana verifier tests
cargo test -p plonk-solana-core
```

---

## Oracle Hash Selection

bb supports three oracle hash modes:

| Mode       | Flag                     | Proof Size | Best For                     |
| ---------- | ------------------------ | ---------- | ---------------------------- |
| Poseidon2  | (default)                | ~16 KB     | Recursive proofs in circuits |
| **Keccak** | `--oracle_hash keccak`   | **~5 KB**  | **EVM/Solana verification**  |
| Starknet   | `--oracle_hash starknet` | ~5 KB      | Starknet verification        |

**Always use `--oracle_hash keccak` for Solana!**

- Smaller proofs (saves transaction space)
- Keccak is cheaper than Poseidon2 on Solana
- Transcript can use SHA3/Keccak256

---

## Architecture Decisions

### Single Code Path (from SPEC.md)

Following groth16-solana's pattern:

- Use `solana-bn254` syscalls everywhere
- Same code for on-chain and tests
- `solana-program-test` provides syscall stubs locally
- No arkworks in production code (only dev-dependencies)

### Per-Circuit Verifiers

Each circuit gets its own verifier program with embedded VK:

- Matches Barretenberg's Solidity verifier pattern
- Simpler security model
- Better compute efficiency

---

## Proof Format (UltraHonk bb 0.87 with Keccak + ZK)

Based on `bb prove --zk` output:

```
target/keccak/
├── proof           # 16,224 bytes - ZK proof (FIXED SIZE)
├── vk              # 1,760 bytes - verification key
└── public_inputs   # 32 bytes per input
```

### Key Discovery: Fixed-Size Proofs in bb 0.87

bb 0.87 produces **fixed-size proofs** padded to `CONST_PROOF_SIZE_LOG_N=28`, regardless of actual circuit size:

| Circuit Size | log_n | Proof Size | Notes |
| ------------ | ----- | ---------- | ----- |
| 4,096        | 12    | 16,224     | Fixed |
| 8,192        | 13    | 16,224     | Fixed |
| 262,144      | 18    | 16,224     | Fixed |

### bb 0.87 G1 Point Encoding (Limbed Format)

G1 points in bb 0.87 proofs use **128 bytes (4 × 32-byte limbs)**, not 64 bytes:

- Each coordinate (x, y) is split into 2 limbs
- Low limb: bits [0..128]
- High limb: bits [128..256]
- Total: 4 limbs × 32 bytes = 128 bytes per G1

### VK Structure (1,760 bytes for bb 0.87)

```
Header (32 bytes = 4 fields × 8 bytes):
  [0..8]:    circuit_size (u64 LE) → 4096
  [8..16]:   log_circuit_size (u64 LE) → 12
  [16..24]:  num_public_inputs (u64 LE) → 17
  [24..32]:  pub_inputs_offset (u64 LE) → 0

G1 Commitments (1728 bytes = 27 points × 64 bytes):
  27 selector/permutation polynomial commitments
  Each G1 point is 64 bytes: x (32 bytes BE) || y (32 bytes BE)
```

Note: bb 0.87 removed Q_NNF, reducing from 28 to 27 commitments.

### Proof Structure (FIXED SIZE: 16,224 bytes)

The proof contains 507 Fr elements = 16,224 bytes:

- Pairing point object (16 Fr)
- Witness commitments (32 Fr, as 8 G1 × 4 limbs)
- Libra data (5 Fr for ZK)
- Sumcheck univariates (252 Fr = 28 rounds × 9 coefficients)
- Sumcheck evaluations (40 Fr)
- Libra/Gemini/Shplonk data (remaining Fr)

### Reference Implementation: yugocabrio/ultrahonk-rust-verifier

Found a complete Rust UltraHonk verifier: https://github.com/yugocabrio/ultrahonk-rust-verifier

- Uses arkworks types internally (compute-heavy on Solana)
- Expects Solidity JSON format (128-byte G1 points)
- We use it as **algorithm reference only**, implementing with byte-based types

Verification algorithm structure:

1. **Transcript** (Keccak256-based Fiat-Shamir)
2. **Sumcheck** (26 subrelations + barycentric interpolation)
3. **Shplemini** (batched opening verification)
4. **Final pairing check**

---

## BN254 Syscall Usage

```rust
use solana_bn254::prelude::{
    alt_bn128_g1_addition_be,
    alt_bn128_g1_multiplication_be,
    alt_bn128_pairing_be,
};

// G1 addition: 128 bytes in (two G1), 64 bytes out
let result = alt_bn128_g1_addition_be(&[point_a, point_b].concat())?;

// Scalar mul: 96 bytes in (G1 + scalar), 64 bytes out
let result = alt_bn128_g1_multiplication_be(&[point, scalar].concat())?;

// Pairing: n * 192 bytes in, 32 bytes out (last byte = 1 if valid)
let result = alt_bn128_pairing_be(&pairing_input)?;
```

---

## Verification Algorithm Status

### All Complete! ✅

1. **Field Arithmetic** (`field.rs`) ✅

   - Fr add, sub, mul, neg, inv, div
   - 256-bit operations with proper mod r reduction
   - All tests passing

2. **Fiat-Shamir Transcript** (`transcript.rs`) ✅

   - Keccak256-based challenge generation
   - Split challenge (lower/upper 128 bits)
   - Limbed G1 point appending for bb 0.87 format
   - Deterministic and tested

3. **Proof/VK Parsing** (`proof.rs`, `key.rs`) ✅

   - VK: 1,760 bytes (32-byte header + 27 G1 commitments)
   - Proof: 16,224 bytes (fixed size for ZK in bb 0.87)
   - Supports both old (1,888 byte) and new (1,760 byte) VK formats
   - Dynamic parsing with limbed G1 point extraction

4. **BN254 Operations** (`ops.rs`) ✅

   - G1 add, mul, neg via syscalls
   - MSM (multi-scalar multiplication)
   - Pairing check with correct G2 points

5. **Challenge Generation** (`verifier.rs`) ✅

   - All challenges match Solidity exactly:
     - eta, eta_two, eta_three
     - beta, gamma
     - alphas[0..24] (25 challenges)
     - gate_challenges[0..27] (28 challenges, fixed loop)
     - sumcheck u_challenges
     - libra_challenge (ZK)
     - rho, gemini_r, shplonk_nu, shplonk_z

6. **Public Input Delta** ✅

   - Uses circuit_size (N) as separator (not 1<<28)
   - Handles pairing point object as part of public inputs
   - Formula matches Solidity's `computePublicInputDelta`

7. **Sumcheck Verification** (`sumcheck.rs`) ✅

   - Round-by-round verification passing (LOG_N rounds)
   - pow_partial computation correct
   - ZK adjustment formula correct
   - Batching formula correct (26 subrels, 25 alphas)
   - Final relation check passes!

8. **All 26 Subrelations** (`relations.rs`) ✅

   - Arithmetic (0-1): Basic gates
   - Permutation (2-3): Wire constraints
   - Lookup (4-5): Table lookups
   - DeltaRange (6-9): Range checks
   - Elliptic (10-11): EC operations
   - Auxiliary (12-17): ROM/RAM, non-native field
   - Poseidon External (18-21): Hash external rounds
   - Poseidon Internal (22-25): Hash internal rounds

9. **Shplemini Verification** (`shplemini.rs`) ✅

   - Full batchedEvaluation computation
   - constantTermAccumulator with libraPolyEvals
   - Full MSM for P0 computation (~70 commitments)
   - Correct P1 negation
   - All scalars match Solidity

10. **Final Pairing Check** ✅
    - Uses correct G2 points (G2 generator and x·G2 from trusted setup)
    - e(P0, G2) × e(P1, x·G2) = 1 verified

---

## 🔑 Critical Implementation Details

### Wire Enum Indices (bb 0.87 - MUST match Solidity exactly!)

```rust
// bb 0.87 Solidity verifier's WIRE enum order (40 entities, no Q_NNF):
Q_M = 0, Q_C = 1, Q_L = 2, Q_R = 3, Q_O = 4, Q_4 = 5, Q_LOOKUP = 6, Q_ARITH = 7,
Q_RANGE = 8, Q_ELLIPTIC = 9, Q_AUX = 10,
Q_POSEIDON2_EXTERNAL = 11, Q_POSEIDON2_INTERNAL = 12,
SIGMA_1 = 13, SIGMA_2 = 14, SIGMA_3 = 15, SIGMA_4 = 16,
ID_1 = 17, ID_2 = 18, ID_3 = 19, ID_4 = 20,
TABLE_1 = 21, TABLE_2 = 22, TABLE_3 = 23, TABLE_4 = 24,
LAGRANGE_FIRST = 25, LAGRANGE_LAST = 26,
W_L = 27, W_R = 28, W_O = 29, W_4 = 30, Z_PERM = 31,
LOOKUP_INVERSES = 32, LOOKUP_READ_COUNTS = 33, LOOKUP_READ_TAGS = 34,
W_L_SHIFT = 35, W_R_SHIFT = 36, W_O_SHIFT = 37, W_4_SHIFT = 38, Z_PERM_SHIFT = 39
```

### Subrelation Index Mapping (26 total for bb 0.87)

```
- Arithmetic (2): indices 0-1
- Permutation (2): indices 2-3
- Lookup (2): indices 4-5
- Range/DeltaRange (4): indices 6-9
- Elliptic (2): indices 10-11
- Auxiliary (6): indices 12-17
- Poseidon External (4): indices 18-21
- Poseidon Internal (4): indices 22-25
```

Note: bb 0.87 removed NNF relation, reducing from 28 to 26 subrelations.

### Constants from bb 0.87 Solidity

```
NUMBER_OF_ENTITIES = 40 (was 41)
NUMBER_OF_SUBRELATIONS = 26 (was 28)
NUMBER_OF_ALPHAS = 25 (was 27)
CONST_PROOF_SIZE_LOG_N = 28
ZK_BATCHED_RELATION_PARTIAL_LENGTH = 9
BATCHED_RELATION_PARTIAL_LENGTH = 8
```

### Public Input Delta Formula

```
numerator_acc = gamma + beta * (SEPARATOR + offset)  // NOT circuit_size!
denominator_acc = gamma - beta * (offset + 1)
// Then iterate over public_inputs and pairing_point_object
```

## Open Questions (All Resolved! ✅)

- [x] ~~UltraPlonk vs UltraHonk?~~ → **UltraHonk**
- [x] ~~Which oracle hash?~~ → **Keccak + ZK**
- [x] ~~Exact UltraHonk proof format structure~~ → **Fixed 16,224 bytes for bb 0.87**
- [x] ~~Complete challenge generation matching bb~~ → **All 25+ challenges match**
- [x] ~~Sumcheck relation evaluation~~ → **All 26 subrelations implemented**
- [x] ~~Shplemini batched opening verification~~ → **Full MSM computation working**
- [x] ~~Variable circuit size support~~ → **Tested log_n from 12 to 18**

---

## Transaction Size & Cost Model

### Core Constraints

| Constraint                    | Value                | Implication                           |
| ----------------------------- | -------------------- | ------------------------------------- |
| Max tx size                   | **1232 bytes** total | Proofs cannot fit in instruction data |
| Max account size              | ~10 MB               | Accounts are where proofs live        |
| UltraHonk proof size (Keccak) | ~5 KB                | Must be chunked across multiple txs   |

**Conclusion:** Proofs are always stored in accounts and streamed via chunked uploads, never passed directly in tx data.

### Proof Upload Pattern

```
1. Create proof account (program-owned, user pays rent)
2. Upload proof chunks via N small txs (~1KB instruction data each)
3. Call verify_and_execute (reads proof from account, verifies, executes state change)
4. Close proof account (refunds rent to user)
```

### Cost Breakdown

#### Rent-Exempt Deposit (the real cost)

Solana rent-exempt minimum: **~6960 lamports/byte** (2 years).

| Account Size | Rent Deposit | Notes                         |
| ------------ | ------------ | ----------------------------- |
| 8 KB         | ~0.056 SOL   | Tight fit for Keccak proofs   |
| 16 KB        | ~0.11 SOL    | Comfortable for most circuits |
| 32 KB        | ~0.22 SOL    | Large circuits / headroom     |
| 64 KB        | ~0.45 SOL    | Very large circuits           |

**Key point:** This is a _refundable deposit_, not a fee. User gets it back when account closes.

#### Transaction Fees (negligible)

- Base fee: **~0.000005 SOL per tx**
- For 1 init + 5 chunk uploads + 1 verify = 7 txs → **~0.000035 SOL**
- Orders of magnitude smaller than rent deposit
- Priority fees optional (only if you want faster inclusion)

### Safety Rules

1. **Proof accounts must be program-owned**

   - Only your program can write/resize/close
   - Users can't steal lamports locked as rent

2. **Users fund their own rent** (initial design)

   - DoS risk bounded: attackers must lock their own SOL
   - No griefing vector against protocol treasury

3. **Protocol-subsidized rent** (future optimization) requires:
   - Anti-spam stakes from users
   - Per-user reusable buffers (amortize rent across proofs)
   - Garbage collection for stale/abandoned accounts
   - Rate limiting per user/slot/epoch

### Design Recommendations

For MVP:

- User pays rent, gets full refund on successful verify + close
- Single-use proof accounts (simple, no state to track)
- ~16 KB account size (covers Keccak proofs with margin)

For production:

- Per-user reusable proof buffer PDA
- Protocol may front rent but requires small user stake
- GC bot reclaims abandoned buffers after timeout
- Consider rebates on successful proofs to improve UX

---

---

## ✅ RESOLVED: bb 3.0 Keccak Proof Format Understanding

**Discovered Dec 2024:** The proof size is VARIABLE based on `log_circuit_size`, NOT fixed at `CONST_PROOF_SIZE_LOG_N=28`.

### Key Insight

The proof DOES contain inline sumcheck data! It's just sized for the actual circuit, not the maximum.

- For our test circuit with `log_n=6`: proof is 5184 bytes (162 Fr elements)
- If we had `log_n=28`: proof would be ~12KB

### Proof Structure (for log_n=6, ZK flavor)

| Component              | Size (Fr) | Notes                     |
| ---------------------- | --------- | ------------------------- |
| Pairing Point Object   | 16        | Always 16 Fr              |
| Witness Commitments    | 16        | 8 G1 = 16 Fr              |
| Libra Concat Commit    | 2         | ZK only: 1 G1 = 2 Fr      |
| Libra Sum              | 1         | ZK only                   |
| Sumcheck Univariates   | 54        | log_n × 9 (ZK) = 6 × 9    |
| Sumcheck Evaluations   | 41        | NUM_ALL_ENTITIES (ZK)     |
| Libra Eval             | 1         | ZK only                   |
| Libra Grand Sum Commit | 2         | ZK only: 1 G1 = 2 Fr      |
| Libra Quotient Commit  | 2         | ZK only: 1 G1 = 2 Fr      |
| Gemini Masking Commit  | 2         | ZK only: 1 G1 = 2 Fr      |
| Gemini Masking Eval    | 1         | ZK only                   |
| Gemini Fold Commits    | 10        | (log_n - 1) G1 = 5 × 2    |
| Gemini A Evals         | 6         | log_n Fr                  |
| Small IPA Evals        | 2         | ZK only                   |
| Shplonk Q + KZG W      | 4         | 2 G1 = 4 Fr               |
| Extra (protocol data)  | 2         | Observed in actual proofs |
| **TOTAL**              | **162**   | = 5184 bytes ✓            |

### Why bb Native Verifier Works

The bb native verifier uses `transcript->load_proof(proof)` which correctly parses the variable-size proof.
The sumcheck data IS inline - it's just sized for the specific circuit.

### Solidity Verifier Difference

The Solidity verifier expects PADDED proofs with `log_n=28` for gas-efficient fixed-size loops.
This is why it expects ~12-14KB. For on-chain verification, we can either:

1. Pad proofs to max size (wastes space)
2. Use variable-size verification (our approach)

### Implementation Update

We've updated the proof parser to handle variable-size proofs:

- `Proof::expected_size(log_n, is_zk)` calculates correct size
- `Proof::from_bytes(bytes, log_n, is_zk)` parses dynamically
- Accessor methods for all proof components

---

## 🚧 Transcript Encoding (In Progress)

### Key Discoveries

1. **G1 Point Encoding**: bb uses 136-bit limb split encoding in transcript

   - Each coordinate (x, y) is split into (lo, hi) where lo = coord mod 2^136
   - Total: 4 × 32 bytes = 128 bytes per G1 point in transcript
   - NOT raw 64-byte encoding!

2. **VK Hash**: Added to transcript first (before public inputs)

   - bb uses `vk->hash_with_origin_tagging(domain_separator, *transcript)`
   - Our computed hash doesn't match bb's yet

3. **ZK Initial Target**: For ZK proofs:
   - Initial sumcheck target = `libra_sum * libra_challenge`
   - libra_challenge is generated AFTER adding libra_concat and libra_sum

### What bb's Oink Verifier Does

```
1. Compute VK hash and add to transcript
2. Receive circuit_size, public_inputs_size
3. Receive public inputs
4. Receive pairing_point_object (16 Fr)
5. Receive w1, w2, w3 commitments
6. Generate eta challenges (split)
7. Receive lookup_read_counts, lookup_read_tags, w4
8. Generate beta, gamma (split)
9. Receive lookup_inverses, z_perm
10. Generate alpha
11. [ZK] Receive libra_concat, libra_sum; generate libra_challenge
12. Generate gate challenges (28 rounds)
13. For each round: add univariates, generate sumcheck_u challenge
14. Add sumcheck evaluations, generate rho
15. Add gemini fold commitments, generate gemini_r
16. Add gemini_a evaluations, generate shplonk_nu
17. Add shplonk_q, generate shplonk_z
```

### Remaining Work

- **🚨 CRITICAL: Fix VK hash computation** - See finding below
- Verify all transcript fields are in correct order
- Verify encoding of all fields matches bb

---

## 🚨 CRITICAL: VK Hash Mismatch (Dec 2024)

**Discovery:** Running `bb verify -d ...` shows the actual VK hash used internally:

```bash
bb verify -d -p ./target/keccak/proof -k ./target/keccak/vk \
  -i ./target/keccak/public_inputs --oracle_hash keccak

# Output includes:
# vk hash in Oink verifier: 0x093e299e4b0c0559f7aa64cb989d22d9d10b1d6b343ce1a894099f63d7a85a75
```

**Our computed value is DIFFERENT:**

```
Our compute_vk_hash():    0x208bd97838d91de580261bed943ed295c712c7fb7851189c7dedae7473606d1d
bb's actual vk hash:      0x093e299e4b0c0559f7aa64cb989d22d9d10b1d6b343ce1a894099f63d7a85a75
```

**Impact:** This is the ROOT CAUSE of all verification failures. The VK hash is the first thing added to the transcript, so if it's wrong, ALL subsequent challenges (η, β, γ, α, etc.) will be wrong.

**Next Steps:**

1. Study bb's source code for VK hash computation
2. Look at generated Solidity verifiers for reference
3. The hash likely includes different field encoding or additional metadata

---

## Changelog

| Date     | Discovery                                                           |
| -------- | ------------------------------------------------------------------- |
| Dec 2024 | Found ultraplonk_verifier - but it's for OLD system                 |
| Dec 2024 | **Noir 1.0 uses UltraHonk, not UltraPlonk**                         |
| Dec 2024 | Keccak oracle produces ~5KB proofs (vs 16KB Poseidon2)              |
| Dec 2024 | E2E workflow verified: nargo → bb → solana-program-test             |
| Dec 2024 | Solana SDK v3.x has stable BN254 syscalls                           |
| Dec 2024 | Documented tx size limits, rent costs, chunked upload pattern       |
| Dec 2024 | VK format: 3 headers + 28 G1 points (1888 bytes)                    |
| Dec 2024 | Implemented field arithmetic with all tests passing                 |
| Dec 2024 | E2E test running: program invoked, BN254 syscalls working           |
| Dec 2024 | yugocabrio verifier: no_std OK but uses arkworks (use as reference) |
| Dec 2024 | **Proof format: variable size based on log_n, sumcheck included!**  |
| Dec 2024 | Implemented dynamic proof parser with size calculation              |
| Dec 2024 | **G1 uses 136-bit split in transcript (128 bytes, not 64!)**        |
| Dec 2024 | **ZK initial target = libra_sum × libra_challenge**                 |
| Dec 2024 | **VK hash must be added to transcript first**                       |
| Dec 2024 | 📚 Created docs/theory.md - complete UltraHonk theory walkthrough   |
| Dec 2024 | 🧪 Created scripts/validate_theory.py - proof data validation       |
| Dec 2024 | **🔧 SUMCHECK CHALLENGE GENERATION FIXED!**                         |
|          | Bug 1: split_challenge used 127 bits, Solidity uses 128 bits        |
|          | Bug 2: We cached hi for odd rounds, Solidity discards hi every time |
|          | All 6 sumcheck rounds now pass!                                     |
| Dec 2024 | **✅ FULL SUMCHECK VERIFICATION PASSES!**                           |
|          | Fixed: public_inputs_delta offset (1 not 0)                         |
|          | Fixed: Poseidon internal diagonal matrix constants                  |
|          | Fixed: Memory relation (subrel 13-18) - full implementation         |
|          | Fixed: NNF relation (subrel 19) - full implementation               |
|          | All 28 subrelations now match Solidity!                             |
| Dec 2024 | **🔧 Rho challenge generation fixed for ZK proofs**                 |
|          | Must append: libra_eval, libra_comms[1,2], geminiMaskingPoly/Eval   |
|          | Rho now matches Solidity exactly!                                   |
| Dec 2024 | **✅ Shplemini/KZG verification complete!**                         |
|          | batchedEvaluation matches Solidity                                  |
|          | P1 negation fixed (negate KZG quotient)                             |
|          | constantTermAccumulator matches Solidity (with libraPolyEvals)      |
|          | Full P0 MSM with all commitments implemented                        |
|          | Pairing point aggregation with recursionSeparator                   |
|          | VK G2 point (x·G2 from trusted setup, not G2 generator)             |
| Dec 2024 | **🎉 END-TO-END VERIFICATION PASSES!**                              |
|          | 52 unit tests passing                                               |
|          | Test vectors: valid proof, tampered proof, wrong public input       |
|          | All verification steps match Solidity verifier exactly              |
| Dec 2024 | **🔄 Upgraded to bb 0.87 / nargo 1.0.0-beta.8**                     |
|          | VK format changed: 1,760 bytes (27 G1, no Q_NNF)                    |
|          | Proof format: Fixed 16,224 bytes with limbed G1 encoding            |
|          | Constants changed: 26 subrels, 25 alphas, 40 entities               |
|          | Gate challenges: Fixed 28 iterations (CONST_PROOF_SIZE_LOG_N)       |
| Dec 2024 | **✅ ALL 7 TEST CIRCUITS VERIFIED!**                                |
|          | simple_square, iterated_square_100/1000/10k, fib_chain_100          |
|          | hash_batch (log_n=17), merkle_membership (log_n=18)                 |
|          | 56 unit tests passing                                               |
| Dec 2024 | **🚀 ON-CHAIN VERIFICATION (Surfpool)**                             |
|          | Phase 1 (Challenges): 296K CUs in 6 TXs ✅                          |
|          | Phase 2 (Sumcheck): 5.1M CUs in 7 TXs ✅                            |
|          | Phase 3 (MSM): >1.4M CUs - needs splitting                          |
|          | Batch inversion: **38% savings** (1,065K → 655K CUs per 2 rounds)   |

---

## Optimization Resources

For CU reduction strategies, see **[`docs/suggested-optimizations.md`](./suggested-optimizations.md)**:

| Optimization                     | Status  | Impact                     |
| -------------------------------- | ------- | -------------------------- |
| Montgomery multiplication        | ✅ Done | **7x faster** field muls   |
| Batch inversion (sumcheck)       | ✅ Done | **38% savings** per round  |
| Precompute I_FR constants        | ✅ Done | Avoids fr_from_u64         |
| Binary Extended GCD              | ✅ Done | Faster inversions          |
| **Batch inversion (Shplemini)**  | ⏳ Next | Est. 60-130K CUs savings   |
| **Precompute rho powers**        | ⏳ Next | Est. 150K CUs savings      |

**Current bottleneck:** Phase 3 (Shplemini MSM) exceeds 1.4M CUs.
Target the next two optimizations to reduce Phase 3 enough to fit or minimize splits.
