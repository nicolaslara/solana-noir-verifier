# Knowledge Base - Solana Noir Verifier

This document captures learned insights, solutions, and important implementation details discovered during development.

---

## 🚨 Critical Discovery: UltraHonk, Not UltraPlonk

**Noir 1.0+ uses UltraHonk by default, NOT UltraPlonk!**

The `ultraplonk_verifier` reference we studied is for an older proof system. Noir 1.0 has migrated to UltraHonk.

| Aspect     | UltraPlonk (old) | UltraHonk (current) |
| ---------- | ---------------- | ------------------- |
| Proof size | ~2 KB            | ~5-16 KB            |
| Transcript | Keccak256        | Poseidon2 or Keccak |
| bb scheme  | N/A (deprecated) | `ultra_honk`        |

**Key implications:**

- Our proof/VK parsing code needs updating for UltraHonk format
- The test resources from `ultraplonk_verifier` are incompatible
- We need to study UltraHonk verification, not UltraPlonk

---

## E2E Workflow (Verified Working)

### Toolchain Versions

```bash
$ nargo --version
nargo version = 1.0.0-beta.15

$ ~/.bb/bb --version
3.0.0-nightly.20251104
```

### Complete Workflow

```bash
# 1. Compile circuit
cd test-circuits/simple_square
nargo compile

# 2. Generate witness
nargo execute

# 3. Generate proof (USE KECCAK for Solana!)
~/.bb/bb prove \
    -b ./target/simple_square.json \
    -w ./target/simple_square.gz \
    --oracle_hash keccak \
    --write_vk \
    -o ./target/keccak

# 4. Verify externally
~/.bb/bb verify \
    -p ./target/keccak/proof \
    -k ./target/keccak/vk \
    --oracle_hash keccak

# 5. Run Solana tests
cargo test -p example-verifier --test integration_test
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

## Proof Format (UltraHonk with Keccak)

Based on `bb prove` output:

```
target/keccak/
├── proof           # 5184 bytes - the proof
├── vk              # 1888 bytes - verification key
├── public_inputs   # 32 bytes per input
└── vk_hash         # 32 bytes - hash of VK
```

### ⚠️ Format Difference: Binary vs Solidity

**bb outputs two different formats:**

| Format        | Size        | G1 Encoding | Purpose            |
| ------------- | ----------- | ----------- | ------------------ |
| Binary        | 5184 bytes  | 64 bytes    | Our proof files    |
| Solidity/JSON | 14592 bytes | 128 bytes   | EVM verifier input |

The Solidity format uses limb splitting (136-bit low, ≤118-bit high) for each coordinate, resulting in 4 × 32 = 128 bytes per G1 point. Our binary format uses standard BN254 encoding (32 bytes per coordinate).

### VK Structure (1888 bytes)

```
Header (96 bytes = 3 fields × 32 bytes):
  [0..32]:   log2_circuit_size (as big-endian u256, value in last 4 bytes)
  [32..64]:  log2_domain_size  (as big-endian u256)
  [64..96]:  num_public_inputs (as big-endian u256)

G1 Commitments (1792 bytes = 28 points × 64 bytes):
  28 selector/permutation polynomial commitments
  Each G1 point is 64 bytes: x (32 bytes BE) || y (32 bytes BE)
```

### Proof Structure (VARIABLE SIZE)

> **Note:** We initially misunderstood this as fixed 81 chunks. See "RESOLVED: Proof Format" section below for correct understanding.

The proof size depends on `log_circuit_size` from the VK:

- For `log_n=6` (test circuit): 162 Fr = **5184 bytes**
- For `log_n=28` (max): ~382 Fr = **~12KB**

The proof contains: pairing_point_object + commitments + sumcheck_univariates + sumcheck_evaluations + gemini_data + opening_proofs

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

### Implemented ✅

1. **Field Arithmetic** (`field.rs`)

   - Fr add, sub, mul, neg, inv, div
   - 256-bit operations with proper mod r reduction
   - All tests passing

2. **Fiat-Shamir Transcript** (`transcript.rs`)

   - Keccak256-based challenge generation
   - Split challenge (lower/upper 128 bits)
   - Deterministic and tested

3. **Proof/VK Parsing** (`proof.rs`, `key.rs`)

   - VK: 1888 bytes (3 header fields + 28 G1 commitments)
   - Proof: Variable size based on `log_n` from VK
   - Dynamic parser: `Proof::from_bytes(bytes, log_n, is_zk)`

4. **BN254 Operations** (`ops.rs`)
   - G1 add, mul, neg via syscalls
   - MSM (multi-scalar multiplication)
   - Pairing check

### In Progress 🚧

5. **Challenge Generation** (`verifier.rs`)

   - Basic structure implemented
   - Needs exact match with bb's transcript

6. **Public Input Delta**
   - Formula implemented
   - Needs verification against bb

### Pending ❌

7. **Sumcheck Verification**

   - Currently returns `Ok(true)` (placeholder)
   - Need to implement relation evaluation

8. **Shplemini Verification**

   - Batched opening proof
   - Final pairing point computation

9. **Complete Pairing Check**
   - Currently uses placeholder points
   - Need proper batched claim aggregation

## Open Questions

- [x] ~~UltraPlonk vs UltraHonk?~~ → **UltraHonk**
- [x] ~~Which oracle hash?~~ → **Keccak**
- [x] ~~Exact UltraHonk proof format structure~~ → **Documented above**
- [ ] Complete challenge generation matching bb
- [ ] Sumcheck relation evaluation
- [ ] Shplemini batched opening verification

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

- Fix VK hash computation to match bb's exactly
- Verify all transcript fields are in correct order
- Verify encoding of all fields matches bb

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
