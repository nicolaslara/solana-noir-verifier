# Solana Noir Verifier - Implementation Tasks

## ✅ Implementation Complete!

**December 2024:** Full UltraHonk verification working with bb 0.87 / nargo 1.0.0-beta.8.

| Metric        | Value                    |
| ------------- | ------------------------ |
| Unit Tests    | 56 passing               |
| Test Circuits | 7 verified               |
| Circuit Sizes | log_n 12-18              |
| Proof Size    | 16,224 bytes (fixed, ZK) |
| VK Size       | 1,760 bytes              |

---

## E2E Workflow (Verified Working ✅)

```bash
# 1. Compile
nargo compile

# 2. Execute (generate witness)
nargo execute

# 3. Prove (USE KECCAK + ZK!)
~/.bb/bb prove -b ./target/circuit.json -w ./target/circuit.gz \
    --scheme ultra_honk --oracle_hash keccak --zk -o ./target/keccak

# 4. Write VK
~/.bb/bb write_vk -b ./target/circuit.json \
    --scheme ultra_honk --oracle_hash keccak -o ./target/keccak

# 5. Verify externally
~/.bb/bb verify -p ./target/keccak/proof -k ./target/keccak/vk \
    --oracle_hash keccak --zk

# 6. Solana verifier test
cargo test -p plonk-solana-core
```

### Sizes (bb 0.87)

| Mode          | Proof      | VK        | Use          |
| ------------- | ---------- | --------- | ------------ |
| Poseidon2     | ~16 KB     | ~3.6 KB   | Recursive    |
| **Keccak+ZK** | **16,224** | **1,760** | **Solana** ✓ |

---

## Completed ✅

- [x] Study groth16-solana architecture
- [x] Study ultraplonk_verifier architecture
- [x] Update Solana deps to v3.x
- [x] Simplify project structure - single code path with solana-bn254
- [x] Clean up all Cargo.toml files
- [x] Create basic types (G1, G2, Scalar as byte arrays)
- [x] Implement ops module (g1_add, g1_mul, g1_msm, pairing_check)
- [x] Create Fiat-Shamir transcript (Keccak256)
- [x] All 14 unit tests passing
- [x] **Install Noir toolchain (nargo 1.0.0-beta.15)**
- [x] **Install Barretenberg CLI (bb 3.0.0)**
- [x] **Discover Noir 1.0 uses UltraHonk, not UltraPlonk**
- [x] **E2E workflow verified: nargo → bb → solana-program-test**
- [x] **Document workflow in README.md**
- [x] **Reverse engineer VK format (1888 bytes = 3 headers + 28 G1)**
- [x] **Understand proof format (variable size based on log_n)**
- [x] **Implement field arithmetic (Fr mod operations)**
- [x] **38 unit tests passing**
- [x] **E2E test running: program invoked, BN254 syscalls working**
- [x] **Sumcheck module (sumcheck.rs): round verification + relation accumulation**
- [x] **Relations module (relations.rs): all 28 UltraHonk subrelations**
- [x] **Shplemini module (shplemini.rs): batch opening verification structure**
- [x] **Fixed Wire enum indices to match Solidity (added QNnf, shifted indices)**
- [x] **Fixed NUM_SUBRELATIONS from 26 to 28**
- [x] **Fixed NUM_ALL_ENTITIES to 41 for both ZK and non-ZK**
- [x] **Fixed public_input_delta: uses SEPARATOR (1<<28) not circuit_size**
- [x] **Fixed subrelation index mapping (lookup 4-6, range 7-10, etc.)**
- [x] **Fixed split_challenge to 128-bit (matching Solidity)**
- [x] **Fixed public_inputs_delta offset (1, not 0)**
- [x] **Fixed Poseidon internal diagonal matrix constants**
- [x] **Implemented full Memory relation (subrel 13-18)**
- [x] **Implemented full NNF relation (subrel 19)**
- [x] **All 28 subrelations now match Solidity! ✅**
- [x] **SUMCHECK VERIFICATION PASSES! ✅**
- [x] **Fixed rho challenge generation (add ZK elements to transcript)**
- [x] **batchedEvaluation matches Solidity**
- [x] **P1 negation fixed (negate KZG quotient)**
- [x] **shplonk_nu challenge fixed (add libraPolyEvals to transcript)**
- [x] **constantTermAccumulator matches Solidity**
- [x] **Full P0 MSM computation matches Solidity**
- [x] **Pairing point aggregation (recursionSeparator, mulWithSeparator)**
- [x] **fr_reduce fixed (multi-subtract for values > 5r)**
- [x] **VK G2 point fixed (x·G2 from trusted setup, not G2 generator)**
- [x] **🎉 END-TO-END VERIFICATION PASSES! 🎉**

---

g## On-Chain Verification (In Progress)

### Challenge: BPF Compute Unit Limits

Solana has a **1.4M CU per-transaction limit**. UltraHonk verification requires splitting across multiple transactions.

### Completed ✅

- [x] Solana program deployed to Surfpool
- [x] Account-based proof storage (chunked upload)
- [x] Binary extended GCD for `fr_inv` (faster than Fermat's theorem)
- [x] Karatsuba multiplication (~12% CU reduction)
- [x] **Montgomery multiplication (~87% CU reduction, 7x faster!)** 🎉
- [x] Challenge generation split into 6 transactions (**~296K CUs total**):
  - Phase 1a: eta/beta/gamma (6K CUs)
  - Phase 1b: alphas + gates (15K CUs)
  - Phase 1c: sumcheck 0-13 (13K CUs)
  - Phase 1d: sumcheck 14-27 + final (24K CUs)
  - Phase 1e1: delta part 1 (**104K CUs** - was 915K!)
  - Phase 1e2: delta part 2 (**134K CUs** - was 1.07M!)

### In Progress 🔧

- [ ] Phase 2 (Sumcheck verification) - exceeds 1.4M CUs, needs splitting

### Pending ⏳

- [ ] Phase 3 (MSM computation) - not yet tested
- [ ] Phase 4 (Pairing check) - not yet tested

### Optimization Progress

| Optimization              | Status         | Improvement       |
| ------------------------- | -------------- | ----------------- |
| Karatsuba multiplication  | ✅ Implemented | -12% CUs          |
| Montgomery multiplication | ✅ Implemented | **-87% CUs (7x)** |
| Binary Extended GCD       | ✅ Implemented | Much faster inv   |
| BPF assembly              | ⏳ Pending     | Est. 2x more      |
| Solana syscall            | ⏳ Proposal    | Est. 10x more     |

See `docs/bpf-limitations.md` for detailed analysis.

---

## Completed ✅

### UltraHonk Verification Implementation

- [x] VK parsing for bb 3.0 format
- [x] Proof parsing for bb 3.0 format (now variable-size!)
- [x] Field arithmetic (add, sub, mul, inv, div)
- [x] Fiat-Shamir transcript with Keccak256
- [x] Challenge split (lower/upper 128 bits) **FIXED! Was 127 bits, Solidity uses 128**
- [x] Public input delta calculation **FIXED! Uses 1<<28 separator, not circuit_size**
- [x] **Understand proof format: variable size based on log_circuit_size**
- [x] **Proof DOES contain sumcheck data inline**
- [x] **Sumcheck round verification (barycentric interpolation)**
- [x] **All 6 sumcheck rounds pass!** Fixed challenge gen to match Solidity verifier
- [x] **All 28 subrelations implemented (relations.rs)** Updated from 26 to match Solidity
- [x] **Shplemini structure implemented (shplemini.rs)**
- [x] **Pairing check wired up**
- [x] **📚 Theoretical documentation (docs/theory.md)** - Updated with glossary, working status
- [x] **🧪 Validation script (scripts/validate_theory.py)**
- [x] **Challenge matching verified** - All challenges (eta, beta, gamma, alpha, etc.) correct
- [x] **Sumcheck rounds all pass** - 6/6 rounds verify correctly
- [x] **Final relation check passes** - grand_relation == target ✅
- [x] **Full MSM computation in shplemini** - All scalars and commitments match Solidity ✅
- [x] **End-to-end verification passing** - VERIFIED! ✅

### Verification Complete! 🎉

**Status:** Full UltraHonk verification working! ✅

**What works:**

- All 28 subrelation values match Solidity exactly
- grand_relation computation correct
- ZK adjustment applied correctly
- Rho challenge matches Solidity
- batchedEvaluation matches Solidity
- P1 correctly negated
- constantTermAccumulator matches Solidity
- Full P0 MSM computation matches Solidity
- Pairing point aggregation (recursionSeparator, mulWithSeparator)
- VK G2 point (x·G2 from trusted setup)
- **52 unit tests passing**

### Test Vectors ✅

**Source:** Our own `simple_square` test circuit (x² = y, witness x=3, public y=9)

| Test                            | Description                              | Status               |
| ------------------------------- | ---------------------------------------- | -------------------- |
| `test_valid_proof_verifies`     | Valid proof + correct public inputs      | ✅ Passes            |
| `test_tampered_proof_fails`     | Modified proof byte → VerificationFailed | ✅ Fails as expected |
| `test_wrong_public_input_fails` | Wrong public input → VerificationFailed  | ✅ Fails as expected |

**Reference implementations for additional test vectors:**

- **zkVerify ultrahonk_verifier** - Has hardcoded vectors but for LOG_N=28 (larger circuit)
- **yugocabrio ultrahonk-rust-verifier** - Same bb/nargo versions, can run their build script
- **Barretenberg C++** - Dynamic test generation only

### Variable Circuit Size Support ✅

Our implementation handles **variable-size proofs** based on the actual circuit's `log_n`, unlike some other verifiers that use fixed `CONST_PROOF_SIZE_LOG_N = 28`.

| log_n | Circuit Size | Proof Size (ZK) | Notes                    |
| ----- | ------------ | --------------- | ------------------------ |
| 6     | 64 rows      | 5,184 bytes     | Our `simple_square` test |
| 10    | 1,024 rows   | ~6 KB           | Small production circuit |
| 20    | 1M rows      | ~10 KB          | Large circuit            |
| 28    | 256M rows    | 13,632 bytes    | Maximum supported        |

### Test Circuit Suite (December 2024)

All circuits verified with `bb 0.87` (ZK proofs):

| Circuit                | ACIR Opcodes | n (circuit size) | log_n | Proof Size | Features             | Status |
| ---------------------- | ------------ | ---------------- | ----- | ---------- | -------------------- | ------ |
| `simple_square`        | 1            | 4,096            | 12    | 16,224     | Basic arithmetic     | ✅     |
| `iterated_square_100`  | 100          | 4,096            | 12    | 16,224     | 100 iterations       | ✅     |
| `iterated_square_1000` | 1,000        | 8,192            | 13    | 16,224     | 1k iterations        | ✅     |
| `iterated_square_10k`  | 10,000       | 16,384           | 14    | 16,224     | 10k iterations       | ✅     |
| `iterated_square_100k` | 100,000      | 131,072          | 17    | 16,224     | 100k iterations      | ⏭️     |
| `hash_batch`           | 2,112        | 131,072          | 17    | 16,224     | 32× blake3 + XOR     | ✅     |
| `merkle_membership`    | 2,688        | 262,144          | 18    | 16,224     | 16-level Merkle tree | ✅     |
| `fib_chain_100`        | 1            | 4,096            | 12    | 16,224     | Fibonacci chain      | ✅     |

**Key observations (bb 0.87):**

- ZK proof size is **constant** (16,224 bytes = 507 Fr) regardless of circuit complexity
- bb 0.87 uses fixed-size proofs padded to `CONST_PROOF_SIZE_LOG_N=28`
- Hash operations (blake3) expand circuit size significantly more than arithmetic
- `hash_batch` (2112 opcodes) → log_n=17, `merkle_membership` (2688 opcodes) → log_n=18

**Our implementation:**

- Handles both old (1,888-byte) and new (1,760-byte) VK formats
- Fixed-size proof parsing with limbed G1 point extraction
- All challenges match Solidity verifier exactly

### Completed Debugging (All Verified Correct) ✅

1. ✅ **Challenge generation** - All matches Solidity (25 alphas, 28 gate challenges)
2. ✅ **Wire enum indices** - All 40 match bb 0.87 Solidity WIRE enum
3. ✅ **NUM_SUBRELATIONS = 26, NUMBER_OF_ALPHAS = 25** (updated for bb 0.87)
4. ✅ **public_input_delta** - Uses circuit_size (N) as separator
5. ✅ **Sumcheck round verification** - All LOG_N rounds pass
6. ✅ **ZK adjustment formula** - Matches Solidity exactly
7. ✅ **All 26 Subrelations** - Full implementation
   - Arithmetic (0-1), Permutation (2-3), Lookup (4-5)
   - DeltaRange (6-9), Elliptic (10-11), Auxiliary (12-17)
   - Poseidon External (18-21), Poseidon Internal (22-25)
8. ✅ **Shplemini MSM** - Full ~70 commitment computation
   - batchedEvaluation matches Solidity
   - constantTermAccumulator with libraPolyEvals
   - All scalars match Solidity
9. ✅ **Final Pairing Check** - Uses correct G2 points

---

## ✅ RESOLVED: Proof Format Understanding

**Discovered Dec 2024:** The proof size is VARIABLE based on `log_circuit_size` from VK!

### Key Insight

The proof DOES contain sumcheck data - it's just sized for the actual circuit:

- For `log_n=6` (test circuit): **162 Fr = 5184 bytes** (ZK)
- For `log_n=28` (max size): **~382 Fr = ~12KB**

### Proof Structure (ZK, log_n=6)

| Component            | Size (Fr) | Calculation                  |
| -------------------- | --------- | ---------------------------- |
| Pairing Point Object | 16        | Fixed                        |
| Witness Commits      | 16        | 8 G1 × 2 Fr                  |
| Libra Concat + Sum   | 3         | ZK: 1 G1 + 1 Fr              |
| Sumcheck Univariates | 54        | log_n × 9 (ZK uses 9, not 8) |
| Sumcheck Evals       | 41        | NUM_ALL_ENTITIES (ZK)        |
| Libra + Masking      | 8         | ZK: various libra/masking    |
| Gemini Fold Commits  | 10        | (log_n - 1) × 2 Fr           |
| Gemini A Evals       | 6         | log_n Fr                     |
| Small IPA + Opening  | 8         | ZK extras + shplonk/kzg      |
| **TOTAL**            | **162**   | ✅ Matches actual proof      |

### Implementation

- `Proof::expected_size(log_n, is_zk)` - calculates correct size
- `Proof::from_bytes(bytes, log_n, is_zk)` - dynamic parsing
- Accessor methods for all proof components

---

## Reference Implementation

### yugocabrio/ultrahonk-rust-verifier

- **Status**: Core is `no_std` + `alloc` friendly ✅
- **BUT**: Uses arkworks types internally (G1Affine, ark_bn254::Fr)
- **Has**: Backend abstraction (`Bn254Ops` trait) for MSM/pairing
- **Expects**: Solidity JSON format (128-byte G1 + inline sumcheck)

### Options to Use yugocabrio

| Option              | Approach                             | Effort | Risk          |
| ------------------- | ------------------------------------ | ------ | ------------- |
| A. Fork and adapt   | Replace arkworks types with bytes    | High   | Medium        |
| B. Use as reference | Copy algorithm, keep our byte types  | Medium | Low           |
| C. Conversion layer | Convert arkworks ↔ bytes at boundary | Low    | High overhead |

**Decision**: Option B - use yugocabrio as algorithm reference, keep our byte-based types for Solana compatibility.

---

## Key Insights from yugocabrio

### Verification Flow

1. **Transcript** (`transcript.rs`): Keccak256 Fiat-Shamir

   - Absorbs: VK metadata, public inputs, pairing point object, commitments
   - Produces: eta, beta, gamma, alphas, gate challenges, sumcheck challenges, rho, gemini_r, shplonk_nu, shplonk_z

2. **Sumcheck** (`sumcheck.rs` + `relations.rs`)

   - `log_n` rounds (e.g., 6 for our test circuit, max 28)
   - 9 coefficients per round for ZK (8 for non-ZK)
   - 26 subrelations: arithmetic, permutation, lookup, range, elliptic, aux, poseidon
   - Barycentric interpolation for next_target

3. **Shplemini** (`shplemini.rs`)

   - Batched opening verification
   - 70 commitments in MSM
   - Fixed G2 points for pairing

4. **Final Check**
   - `pairing_check(p0, p1)` with fixed G2 constants

### Key Constants (bb 0.87)

```rust
CONST_PROOF_SIZE_LOG_N = 28
BATCHED_RELATION_PARTIAL_LENGTH = 8
ZK_BATCHED_RELATION_PARTIAL_LENGTH = 9
NUMBER_OF_ENTITIES = 40 (was 41)
NUMBER_OF_SUBRELATIONS = 26 (was 28)
NUMBER_OF_ALPHAS = 25 (was 27)
NUMBER_UNSHIFTED = 35
NUMBER_SHIFTED = 5
```

---

## Project Structure

```
solana-noir-verifier/
├── Cargo.toml                    # Workspace
├── README.md                     # Workflow documentation
├── SPEC.md                       # Original specification
├── tasks.md                      # This file
├── crates/
│   ├── plonk-core/              # Core verifier library
│   │   ├── field.rs             # Fr arithmetic ✅
│   │   ├── types.rs             # G1, G2, Scalar ✅
│   │   ├── ops.rs               # BN254 syscalls ✅
│   │   ├── transcript.rs        # Fiat-Shamir ✅
│   │   ├── key.rs               # VK parsing ✅
│   │   ├── proof.rs             # Proof parsing ✅
│   │   ├── verifier.rs          # Verification 🚧
│   │   ├── constants.rs         # Field constants ✅
│   │   └── errors.rs            # Error types ✅
│   └── vk-codegen/              # CLI for VK → Rust constants
├── programs/
│   └── example-verifier/        # Solana program
│       └── tests/
│           └── integration_test.rs  # E2E test ✅
├── test-circuits/
│   └── simple_square/           # Test circuit
│       └── target/keccak/       # Generated proof/VK ✅
└── docs/
    └── knowledge.md             # Implementation notes
```

---

---

## Groth16 Alternative Experiment ✅

See `experiments/groth16-alternative/` for a complete experiment comparing Groth16 to UltraHonk.

### Two Approaches Documented

| Approach         | Circuit Language | Status           | Best For                   |
| ---------------- | ---------------- | ---------------- | -------------------------- |
| **Direct gnark** | Go               | ✅ Working       | New projects, full control |
| **Noir → gnark** | Noir             | ⚠️ Old Noir only | Existing Noir codebases    |

### Key Results

| Metric             | UltraHonk | Groth16                        |
| ------------------ | --------- | ------------------------------ |
| **Proof Size**     | ~5 KB     | **256 bytes** (20x smaller!)   |
| **Solana CU**      | ~200-400K | **81K** (measured on Surfpool) |
| **Trusted Setup**  | Universal | Per-circuit                    |
| **1M constraints** | TBD       | **~4 seconds** proving time    |

### Files

- `experiments/groth16-alternative/gnark/` - Direct gnark implementation (✅ working)
- `experiments/groth16-alternative/noir-gnark/` - Noir → gnark backend (old Noir only)
- `experiments/groth16-alternative/solana-verifier/` - Solana verifier (all tests passing)
- `experiments/groth16-alternative/benchmarks/results.md` - Performance data

---

## zkVerify Compression Experiment 🚧

See `experiments/zkverify-compression/` for proof compression via zkVerify.

### Pipeline

```
Noir → UltraHonk proof → zkVerify → Groth16 receipt → Solana
```

### Why This Matters

| Aspect            | Direct UltraHonk | zkVerify Compression           |
| ----------------- | ---------------- | ------------------------------ |
| **Proof Size**    | ~5 KB            | **256 bytes**                  |
| **Solana CU**     | ~200-400K        | **~81K**                       |
| **Trusted Setup** | Universal        | Per-circuit (zkVerify handles) |
| **Latency**       | Instant          | ~minutes                       |
| **Noir Support**  | ✅ Full          | ✅ Full                        |

### Status

- [x] Set up experiment structure
- [x] Create sample Noir circuit
- [x] Create proof generation scripts
- [x] Create zkVerify submission scripts
- [x] Create Solana verification scripts
- [ ] Test end-to-end with zkVerify testnet
- [ ] Document aggregation receipt format
- [ ] Integrate with existing groth16-solana verifier

### Files

- `experiments/zkverify-compression/circuits/` - Noir circuits
- `experiments/zkverify-compression/scripts/` - Pipeline scripts
- `experiments/zkverify-compression/TESTING.md` - Step-by-step guide

---

## Key References

- [Barretenberg Docs](https://barretenberg.aztec.network/docs/getting_started/)
- [bb source](https://github.com/AztecProtocol/barretenberg)
- [groth16-solana](https://github.com/Lightprotocol/groth16-solana)
- [noir_backend_using_gnark](https://github.com/lambdaclass/noir_backend_using_gnark) - Noir → gnark (old Noir)
- [zkVerify ultraplonk_verifier](https://github.com/zkVerify/ultraplonk_verifier) (for reference, different format)
- [zkVerify Documentation](https://docs.zkverify.io) - Proof aggregation service
