# Solana Noir Verifier - Implementation Tasks

## 🚨 Critical Discovery

**Noir 1.0 uses UltraHonk, NOT UltraPlonk!**

The `ultraplonk_verifier` reference is for an older system. We need to implement UltraHonk verification.

---

## E2E Workflow (Verified Working ✅)

```bash
# 1. Compile
nargo compile

# 2. Execute (generate witness)
nargo execute

# 3. Prove (USE KECCAK!)
~/.bb/bb prove -b ./target/circuit.json -w ./target/circuit.gz \
    --oracle_hash keccak --write_vk -o ./target/keccak

# 4. Verify externally
~/.bb/bb verify -p ./target/keccak/proof -k ./target/keccak/vk \
    --oracle_hash keccak

# 5. Solana test
cargo test -p example-verifier --test integration_test
```

### Proof Sizes

| Oracle     | Proof    | VK       | Use          |
| ---------- | -------- | -------- | ------------ |
| Poseidon2  | 16 KB    | 3.6 KB   | Recursive    |
| **Keccak** | **5 KB** | **2 KB** | **Solana** ✓ |

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
- [x] **Relations module (relations.rs): all 26 UltraHonk subrelations**
- [x] **Shplemini module (shplemini.rs): batch opening verification structure**

---

## In Progress 🚧

### UltraHonk Verification Implementation

- [x] VK parsing for bb 3.0 format
- [x] Proof parsing for bb 3.0 format (now variable-size!)
- [x] Field arithmetic (add, sub, mul, inv, div)
- [x] Fiat-Shamir transcript with Keccak256
- [x] Challenge split (lower/upper 128 bits) **FIXED! Was 127 bits, Solidity uses 128**
- [x] Public input delta calculation
- [x] **Understand proof format: variable size based on log_circuit_size**
- [x] **Proof DOES contain sumcheck data inline**
- [x] **Sumcheck round verification (barycentric interpolation)**
- [x] **All 6 sumcheck rounds pass!** Fixed challenge gen to match Solidity verifier
- [x] **All 26 subrelations implemented (relations.rs)**
- [x] **Shplemini structure implemented (shplemini.rs)**
- [x] **Pairing check wired up**
- [x] **📚 Theoretical documentation (docs/theory.md)**
- [x] **🧪 Validation script (scripts/validate_theory.py)**
- [ ] **Debug: validate challenges match bb exactly**
- [ ] **Full MSM computation in shplemini**
- [ ] **End-to-end verification passing**

### Debugging Priority (See docs/theory.md Section 13)

1. **Challenge Matching** - Most likely source of failures
   - VK hash computation
   - Transcript element ordering
   - Challenge split boundaries (127-bit)
2. **Sumcheck Verification** - Round-by-round check
   - Initial target for ZK = libra_sum × libra_challenge
   - Barycentric interpolation for next_target
3. **Relation Evaluation** - 26 subrelations
   - Arithmetic (0-1) and Permutation (2-3) are critical
   - Many others may be zero for simple circuits
4. **Shplemini MSM** - Final pairing point computation
   - Currently using simplified placeholder
   - Needs full ~70 commitment MSM

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

### Key Constants

```rust
CONST_PROOF_SIZE_LOG_N = 28
BATCHED_RELATION_PARTIAL_LENGTH = 8
NUMBER_OF_ENTITIES = 41
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

| Metric            | UltraHonk | Groth16                      |
| ----------------- | --------- | ---------------------------- |
| **Proof Size**    | ~5 KB     | **256 bytes** (20x smaller!) |
| **Solana CU**     | ~200-400K | **~200K**                    |
| **Trusted Setup** | Universal | Per-circuit                  |

### Files

- `experiments/groth16-alternative/gnark/` - Direct gnark implementation (✅ working)
- `experiments/groth16-alternative/noir-gnark/` - Noir → gnark backend (old Noir only)
- `experiments/groth16-alternative/solana-verifier/` - Solana verifier (all tests passing)
- `experiments/groth16-alternative/benchmarks/results.md` - Performance data

---

## Key References

- [Barretenberg Docs](https://barretenberg.aztec.network/docs/getting_started/)
- [bb source](https://github.com/AztecProtocol/barretenberg)
- [groth16-solana](https://github.com/Lightprotocol/groth16-solana)
- [noir_backend_using_gnark](https://github.com/lambdaclass/noir_backend_using_gnark) - Noir → gnark (old Noir)
- [zkVerify ultraplonk_verifier](https://github.com/zkVerify/ultraplonk_verifier) (for reference, different format)
