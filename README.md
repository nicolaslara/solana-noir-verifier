# Solana Noir Verifier

A circuit-specific verifier for [Noir](https://noir-lang.org/) proofs on Solana, using Solana's native BN254 syscalls.

## 🎯 Overview

This project enables verification of Noir zero-knowledge proofs on Solana. It targets Noir's [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) backend (UltraHonk) and uses Solana's `alt_bn128` syscalls for efficient on-chain verification.

### Key Features

- **Per-circuit verifiers**: Each circuit gets its own Solana program with embedded VK
- **Single code path**: Same verification code runs on-chain and in tests
- **Native syscalls**: Uses `solana-bn254` for BN254 curve operations
- **Keccak transcript**: Optimized for external verification (~5KB proofs)

## 🔄 How It Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           BUILD PHASE (once per circuit)                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. Compile Circuit       2. Generate VK           3. Build Verifier        │
│  ┌──────────────┐        ┌──────────────┐        ┌──────────────────┐      │
│  │  main.nr     │───────▶│  bb prove    │───────▶│  vk-codegen      │      │
│  │  (Noir)      │        │  --write_vk  │        │                  │      │
│  └──────────────┘        └──────────────┘        └────────┬─────────┘      │
│                                 │                         │                 │
│                                 ▼                         ▼                 │
│                          ┌──────────────┐        ┌──────────────────┐      │
│                          │  vk (2KB)    │───────▶│ Solana Program   │      │
│                          └──────────────┘        │ + embedded VK    │      │
│                                                  └──────────────────┘      │
│                                                           │                 │
└───────────────────────────────────────────────────────────┼─────────────────┘
                                                            │
                                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           RUNTIME (each verification)                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  4. User generates proof          5. Submit to on-chain verifier            │
│  ┌──────────────────┐            ┌──────────────────────────┐              │
│  │ bb prove         │            │  Transaction contains:   │              │
│  │ (off-chain)      │───────────▶│  - proof (~5KB)          │              │
│  └──────────────────┘            │  - public inputs         │              │
│         │                        └───────────┬──────────────┘              │
│         ▼                                    │                              │
│  ┌──────────────────┐                        ▼                              │
│  │ proof + inputs   │            ┌──────────────────────────┐              │
│  └──────────────────┘            │  Verifier checks proof   │              │
│                                  │  against embedded VK     │              │
│                                  │  → OK / Error            │              │
│                                  └──────────────────────────┘              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### What Gets Deployed?

| Artifact                 | Where               | When              |
| ------------------------ | ------------------- | ----------------- |
| **Solana Program (.so)** | On-chain            | Once per circuit  |
| VK (verification key)    | Embedded in program | Compiled in       |
| Proofs                   | Transaction data    | Each verification |
| Public inputs            | Transaction data    | Each verification |

### This Repo's Scope

- ✅ Circuit compilation and proof generation workflow
- ✅ VK codegen → Rust constants
- ✅ Verifier program template
- ✅ Local testing with `solana-program-test`
- ❌ Deployment to Solana (use `solana program deploy`)
- ❌ Client SDK for submitting proofs

## 🚀 Quick Start

### Prerequisites

```bash
# Noir toolchain
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup

# Barretenberg (bb) CLI
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash
bbup

# Rust + Solana
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Version Requirements

| Tool              | Version      | Notes                    |
| ----------------- | ------------ | ------------------------ |
| Noir (nargo)      | 1.0.0-beta.8 | UltraHonk/Keccak support |
| Barretenberg (bb) | 0.87.x       | Auto-detected by bbup    |
| Rust              | 1.75+        |                          |
| Solana SDK        | 3.0+         | BN254 syscalls           |

### First-Time Setup

After cloning the repo, rebuild all test circuits and run tests:

```bash
# 1. Build all test circuit proofs and VKs
cd test-circuits && ./build_all.sh && cd ..

# 2. Run tests (should see 58 passing)
cargo test

# 3. (Optional) Test on Surfpool local validator
cd programs/ultrahonk-verifier
CIRCUIT=simple_square cargo build-sbf
solana program deploy target/deploy/ultrahonk_verifier.so --url http://127.0.0.1:8899 --use-rpc
cd ../..
CIRCUIT=simple_square node scripts/solana/test_phased.mjs
```

## 📋 E2E Workflow

### Phase 1: Circuit Development & Proof Generation

#### 1.1 Create a Noir Circuit

```bash
mkdir -p test-circuits/my_circuit && cd test-circuits/my_circuit
nargo init
```

Edit `src/main.nr`:

```noir
// Prove we know x such that x * x == y
fn main(x: Field, y: pub Field) {
    assert(x * x == y);
}
```

Edit `Prover.toml` (test inputs for proof generation):

```toml
x = "3"
y = "9"
```

#### 1.2 Compile & Generate Proof

```bash
nargo compile                    # → target/my_circuit.json
nargo execute                    # → target/my_circuit.gz (witness)

~/.bb/bb prove \
    -b ./target/my_circuit.json \
    -w ./target/my_circuit.gz \
    --oracle_hash keccak \
    --zk \                       # Use ZK mode for Solana (~16KB proofs)
    -o ./target/keccak           # → proof, public_inputs

~/.bb/bb write_vk \
    -b ./target/my_circuit.json \
    --oracle_hash keccak \
    -o ./target/keccak           # → vk
```

#### 1.3 Verify with bb (Sanity Check)

```bash
~/.bb/bb verify -p ./target/keccak/proof -k ./target/keccak/vk --oracle_hash keccak --zk
# Expected: "Proof verified successfully"
```

---

### Phase 2: Generate Solana Verifier Program

#### 2.1 Generate VK Constants

The VK needs to be embedded in your Solana program as Rust constants:

```bash
# From repo root:
cargo run -p plonk-solana-vk-codegen -- \
    --vk ./test-circuits/my_circuit/target/keccak/vk \
    --proof ./test-circuits/my_circuit/target/keccak/proof \
    --public-inputs ./test-circuits/my_circuit/target/keccak/public_inputs \
    --output ./programs/my_circuit_verifier/src/vk.rs \
    --name my_circuit
```

This generates:

```rust
// programs/my_circuit_verifier/src/vk.rs
pub const NUM_PUBLIC_INPUTS: usize = 1;
pub const PROOF_SIZE: usize = 16224;  // ZK proof (fixed size in bb 0.87)
pub const VK_SIZE: usize = 1760;      // VK size
pub const VK_BYTES: [u8; 1760] = [ /* your circuit's VK */ ];
```

#### 2.2 Create Your Verifier Program

Copy `programs/example-verifier/` as a template:

```bash
cp -r programs/example-verifier programs/my_circuit_verifier
```

Include the generated `vk.rs` in your `lib.rs`:

```rust
mod vk;
use vk::{VK_BYTES, NUM_PUBLIC_INPUTS, PROOF_SIZE};
```

The program receives **proof + public inputs** in transaction data and verifies against the embedded VK.

---

### Phase 3: Local Testing (simulates on-chain)

```bash
cargo test -p my_circuit_verifier --test integration_test
```

This uses `solana-program-test` which runs your program with the same BN254 syscalls available on mainnet - identical behavior to on-chain execution.

---

### Phase 4: Deployment (out of scope for this repo)

```bash
# Build the BPF program
cargo build-sbf -p my_circuit_verifier

# Deploy to Solana (requires solana-cli + funded wallet)
solana program deploy target/deploy/my_circuit_verifier.so
# → Program ID: <your_program_id>
```

After deployment, users can submit verification transactions containing proof + public inputs.

---

### Quick Script

Run all of Phase 1 + 2.1 in one command:

```bash
./scripts/build-circuit-verifier.sh test-circuits/simple_square
```

## 📊 Proof Formats

Barretenberg 0.87 supports two oracle hash modes:

| Mode                | Proof Size   | VK Size   | Use Case         |
| ------------------- | ------------ | --------- | ---------------- |
| Poseidon2 (default) | ~16 KB       | ~3.6 KB   | Recursive proofs |
| **Keccak + ZK**     | **16,224 B** | **1,760** | **EVM/Solana** ✓ |

**Always use `--oracle_hash keccak --zk` for Solana verification.**

Note: bb 0.87 produces **fixed-size proofs** (16,224 bytes for ZK) regardless of circuit complexity. This is due to `CONST_PROOF_SIZE_LOG_N=28` padding.

## 🏗️ Project Structure

```
solana-noir-verifier/
├── crates/
│   ├── plonk-core/              # Core verifier library (56 tests ✅)
│   │   ├── ops.rs               # BN254 ops via syscalls
│   │   ├── transcript.rs        # Fiat-Shamir (Keccak256)
│   │   ├── key.rs               # VK parsing (1,760 byte format)
│   │   ├── proof.rs             # Proof parsing (16,224 byte format)
│   │   ├── sumcheck.rs          # Sumcheck protocol
│   │   ├── relations.rs         # 26 subrelations
│   │   ├── shplemini.rs         # Batch opening verification
│   │   └── verifier.rs          # Main verification logic
│   └── vk-codegen/              # CLI: VK JSON → Rust constants
├── programs/
│   ├── ultrahonk-verifier/      # Main Solana verifier program ✅
│   └── example-verifier/        # Solana program template
├── test-circuits/               # 7 verified circuits
│   ├── simple_square/           # Basic x² = y
│   ├── iterated_square_*/       # Scalability tests
│   ├── hash_batch/              # Blake3 hashing
│   └── merkle_membership/       # Merkle proofs
├── scripts/
│   └── solana/                  # Surfpool testing scripts
└── docs/
    ├── theory.md                # UltraHonk protocol docs
    ├── knowledge.md             # Implementation notes
    └── solana-testing.md        # On-chain testing guide
```

## 🔧 Development

### Build

```bash
cargo build --workspace
```

### Test

```bash
# Run all tests (58 tests across workspace)
cargo test

# Core library tests only
cargo test -p plonk-solana-core

# Test all 7 circuits with output
cargo test -p plonk-solana-core test_all_available_circuits -- --nocapture
```

### Rebuild Test Circuits

If you delete `target/` directories or want fresh proofs:

```bash
cd test-circuits

# Build all circuits
./build_all.sh

# Or build a specific circuit
./build_all.sh simple_square
./build_all.sh merkle_membership
```

This runs: `nargo compile` → `nargo execute` → `bb prove` → `bb write_vk`

### Test on Surfpool (Local Solana)

[Surfpool](https://github.com/txtx/surfpool) provides a local Solana validator for testing.

```bash
# 1. Start Surfpool (in separate terminal)
surfpool start

# 2. Build & deploy (circuit VK is embedded at compile time)
cd programs/ultrahonk-verifier
CIRCUIT=simple_square cargo build-sbf
solana program deploy target/deploy/ultrahonk_verifier.so --url http://127.0.0.1:8899 --use-rpc

# 3. Run verification test
cd ../..
CIRCUIT=simple_square node scripts/solana/test_phased.mjs
```

**Expected output:**

```
Phase 1 (Challenges): 287K CUs (1 TX)
Phase 2 (Sumcheck):   3.82M CUs (3 TXs)
Phase 3 (MSM):        2.48M CUs (4 TXs)
Phase 4 (Pairing):    55K CUs (1 TX)
Total: 6.64M CUs across 9 transactions
🎉 All phases passed! Verification complete.
```

### Multi-Circuit Support

The verifier embeds a circuit-specific VK at compile time. To verify different circuits:

```bash
# Build with specific circuit VK
cd programs/ultrahonk-verifier
CIRCUIT=hash_batch cargo build-sbf
solana program deploy target/deploy/ultrahonk_verifier.so --url http://127.0.0.1:8899 --use-rpc

# Test with matching circuit
CIRCUIT=hash_batch node scripts/solana/test_phased.mjs
```

**Available circuits:** `simple_square`, `iterated_square_100`, `iterated_square_1000`, `iterated_square_10k`, `fib_chain_100`, `hash_batch`, `merkle_membership`

**How it works:**

1. `build.rs` reads `CIRCUIT` env var (defaults to `simple_square`)
2. Copies VK from `test-circuits/$CIRCUIT/target/keccak/vk`
3. Embeds it in the program at `$OUT_DIR/vk.bin`

> **Production TODO:** Load VK from a Solana account instead of compile-time embedding to support any circuit without redeploying.

### Generate VK Constants

```bash
cargo run -p plonk-solana-vk-codegen -- \
    --input ./target/keccak/vk.json \
    --output ./generated_vk.rs
```

## 📖 Documentation

- [`SPEC.md`](./SPEC.md) - Detailed specification
- [`tasks.md`](./tasks.md) - Implementation progress
- [`docs/knowledge.md`](./docs/knowledge.md) - Implementation notes

## ✅ Current Status

**Complete!** End-to-end UltraHonk verification working with bb 0.87 / nargo 1.0.0-beta.8.

### Performance (simple_square, log_n=12)

| Metric               | Value            |
| -------------------- | ---------------- |
| Total CUs            | **6.64M**        |
| Transactions         | **9**            |
| Phase 1 (Challenges) | 287K CUs, 1 TX   |
| Phase 2 (Sumcheck)   | 3.82M CUs, 3 TXs |
| Phase 3 (MSM)        | 2.48M CUs, 4 TXs |
| Phase 4 (Pairing)    | 55K CUs, 1 TX    |

### Completed ✅

- [x] Project structure and dependencies
- [x] BN254 operations via syscalls
- [x] Proof/VK parsing (bb 0.87 format with limbed G1 points)
- [x] Fiat-Shamir transcript (Keccak256)
- [x] All 25 alpha challenges generation
- [x] Gate challenges (CONST_PROOF_SIZE_LOG_N iterations)
- [x] Sumcheck verification (all rounds)
- [x] All 26 subrelations (arithmetic, permutation, lookup, range, elliptic, aux, poseidon)
- [x] Shplemini batch opening verification
- [x] KZG pairing check
- [x] **58 unit tests passing**
- [x] **7 test circuits verified** (log_n from 12 to 18)
- [x] **Multi-transaction phased verification** (9 TXs total)
- [x] **Zero-copy proof parsing** (saves 16KB heap)

### Test Circuits Verified ✅

| Circuit              | log_n | Public Inputs | Status |
| -------------------- | ----- | ------------- | ------ |
| simple_square        | 12    | 1             | ✅     |
| iterated_square_100  | 12    | 1             | ✅     |
| iterated_square_1000 | 13    | 1             | ✅     |
| iterated_square_10k  | 14    | 1             | ✅     |
| fib_chain_100        | 12    | 1             | ✅     |
| hash_batch           | 17    | 32            | ✅     |
| merkle_membership    | 18    | 32            | ✅     |

## 🔗 References

- [Noir Documentation](https://noir-lang.org/docs)
- [Barretenberg](https://barretenberg.aztec.network/docs/getting_started/)
- [groth16-solana](https://github.com/Lightprotocol/groth16-solana) - Groth16 verifier pattern
- [ultraplonk_verifier](https://github.com/zkVerify/ultraplonk_verifier) - UltraPlonk reference

## 📜 License

MIT OR Apache-2.0
