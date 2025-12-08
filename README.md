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

| Tool              | Version        | Notes                 |
| ----------------- | -------------- | --------------------- |
| Noir (nargo)      | 1.0.0-beta.15+ | UltraHonk support     |
| Barretenberg (bb) | 3.0.0+         | Auto-detected by bbup |
| Rust              | 1.75+          |                       |
| Solana SDK        | 3.0+           | BN254 syscalls        |

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
    --oracle_hash keccak \       # Use Keccak for Solana (~5KB proofs)
    --write_vk \
    -o ./target/keccak           # → proof, vk, public_inputs
```

#### 1.3 Verify with bb (Sanity Check)

```bash
~/.bb/bb verify -p ./target/keccak/proof -k ./target/keccak/vk --oracle_hash keccak
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
pub const PROOF_SIZE: usize = 5184;
pub const VK_SIZE: usize = 1888;
pub const VK_BYTES: [u8; 1888] = [ /* your circuit's VK */ ];
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

Barretenberg supports two oracle hash modes:

| Mode                | Proof Size | VK Size   | Use Case         |
| ------------------- | ---------- | --------- | ---------------- |
| Poseidon2 (default) | ~16 KB     | ~3.6 KB   | Recursive proofs |
| **Keccak**          | **~5 KB**  | **~2 KB** | **EVM/Solana** ✓ |

**Always use `--oracle_hash keccak` for Solana verification.**

## 🏗️ Project Structure

```
solana-noir-verifier/
├── crates/
│   ├── plonk-core/           # Core verifier library
│   │   ├── ops.rs            # BN254 ops via syscalls
│   │   ├── transcript.rs     # Fiat-Shamir (Keccak256)
│   │   ├── key.rs            # VK parsing
│   │   ├── proof.rs          # Proof parsing
│   │   └── verifier.rs       # Verification logic
│   └── vk-codegen/           # CLI: VK JSON → Rust constants
├── programs/
│   └── example-verifier/     # Solana program template
├── test-circuits/
│   └── simple_square/        # Example Noir circuit
└── tests/
    └── resources/            # Test vectors
```

## 🔧 Development

### Build

```bash
cargo build --workspace
```

### Test

```bash
# All tests
cargo test --workspace

# Integration tests only
cargo test -p example-verifier --test integration_test
```

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

## ⚠️ Current Status

**Work in Progress** - The e2e workflow is set up but verification logic is not complete.

### Completed ✅

- [x] Project structure and dependencies
- [x] BN254 operations via syscalls
- [x] Proof/VK parsing
- [x] Fiat-Shamir transcript (Keccak256)
- [x] Solana program template
- [x] E2E test harness

### TODO 🚧

- [ ] UltraHonk widget evaluations
- [ ] KZG pairing verification
- [ ] Full e2e proof verification

## 🔗 References

- [Noir Documentation](https://noir-lang.org/docs)
- [Barretenberg](https://barretenberg.aztec.network/docs/getting_started/)
- [groth16-solana](https://github.com/Lightprotocol/groth16-solana) - Groth16 verifier pattern
- [ultraplonk_verifier](https://github.com/zkVerify/ultraplonk_verifier) - UltraPlonk reference

## 📜 License

MIT OR Apache-2.0
