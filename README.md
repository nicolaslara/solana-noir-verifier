# Solana Noir Verifier

A **circuit-agnostic** verifier for [Noir](https://noir-lang.org/) proofs on Solana, using Solana's native BN254 syscalls.

## 🎯 Overview

This project enables verification of Noir zero-knowledge proofs on Solana. It targets Noir's [Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) backend (UltraHonk) and uses Solana's `alt_bn128` syscalls for efficient on-chain verification.

### Key Features

- **Circuit-agnostic**: One deployed verifier supports ANY UltraHonk circuit
- **VK as account**: Upload your VK once, reuse for all proofs
- **CLI & SDKs**: Easy integration via Rust CLI, TypeScript SDK, or Rust SDK
- **Verification receipts**: On-chain proof that verification succeeded (for CPI)
- **Native syscalls**: Uses `solana-bn254` for BN254 curve operations

---

## 📋 Version Compatibility

| Tool              | Version        | Notes                        |
| ----------------- | -------------- | ---------------------------- |
| Noir (nargo)      | 1.0.0-beta.8   | UltraHonk/Keccak support     |
| Barretenberg (bb) | 0.87.x         | Auto-installed by `bbup`     |
| Rust              | 1.75+          | Stable                       |
| Solana SDK        | 3.0+           | BN254 syscalls               |

**Important:** `bbup` auto-detects your nargo version and installs the compatible bb. Install nargo first:

```bash
# Install Noir (pinned version)
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup -v 1.0.0-beta.8

# Install Barretenberg (auto-detects compatible version)
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash
bbup

# Install Solana CLI
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
```

---

## 🚀 Quick Start with CLI

### Install

```bash
cargo install --path crates/rust-sdk --features cli
```

### Deploy & Verify

```bash
# 1. Start local validator
surfpool  # or: solana-test-validator

# 2. Deploy verifier (one-time, circuit-agnostic)
noir-solana deploy --network localnet
# → Program ID: 7sfMWfVs6P1ACjouyvRwWHjiAj6AsFkYARP2v9RBSSoe

# 3. Upload your circuit's VK
noir-solana upload-vk \
    --vk ./target/keccak/vk \
    --program-id <PROGRAM_ID> \
    --network localnet
# → VK Account: 3WzRvunVbZMFwroHGSi9kEcwPhWyreFM4FNrdmF9TAmd

# 4. Verify a proof
noir-solana verify \
    --proof ./target/keccak/proof \
    --public-inputs ./target/keccak/public_inputs \
    --vk-account <VK_ACCOUNT> \
    --program-id <PROGRAM_ID> \
    --network localnet
# → ✅ Proof verified successfully!
```

### CLI Commands

```bash
noir-solana deploy          # Deploy verifier program
noir-solana upload-vk       # Upload VK to account
noir-solana verify          # Verify a proof (full E2E)
noir-solana status          # Check verification state
noir-solana receipt create  # Create verification receipt
noir-solana receipt check   # Check if receipt exists
noir-solana close           # Close accounts, reclaim rent
```

---

## 📦 SDK Integration

### TypeScript SDK

```typescript
import { SolanaNoirVerifier } from '@solana-noir-verifier/sdk';

const verifier = new SolanaNoirVerifier(connection, programId);

// Upload VK (once per circuit)
const { vkAccount } = await verifier.uploadVK(payer, vkBytes);

// Verify proof
const result = await verifier.verify(payer, proof, publicInputs, vkAccount);
console.log(`Verified in ${result.totalCUs} CUs`);

// Create receipt for CPI
await verifier.createReceipt(payer, stateAccount, proofAccount, vkAccount, publicInputs);
```

### Rust SDK

```rust
use solana_noir_verifier_sdk::SolanaNoirVerifier;

let verifier = SolanaNoirVerifier::new(rpc_client, program_id);

// Upload VK
let vk_result = verifier.upload_vk(&payer, &vk_bytes).await?;

// Verify proof
let result = verifier.verify(
    &payer, &proof, &public_inputs, vk_result.vk_account, None
).await?;

// Create receipt for CPI
verifier.create_receipt(&payer, state, proof_acc, vk_acc, &public_inputs).await?;
```

### CPI Integration

For Solana programs that need to check if a proof was verified:

```rust
use solana_noir_verifier_cpi::{is_verified, get_verified_slot};

// Check if proof was verified
let receipt_pda = derive_receipt_pda(vk_account, &public_inputs, program_id);
if is_verified(&receipt_account)? {
    let slot = get_verified_slot(&receipt_account)?;
    // Proceed with application logic...
}
```

See `examples/sample-integrator/` for a complete example.

---

## 🔄 How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    CIRCUIT DEPLOYMENT (once per circuit)         │
├─────────────────────────────────────────────────────────────────┤
│  1. Create VK account                                            │
│  2. Upload VK (2 chunks for 1,760 bytes)                        │
│  → VK Account pubkey (save for proof verification)              │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                   PROOF VERIFICATION (per proof)                 │
├─────────────────────────────────────────────────────────────────┤
│  1. Create proof + state accounts (1 TX)                        │
│  2. Upload proof (16 chunks in parallel)                        │
│  3. Run verification phases (8 TXs, ~5.4M CUs)                  │
│  4. (Optional) Create verification receipt for CPI              │
│  → Verification result + accounts closed (rent reclaimed)       │
└─────────────────────────────────────────────────────────────────┘
```

### Multi-Transaction Phased Verification

Solana's **1.4M CU per-transaction limit** requires splitting UltraHonk verification across multiple transactions:

| Phase | Description                 | TXs | CUs     |
| ----- | --------------------------- | --- | ------- |
| 1     | Challenge generation        | 1   | ~287K   |
| 2     | Sumcheck (rounds+relations) | 3   | ~3.8M   |
| 3     | MSM (weights+fold+gemini)   | 3   | ~2.1M   |
| 4     | Pairing check               | 1   | ~55K    |
| **Total** |                         | **8** | **~5.4M** |

State is stored in a verification account between transactions.

### Account Structure

| Account      | Size        | Purpose                           |
| ------------ | ----------- | --------------------------------- |
| VK Buffer    | 1,763 bytes | Header (3) + VK (1,760)           |
| Proof Buffer | ~16,261 bytes | Header (9) + PI (32×n) + Proof  |
| State Buffer | 6,408 bytes | Verification state between TXs    |

### Proof Formats

| Mode            | Proof Size   | VK Size   | Use Case       |
| --------------- | ------------ | --------- | -------------- |
| Poseidon2       | ~16 KB       | ~3.6 KB   | Recursive      |
| **Keccak + ZK** | **16,224 B** | **1,760** | **Solana** ✓   |

**Always use `--oracle_hash keccak --zk` for Solana verification.**

Note: bb 0.87 produces **fixed-size proofs** (16,224 bytes for ZK) regardless of circuit complexity due to `CONST_PROOF_SIZE_LOG_N=28` padding.

---

## 📊 Performance

### Verified Test Circuits

| Circuit              | log_n | Public Inputs | Transactions | CUs     |
| -------------------- | ----- | ------------- | ------------ | ------- |
| simple_square        | 12    | 1             | 24           | 5.44M   |
| fib_chain_100        | 12    | 1             | 24           | 5.44M   |
| iterated_square_100  | 12    | 1             | 24           | 5.44M   |
| iterated_square_1000 | 13    | 1             | 25           | 5.70M   |
| iterated_square_10k  | 14    | 1             | 25           | 5.96M   |
| iterated_square_100k | 16    | 1             | 25           | 6.72M   |
| hash_batch           | 17    | 32            | 26           | 6.99M   |
| merkle_membership    | 18    | 32            | 26           | 7.25M   |
| sapling_spend        | 16    | 4             | 25           | 6.49M   |

All proofs are 16,224 bytes (fixed size in ZK mode). Verification takes ~10s on localnet.

### Cost Estimates (Mainnet)

| Component                      | Cost        |
| ------------------------------ | ----------- |
| Per proof verification         | ~$1.10 (8 TXs, priority fees) |
| Circuit deployment (VK upload) | ~$0.003 (one-time) |
| Rent deposits (recoverable)    | ~$33 per proof |

---

## 🔧 Development

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Noir and Barretenberg (see Version Compatibility above)
noirup -v 1.0.0-beta.8
bbup
```

### Build & Test

```bash
# Build all test circuits first (generates proofs + VKs)
cd test-circuits && ./build_all.sh && cd ..

# Run all tests (58+ passing)
cargo test

# Core library tests only
cargo test -p plonk-solana-core

# Build the verifier program
cd programs/ultrahonk-verifier && cargo build-sbf
```

### Generate Proofs

```bash
cd test-circuits/simple_square

# Compile and execute
nargo compile && nargo execute

# Generate proof (ALWAYS use keccak + zk for Solana)
~/.bb/bb prove \
    -b ./target/simple_square.json \
    -w ./target/simple_square.gz \
    --oracle_hash keccak --zk \
    -o ./target/keccak

# Generate VK
~/.bb/bb write_vk \
    -b ./target/simple_square.json \
    --oracle_hash keccak \
    -o ./target/keccak

# Verify locally (sanity check)
~/.bb/bb verify -p ./target/keccak/proof -k ./target/keccak/vk \
    --oracle_hash keccak --zk
```

Or use the helper script:

```bash
cd test-circuits && ./build_all.sh simple_square
```

### Test on Local Validator

```bash
# 1. Start Surfpool (in separate terminal)
surfpool

# 2. Build & deploy
cd programs/ultrahonk-verifier
cargo build-sbf
solana program deploy target/deploy/ultrahonk_verifier.so \
    --url http://127.0.0.1:8899 --use-rpc
# → Note the Program ID

# 3. Test with CLI
noir-solana upload-vk --vk ../../test-circuits/simple_square/target/keccak/vk \
    --program-id <PROGRAM_ID> --network localnet

noir-solana verify \
    --proof ../../test-circuits/simple_square/target/keccak/proof \
    --public-inputs ../../test-circuits/simple_square/target/keccak/public_inputs \
    --vk-account <VK_ACCOUNT> \
    --program-id <PROGRAM_ID> --network localnet

# Or use the JS test script
PROGRAM_ID=<id> node scripts/solana/test_phased.mjs
```

---

## 🏗️ Project Structure

```
solana-noir-verifier/
├── crates/
│   ├── plonk-core/              # Core verifier library (58 tests)
│   │   ├── ops.rs               # BN254 ops via syscalls
│   │   ├── transcript.rs        # Fiat-Shamir (Keccak256)
│   │   ├── key.rs               # VK parsing (1,760 bytes)
│   │   ├── proof.rs             # Proof parsing (16,224 bytes)
│   │   ├── sumcheck.rs          # Sumcheck protocol
│   │   ├── relations.rs         # 26 subrelations
│   │   ├── shplemini.rs         # Batch opening verification
│   │   └── verifier.rs          # Main verification logic
│   ├── rust-sdk/                # Rust SDK + CLI
│   │   ├── src/
│   │   │   ├── client.rs        # SolanaNoirVerifier
│   │   │   ├── instructions.rs  # Instruction builders
│   │   │   └── bin/noir-solana/ # CLI binary
│   │   └── examples/
│   │       └── test_phased.rs   # E2E example
│   ├── verifier-cpi/            # CPI helper for integrators
│   └── vk-codegen/              # VK → Rust constants (legacy)
├── programs/
│   └── ultrahonk-verifier/      # Main Solana verifier program
│       ├── src/
│       │   ├── lib.rs           # Entry point + instructions
│       │   └── phased.rs        # Verification state machine
│       └── tests/
│           └── integration_test.rs
├── sdk/                         # TypeScript SDK
│   └── src/
│       ├── client.ts            # SolanaNoirVerifier class
│       ├── instructions.ts      # Instruction builders
│       └── types.ts             # TypeScript interfaces
├── examples/
│   └── sample-integrator/       # CPI integration example
├── test-circuits/               # 9 verified test circuits
│   ├── simple_square/           # Basic x² = y
│   ├── iterated_square_*/       # Scalability tests
│   ├── hash_batch/              # Blake3 hashing
│   ├── merkle_membership/       # Merkle proofs
│   └── sapling_spend/           # Zcash-style circuit
├── scripts/
│   └── solana/
│       ├── test_phased.mjs      # E2E verification script
│       └── verify.mjs           # Simple verification
└── docs/
    ├── theory.md                # UltraHonk protocol docs
    ├── knowledge.md             # Implementation notes
    └── bpf-limitations.md       # Solana constraints
```

---

## ✅ Implementation Status

### Completed

- [x] BN254 operations via syscalls
- [x] Proof/VK parsing (bb 0.87 format with limbed G1 points)
- [x] Fiat-Shamir transcript (Keccak256)
- [x] All 25 alpha challenges generation
- [x] Gate challenges (CONST_PROOF_SIZE_LOG_N iterations)
- [x] Sumcheck verification (all rounds)
- [x] All 26 subrelations (arithmetic, permutation, lookup, range, elliptic, aux, poseidon)
- [x] Shplemini batch opening verification
- [x] KZG pairing check
- [x] Multi-transaction phased verification
- [x] Zero-copy proof parsing
- [x] VK account support (circuit-agnostic)
- [x] Verification receipts for CPI
- [x] TypeScript SDK
- [x] Rust SDK + CLI
- [x] 9 test circuits verified

### Optimizations Applied

| Optimization                  | Improvement                   |
| ----------------------------- | ----------------------------- |
| Montgomery multiplication     | **-87% CUs (7x faster)**      |
| Batch inversion (sumcheck)    | **-38% CUs sumcheck**         |
| Batch inversion (fold denoms) | **-60% CUs phase 3b1**        |
| FrLimbs in sumcheck           | **-24% Phase 2**              |
| FrLimbs in shplemini          | **-16% Phase 3**              |
| Zero-copy Proof struct        | **-47% transactions**         |
| Parallel proof upload         | 16 chunks in ~0.8s            |

---

## 📖 Documentation

- [`SPEC.md`](./SPEC.md) - Detailed specification
- [`tasks.md`](./tasks.md) - Implementation progress
- [`docs/knowledge.md`](./docs/knowledge.md) - Implementation notes
- [`docs/theory.md`](./docs/theory.md) - UltraHonk protocol
- [`crates/rust-sdk/README.md`](./crates/rust-sdk/README.md) - Rust SDK & CLI docs

## 🔗 References

- [Noir Documentation](https://noir-lang.org/docs)
- [Barretenberg](https://barretenberg.aztec.network/docs/getting_started/)
- [groth16-solana](https://github.com/Lightprotocol/groth16-solana) - Groth16 verifier pattern
- [ultraplonk_verifier](https://github.com/zkVerify/ultraplonk_verifier) - UltraPlonk reference

## 📜 License

MIT OR Apache-2.0
