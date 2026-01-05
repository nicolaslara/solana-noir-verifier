# Solana Noir Verifier - Implementation Tasks

## ✅ Implementation Complete!

**December 2024:** Full UltraHonk verification working with bb 0.87 / nargo 1.0.0-beta.8.

| Metric        | Value                    |
| ------------- | ------------------------ |
| Unit Tests    | 56 passing               |
| Test Circuits | 9 verified               |
| Circuit Sizes | log_n 12-18              |
| Proof Size    | 16,224 bytes (fixed, ZK) |
| VK Size       | 1,760 bytes              |

---

## 📋 Development Principles

As we iterate toward production, maintain these standards:

1. **Code Quality**
   - Clean, readable code with meaningful names
   - Consistent style across Rust, TypeScript, and scripts
   - Remove dead code and commented-out experiments

2. **Documentation**
   - Every public API has doc comments
   - README updated as features are added
   - Design decisions documented in `docs/`

3. **Testing**
   - All changes must pass existing tests
   - New features need corresponding tests
   - E2E tests for critical paths

4. **Working State**
   - Main branch always builds and tests pass
   - Use feature branches for experimental work
   - Don't merge broken code

---

## 🔧 Toolchain Requirements

| Tool              | Version        | Notes                              |
| ----------------- | -------------- | ---------------------------------- |
| Noir (nargo)      | 1.0.0-beta.8   | UltraHonk/Keccak support           |
| Barretenberg (bb) | 0.87.x         | Auto-detected by `bbup` from nargo |
| Rust              | 1.75+          | Stable                             |
| Solana SDK        | 3.0+           | BN254 syscalls                     |

**Important:** `bbup` automatically detects your nargo version and installs the compatible bb version.
To get bb 0.87.x, install nargo 1.0.0-beta.8 first:

```bash
# Install specific Noir version
noirup -v 1.0.0-beta.8

# bbup will auto-detect and install bb 0.87.x
bbup
```

---

## 🚀 Phase 1: SDK & CLI Development (Current Priority)

### 1.1 Client Library Optimization

- [x] **Fix parallel proof uploads** ✅
  - Implemented: Uses `connection.sendTransaction()` for all chunks, then batch-confirm
  - Result: 19 chunks uploaded in ~0.8s

- [x] **Bundle account creation with init + public inputs** ✅
  - Implemented: 1 TX creates both accounts + init buffer + set public inputs
  - Previous: 4 separate TXs → Now: 1 TX

- [x] **Optimize chunk sizing** ✅
  - Changed: 900 → 1020 bytes per chunk (near TX size limit of 1232)
  - Result: 19 → 16 chunks for proof upload (16% fewer TXs)

### 1.2 Production-Grade Abstractions ✅

Production-grade abstractions are now implemented:

- [x] **Proof identification scheme** ✅
  - **Implemented: PDA derived from VK account + PI hash**
    ```
    VerificationReceipt PDA = seeds(["receipt", vk_account, keccak(public_inputs)], program_id)
    ```
  - Receipt account (16 bytes - minimal):
    ```rust
    pub struct VerificationReceipt {
        pub verified_slot: u64,       // When verified
        pub verified_timestamp: i64,  // Unix timestamp
    }
    ```
  - The VK and PI hash are encoded in the PDA address itself (no duplication)
  - Instruction: `CreateReceipt (60)`
  - SDK methods: `deriveReceiptPda()`, `createReceipt()`, `getReceipt()`
  - For Solana programs: `solana-noir-verifier-cpi` crate with `is_verified()` ✅
  - Sample integrator program: `examples/sample-integrator/`

- [x] **Upload integrity verification** ✅
  - **Implemented: Chunk bitmap tracking**
  - Added 4-byte chunk bitmap to proof buffer header (supports up to 32 chunks)
  - Each chunk upload marks its bit in the bitmap
  - Phase 1 validates all required chunks are present before verification
  - Bitmap automatically calculated based on PROOF_SIZE / MAX_CHUNK_SIZE
  - Handles: Out-of-order uploads, missing chunks detection

- [x] **Verification status tracking** ✅
  - **Implemented: Receipt PDA encodes all status information**
  - VK account key + PI hash are encoded in the PDA address itself
  - Receipt stores `verified_slot` and `verified_timestamp`
  - Integrators can implement expiration logic using `verified_slot` if needed
  - CPI crate: `solana-noir-verifier-cpi` with `is_verified()`, `get_verified_slot()`

- [x] **Error handling and recovery** ✅
  - **Decision: Failed verification is terminal (no recovery)**
  - Rationale: UltraHonk is deterministic - retrying won't help unless proof changes
  - Account cleanup: SDK automatically closes accounts to reclaim rent
  - `verify()` option `autoClose: true` (default) cleans up on success AND failure
  - CLI must always enable `autoClose` to recover rent

- [x] **Document findings and decisions** ✅
  - Decisions documented inline in code and tasks.md
  - Key decisions:
    - Receipt PDA = `["receipt", vk_account, keccak(public_inputs)]`
    - Minimal 16-byte receipt (slot + timestamp only)
    - VK/PI encoded in PDA address, no duplication
    - Failed verification is terminal (no retry mechanism needed)

### 1.3 TypeScript/JavaScript SDK ✅

Created `@solana-noir-verifier/sdk` package in `sdk/`:

- [x] **Core SDK structure** ✅
  - `sdk/src/index.ts` - Main exports
  - `sdk/src/client.ts` - SolanaNoirVerifier class
  - `sdk/src/instructions.ts` - Instruction builders
  - `sdk/src/types.ts` - TypeScript interfaces + constants

- [x] **SolanaNoirVerifier class API** ✅
  - `uploadVK(payer, vk)` - Upload VK to chain
  - `verify(payer, proof, publicInputs, vkAccount)` - Full verification
  - `getVerificationState(stateAccount)` - Read state from account

- [x] **Robust transaction handling** ✅
  - Parallel sends with batch confirmation
  - Progress callbacks for UI integration
  - Automatic phase orchestration
  - Automatic account cleanup (`autoClose` option, default: true)
  - Rent reclaimed on both success and failure

### 1.4 Rust SDK & CLI ✅

Created `solana-noir-verifier-sdk` crate in `crates/rust-sdk/`:

#### Rust SDK (Complete ✅)

- [x] **Core SDK structure** ✅
  - `crates/rust-sdk/src/lib.rs` - Main exports
  - `crates/rust-sdk/src/client.rs` - SolanaNoirVerifier client
  - `crates/rust-sdk/src/instructions.rs` - Instruction builders
  - `crates/rust-sdk/src/types.rs` - Types + constants
  - `crates/rust-sdk/src/error.rs` - Error types

- [x] **SolanaNoirVerifier class API** ✅
  - `upload_vk(payer, vk_bytes)` - Upload VK to chain
  - `verify(payer, proof, public_inputs, vk_account, options)` - Full verification
  - `get_verification_state(state_account)` - Read state from account
  - `derive_receipt_pda(vk_account, public_inputs)` - Derive receipt PDA
  - `create_receipt(payer, state, proof, vk, public_inputs)` - Create verification receipt
  - `get_receipt(vk_account, public_inputs)` - Check if proof was verified
  - `close_accounts(payer, state, proof)` - Close accounts to reclaim rent

- [x] **Robust transaction handling** ✅
  - Parallel sends with batch confirmation
  - Automatic phase orchestration (9 TXs)
  - Automatic account cleanup (`auto_close` option, default: true)
  - Rent reclaimed on both success and failure

#### CLI Tool (`noir-solana`) ✅

CLI binary added to the Rust SDK crate. Install with:
```bash
cargo install --path crates/rust-sdk --features cli
```

- [x] **CLI binary in SDK crate**
  ```toml
  # crates/rust-sdk/Cargo.toml
  [[bin]]
  name = "noir-solana"
  path = "src/bin/noir-solana/main.rs"
  required-features = ["cli"]
  ```
  Structure:
  ```
  crates/rust-sdk/src/bin/noir-solana/
  ├── main.rs           # Entry point + clap setup
  ├── config.rs         # RPC/keypair config
  └── commands/
      ├── mod.rs
      ├── deploy.rs     # Deploy verifier program
      ├── upload_vk.rs  # Upload VK to account
      ├── verify.rs     # Submit and verify proof
      ├── status.rs     # Check verification status
      ├── receipt.rs    # Create/check receipts
      └── close.rs      # Close accounts, reclaim rent
  ```

- [x] **Core commands**
  
  ```bash
  # Deploy the verifier program (returns program ID)
  noir-solana deploy --keypair ~/.config/solana/id.json --network devnet
  
  # Upload a VK (returns VK account address)
  noir-solana upload-vk --vk ./target/keccak/vk \
    --program-id <program_id> --network devnet
  
  # Verify a proof (full E2E workflow: upload + 9 TXs)
  noir-solana verify \
    --proof ./target/keccak/proof \
    --public-inputs ./target/keccak/public_inputs \
    --vk-account <vk_pubkey> \
    --program-id <program_id>
  
  # Check verification state (during or after verification)
  noir-solana status --state-account <state_pubkey> \
    --program-id <program_id>
  
  # Create verification receipt (after successful verification)
  noir-solana receipt create \
    --state-account <state_pubkey> \
    --proof-account <proof_pubkey> \
    --vk-account <vk_pubkey> \
    --public-inputs ./target/keccak/public_inputs \
    --program-id <program_id>
  
  # Check if a receipt exists
  noir-solana receipt check \
    --vk-account <vk_pubkey> \
    --public-inputs ./target/keccak/public_inputs \
    --program-id <program_id>
  
  # Close accounts and reclaim rent
  noir-solana close \
    --state-account <state_pubkey> \
    --proof-account <proof_pubkey> \
    --program-id <program_id>
  ```
  
  **Tip:** Set env vars: `KEYPAIR_PATH`, `VERIFIER_PROGRAM_ID`, `SOLANA_RPC_URL`
  
  **Note:** We don't include `prove` commands - use `nargo` and `bb` directly for proof generation.
  This CLI focuses on **Solana-specific** operations (deploy, upload, verify, receipts).

- [x] **Configuration**
  - Support `~/.config/noir-solana/config.toml`
  - Example config:
    ```toml
    [default]
    network = "devnet"
    keypair = "~/.config/solana/id.json"
    
    [networks.devnet]
    rpc_url = "https://api.devnet.solana.com"
    program_id = "7sfMWfVs6P1ACjouyvRwWHjiAj6AsFkYARP2v9RBSSoe"
    
    [networks.localnet]
    rpc_url = "http://127.0.0.1:8899"
    # program_id = <set after deploy>
    ```
  - Environment variable fallbacks: `SOLANA_RPC_URL`, `KEYPAIR_PATH`, `VERIFIER_PROGRAM_ID`
  - CLI flags override config file which overrides env vars

- [x] **Output formats**
  - Human-readable (default)
  - JSON (`--output json`) for scripting
  - Quiet mode (`-q`) for CI pipelines

- [x] **Dependencies**
  - `clap` for argument parsing
  - `indicatif` for progress bars
  - `console` for colored output
  - `dirs` for config file paths
  - `toml` for config parsing
  - `dirs` for config file locations

### 1.5 VK Account Support ✅

VK is now loaded from an account at runtime (program is circuit-agnostic):

- [x] **Add VK account instruction** ✅
  - `InitVkBuffer (4)` - Initialize VK buffer account
  - `UploadVkChunk (5)` - Upload VK data in chunks
  - VK account structure: `[status(1), vk_len(2), vk_data(1760)]`
  - SDK method: `uploadVK(payer, vkBytes)` → returns VK account pubkey
  
- [x] **Update phases to require VK account** ✅
  - Phase 1 (30) and Phase 3c+Pairing (54) require VK account parameter
  - These are the only phases that need VK (challenge gen + final pairing)
  - Embedded VK only used for deprecated test instructions

- [x] **VK account validation** ✅
  - `parse_vk()` validates account is owned by verifier program
  - Validates status is Ready and data is complete
  - **Cross-phase VK consistency**: Phase 1 stores VK account pubkey in state,
    Phase 3c validates it matches (prevents using different VKs across phases)
  - State size increased: 6376 → 6408 bytes (+32 for VK pubkey)

### 1.6 Code Cleanup (Ongoing)

- [ ] **Clean up test scripts**
  - Remove duplicate/unused scripts
  - Consolidate `test_phased.mjs` and `verify.mjs`
  - Add proper error handling and logging

- [ ] **Improve program code organization**
  - Split `lib.rs` into smaller modules
  - Document instruction formats
  - Add integration tests for each instruction

- [ ] **Update README with current state**
  - Clear getting-started guide
  - Example usage for common scenarios
  - Link to detailed docs

### 1.7 Code Reorganization (Prep for UltraPlonk)

Before merging UltraPlonk, reorganize current code to make room:

- [ ] **Move UltraHonk code into dedicated directories**
  - Current structure is flat; need to namespace by proving system
  - Target structure:
    ```
    crates/
    ├── common/                    # Shared: field ops, BN254 ops, types
    │   └── src/
    │       ├── field.rs
    │       ├── ops.rs
    │       ├── types.rs
    │       └── transcript.rs      # Keccak transcript (shared)
    ├── ultrahonk-core/            # UltraHonk-specific verification
    │   └── src/
    │       ├── key.rs
    │       ├── proof.rs
    │       ├── verifier.rs
    │       ├── sumcheck.rs
    │       ├── relations.rs
    │       └── shplemini.rs
    └── ultraplonk-core/           # (Future) UltraPlonk verification
    
    programs/
    ├── ultrahonk-verifier/        # UltraHonk Solana program
    └── ultraplonk-verifier/       # (Future) UltraPlonk Solana program
    ```

- [ ] **Extract shared code into `common` crate**
  - Field arithmetic (Fr operations, Montgomery)
  - BN254 operations (G1, G2, pairing syscalls)
  - Types (G1Point, G2Point, Scalar)
  - Keccak transcript base

- [ ] **Update imports and test that everything still works**
  - All existing tests must pass after reorganization
  - No functional changes, just code movement

- [ ] **Document the module boundaries**
  - What belongs in `common` vs scheme-specific crates
  - Clear interfaces between crates

**After this, we can copy UltraPlonk code directly and adapt it to use shared infrastructure.**

---

## 🔀 Phase 2: UltraPlonk Integration (After 1.7)

Merge the UltraPlonk verifier from `~/devel/privacy-infrastructure-sandbox/spikes/solana-ultraplonk-verifier`.

**Prerequisite:** Complete 1.7 (code reorganization) first!

### 2.1 Copy and Adapt UltraPlonk Code

- [ ] **Copy UltraPlonk crate from spike project**
  - Source: `~/devel/privacy-infrastructure-sandbox/spikes/solana-ultraplonk-verifier/crates/ultraplonk-core`
  - Target: `crates/ultraplonk-core/`
  
- [ ] **Update to use shared `common` crate**
  - Replace duplicate field ops with `common::field`
  - Replace duplicate BN254 ops with `common::ops`
  - Keep UltraPlonk-specific: widgets, quotient eval, proof/VK parsing

- [ ] **Copy UltraPlonk Solana program**
  - Source: `~/devel/.../programs/ultraplonk-verifier`
  - Target: `programs/ultraplonk-verifier/`
  - Simpler than UltraHonk (single-TX verification)

### 2.2 Decide: Unified vs Separate Programs

- [ ] **Evaluate trade-offs**
  - Option A: Single program with scheme prefix in instructions
    - Pro: One deployment, shared account infrastructure
    - Con: Larger program size, more complex
  - Option B: Separate programs sharing common crate
    - Pro: Simpler, smaller individual programs
    - Con: Two deployments to manage
  - **Recommendation:** Start with Option B (separate), can unify later

### 2.2 Version Matrix

| Scheme     | Noir Version   | bb Version | Proof Size | CUs     |
| ---------- | -------------- | ---------- | ---------- | ------- |
| UltraHonk  | 1.0.0+         | 0.87+      | 16,224 B   | ~6.6M   |
| UltraPlonk | 1.0.0-beta.3   | 0.82.2     | ~2,200 B   | ~1.2M   |

- [ ] **Document version requirements clearly**
- [ ] **Add version detection from VK/proof headers**

### 2.3 Shared Test Circuits

- [ ] **Move test circuits to shared location**
  - Keep circuit source code shared
  - Build scripts generate both UltraHonk and UltraPlonk proofs
  - Clear directory structure: `target/ultrahonk/` vs `target/ultraplonk/`

---

## 🔗 Phase 3: CPI Integration (Future)

Enable other Solana programs to verify proofs via CPI.

### 3.1 CPI Design

- [ ] **Stateless CPI verification**
  - Problem: Multi-TX verification doesn't fit CPI model
  - Solution: Verifier stores result in an account, caller checks account state
  
- [ ] **Verification receipt account**
  ```rust
  pub struct VerificationReceipt {
    pub verified: bool,
    pub vk_hash: [u8; 32],      // Hash of VK
    pub pi_hash: [u8; 32],      // Hash of public inputs
    pub slot: u64,              // When verified
    pub expires_at: u64,        // Expiry slot (optional)
  }
  ```

- [ ] **CPI flow for caller programs**
  ```
  1. User submits proof to verifier (multi-TX)
  2. Verifier creates/updates VerificationReceipt
  3. Caller program CPIs to check receipt
  4. Caller validates receipt matches expected PI/VK
  5. Caller proceeds with application logic
  ```

### 3.2 Security Considerations

- [ ] **Receipt expiration**
  - Receipts should expire after N slots
  - Prevents replay of old verifications
  
- [ ] **PI commitment**
  - Receipt includes hash of public inputs
  - Caller must verify PI hash matches expected values

---

## 📦 Phase 4: Package & Distribution

### 4.1 NPM Package

- [ ] **Publish `@solana-noir-verifier/sdk`**
  - Include TypeScript definitions
  - Support ESM and CommonJS
  - Minimal dependencies

### 4.2 Crates.io

- [ ] **Publish `noir-solana-verify` CLI**
  - `cargo install noir-solana-verify`
  
- [ ] **Publish core crates for custom integrations**
  - `solana-ultrahonk-core`
  - `solana-ultraplonk-core`

### 4.3 Program Deployment

- [ ] **Verified mainnet deployment**
  - Deploy to mainnet-beta with verified source
  - Document program ID
  - Consider upgrade authority structure

---

## 🚀 Phase 5: Performance & UX Optimizations (Future)

### 5.1 Jito Bundle Support

- [ ] **Integrate Jito bundling for verification transactions**
  - Current: 8 sequential transactions with individual confirmations
  - With Jito: Bundle all 8 TXs and land them atomically in a single slot
  - Benefits:
    - **Faster verification**: All TXs land together (~400ms vs ~4-8s sequential)
    - **Atomic execution**: Either all phases succeed or none do
    - **Better UX**: Single confirmation wait instead of 8
  - Implementation:
    - Use `jito-ts` SDK for bundle submission
    - Add tip instruction to last TX in bundle
    - Handle bundle status polling
  - Reference: [Jito Labs Bundle API](https://jito-labs.gitbook.io/)

### 5.2 Fee-Charged Verification

- [ ] **Implement optional fee collection for verification**
  - **Motivation**: Monetize verification service; charge per-proof
  - **Key constraint**: Cannot deduct from Solana tx fees—must be explicit transfer
  
  - **Design: Charge once per verification session**
    - Charge at `verify_init` (recommended) or `check_proof` (caller-paid)
    - Record "paid" in session PDA; subsequent steps don't charge again
    - No extra transactions needed
  
  - **State accounts**:
    - `FeeConfig PDA`: admin, enabled, mode, allowed_mints, fee_schedule
    - `FeeVault PDA`: SOL vault + token ATAs for SPL fees
    - `VerificationSession PDA`: paid status, payer, asset, amount, slot
  
  - **Supported assets**: SOL + allowlisted SPL tokens (USDC, etc.)
  
  - **Fee modes**:
    - `None`: Free (disabled)
    - `VerifyInitOnly`: User pays on verify_init
    - `CheckProofOnly`: Caller program pays on check_proof
    - `Either`: Pay at either point
  
  - **Clean API for integrators**:
    - Fee accounts via `remaining_accounts` (main ix list stays stable)
    - When fees disabled, fee accounts optional/no-op
    - Helper crate with `FeeOption::Auto | SOL | SPL(mint) | None`
  
  - **v1 minimal scope**:
    - Only charge on `verify_init`
    - SOL + 1-2 stablecoins (USDC)
    - Fixed fee amount per asset
    - `FeeConfig.enabled = false` by default (free)

---

## ✅ Completed Work (Archive)

### E2E Workflow (Verified Working ✅)

```bash
# 1. Compile
nargo compile

# 2. Execute (generate witness)
nargo execute

# 3. Prove (USE KECCAK + ZK!)
~/.bb/bb prove -b ./target/circuit.json -w ./target/circuit.gz \
    --oracle_hash keccak --zk -o ./target/keccak

# 4. Write VK
~/.bb/bb write_vk -b ./target/circuit.json \
    --oracle_hash keccak -o ./target/keccak

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

### On-Chain Verification (Complete ✅)

**Challenge: BPF Compute Unit Limits**

Solana has a **1.4M CU per-transaction limit**. UltraHonk verification requires splitting across multiple transactions.

**Solution: Multi-TX Phased Verification**

| Phase | Description                | TXs | CUs     |
| ----- | -------------------------- | --- | ------- |
| 1     | Challenge generation       | 1   | ~287K   |
| 2     | Sumcheck (rounds+relations)| 3   | ~3.8M   |
| 3     | MSM (weights+fold+gemini)  | 4   | ~3.3M   |
| 4     | Pairing check              | 1*  | ~54K    |

*Phase 3c and 4 can be combined into single TX, saving 1 TX.

**Current best result (simple_square):** 6.65M CUs across 9 TXs

### Optimization Progress

| Optimization                  | Status         | Improvement                   |
| ----------------------------- | -------------- | ----------------------------- |
| Karatsuba multiplication      | ✅ Implemented | -12% CUs                      |
| Montgomery multiplication     | ✅ Implemented | **-87% CUs (7x)**             |
| Binary Extended GCD           | ✅ Implemented | Much faster inv               |
| Batch inversion (sumcheck)    | ✅ Implemented | **-38% CUs sumcheck**         |
| Batch inversion (fold denoms) | ✅ Implemented | **-60% CUs phase 3b1**        |
| Shplemini rho^k precompute    | ✅ Implemented | Avoids O(k) exponentiation    |
| Shplemini batch inv (gemini)  | ✅ Implemented | Batched denominators          |
| FrLimbs in sumcheck           | ✅ Implemented | **-24% Phase 2 (5M→3.8M)**    |
| FrLimbs in shplemini          | ✅ Implemented | **-16% Phase 3 (2.95M→2.5M)** |
| Zero-copy Proof struct        | ✅ Implemented | **-47% transactions**         |
| Parallel proof upload         | ✅ Implemented | 19 chunks in ~0.8s            |

### Test Circuit Suite

All 9 circuits verified with `bb 0.87` (ZK proofs):

| Circuit                | ACIR Opcodes | log_n | Proof Size | Status |
| ---------------------- | ------------ | ----- | ---------- | ------ |
| `simple_square`        | 1            | 12    | 16,224     | ✅     |
| `fib_chain_100`        | 1            | 12    | 16,224     | ✅     |
| `iterated_square_100`  | 100          | 12    | 16,224     | ✅     |
| `iterated_square_1000` | 1,000        | 13    | 16,224     | ✅     |
| `iterated_square_10k`  | 10,000       | 14    | 16,224     | ✅     |
| `iterated_square_100k` | 100,000      | 16    | 16,224     | ✅     |
| `hash_batch`           | 2,112        | 17    | 16,224     | ✅     |
| `merkle_membership`    | 2,688        | 18    | 16,224     | ✅     |
| `sapling_spend`        | ~15,000      | 16    | 16,224     | ✅     |

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
│   │   ├── verifier.rs          # Verification ✅
│   │   ├── sumcheck.rs          # Sumcheck verification ✅
│   │   ├── relations.rs         # 26 subrelations ✅
│   │   ├── shplemini.rs         # Batch opening ✅
│   │   ├── constants.rs         # Field constants ✅
│   │   └── errors.rs            # Error types ✅
│   ├── rust-sdk/                # Rust SDK + CLI ✅
│   │   ├── src/
│   │   │   ├── lib.rs           # SDK exports ✅
│   │   │   ├── client.rs        # SolanaNoirVerifier ✅
│   │   │   ├── instructions.rs  # Instruction builders ✅
│   │   │   ├── types.rs         # Types + constants ✅
│   │   │   ├── error.rs         # Error types ✅
│   │   │   └── bin/             # CLI binary (TODO)
│   │   │       └── main.rs
│   │   └── examples/
│   │       └── test_phased.rs   # E2E example ✅
│   ├── verifier-cpi/            # CPI helper for integrators ✅
│   └── vk-codegen/              # CLI for VK → Rust constants
├── programs/
│   └── ultrahonk-verifier/      # Solana program
│       ├── src/
│       │   ├── lib.rs           # Entry point + instructions ✅
│       │   └── phased.rs        # Verification state ✅
│       └── tests/
│           └── integration_test.rs  # E2E test ✅
├── sdk/                         # TypeScript SDK ✅
│   ├── src/
│   │   ├── index.ts             # Main exports
│   │   ├── client.ts            # SolanaNoirVerifier class
│   │   ├── instructions.ts      # Instruction builders
│   │   └── types.ts             # TypeScript interfaces
│   └── package.json
├── examples/
│   └── sample-integrator/       # Sample CPI integration ✅
├── test-circuits/               # Noir circuits for testing
│   ├── simple_square/
│   ├── hash_batch/
│   └── ...
├── scripts/
│   └── solana/
│       ├── test_phased.mjs      # E2E verification script
│       └── verify.mjs           # Simple verification
└── docs/
    ├── knowledge.md             # Implementation notes
    ├── theory.md                # Protocol documentation
    └── bpf-limitations.md       # Solana constraints
```

---

## Key References

- [Barretenberg Docs](https://barretenberg.aztec.network/docs/getting_started/)
- [bb source](https://github.com/AztecProtocol/barretenberg)
- [groth16-solana](https://github.com/Lightprotocol/groth16-solana)
- [zkVerify ultraplonk_verifier](https://github.com/zkVerify/ultraplonk_verifier) (for reference)

---

## Related Projects

- **solana-ultraplonk-verifier** (`~/devel/privacy-infrastructure-sandbox/spikes/solana-ultraplonk-verifier`)
  - UltraPlonk verifier for older Noir versions
  - Single-TX verification (~1.2M CUs)
  - To be merged in Phase 2
