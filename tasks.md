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

### 1.2 Production-Grade Abstractions (Research Required)

The current implementation is proof-of-concept. For production, we need cleaner abstractions:

- [ ] **Proof identification scheme**
  - **Decision: PDA derived from VK account + PI hash**
    ```
    VerificationReceipt PDA = seeds([vk_account_pubkey, hash(public_inputs)], program_id)
    ```
  - Rationale:
    - VK already lives in its own account, no need to duplicate in identifier
    - PI hash commits to what was proven (the statement)
    - Proof hash not needed - downstream cares "was X proven?" not "were these bytes verified?"
    - PDA is deterministic - anyone can compute it to look up verification status
  - Receipt account structure:
    ```rust
    pub struct VerificationReceipt {
        pub vk_account: Pubkey,      // 32 bytes - which circuit
        pub pi_hash: [u8; 32],       // 32 bytes - what was proven  
        pub verified_slot: u64,      // 8 bytes - when verified
        pub verified: bool,          // 1 byte
        // Total: 73 bytes (+ discriminator if using Anchor)
    }
    ```

- [ ] **Upload integrity verification**
  - Problem: How do we know all chunks were uploaded correctly?
  - Research approaches:
    - Option A: Merkle root of chunks stored in header, verified on-chain
    - Option B: Final hash check before verification phase
    - Option C: Chunk bitmap + total hash in account header
  - Must handle: Out-of-order uploads, partial uploads, retries

- [ ] **Verification status tracking**
  - Current: Simple `verified` bool in state account
  - Needed for production:
    - Verification timestamp (slot)
    - VK identifier (hash or account)
    - Public inputs commitment
    - Expiration for time-sensitive use cases
  - Research: What do other on-chain verifiers (groth16-solana) do?

- [ ] **Error handling and recovery**
  - What happens if verification fails mid-way?
  - Can we resume from a failed phase?
  - How to clean up failed verification accounts?

- [ ] **Document findings and decisions**
  - Create `docs/design-decisions.md` with research findings
  - Include trade-offs considered
  - Reference implementations studied

### 1.3 TypeScript/JavaScript SDK

Create `@solana-noir-verifier/sdk` package:

- [ ] **Core SDK structure**
  ```
  sdk/
  ├── package.json
  ├── tsconfig.json
  ├── src/
  │   ├── index.ts           # Main exports
  │   ├── client.ts          # SolanaNoirVerifier class
  │   ├── instructions.ts    # Instruction builders
  │   ├── accounts.ts        # Account parsing/creation
  │   ├── types.ts           # TypeScript interfaces
  │   └── utils.ts           # Helpers
  └── tests/
  ```

- [ ] **SolanaNoirVerifier class API**
  ```typescript
  class SolanaNoirVerifier {
    // Upload VK to on-chain account (one-time per circuit)
    async uploadVK(vk: Buffer): Promise<PublicKey>;
    
    // Verify a proof (multi-tx flow)
    async verify(
      proof: Buffer, 
      publicInputs: Buffer[],
      vkAccount: PublicKey
    ): Promise<VerificationResult>;
    
    // Get verification status
    async getStatus(stateAccount: PublicKey): Promise<VerificationStatus>;
    
    // Check if proof was verified (for CPI callers)
    async wasVerified(
      proofId: ProofIdentifier
    ): Promise<VerificationReceipt | null>;
  }
  ```

- [ ] **Robust transaction handling**
  - True parallel sends with batch confirmation
  - Handle blockhash expiration for long upload sequences
  - Retry logic for transient failures
  - Progress callbacks for UI integration

### 1.4 Rust CLI Tool

Create `noir-solana-verify` CLI:

- [ ] **CLI structure**
  ```
  cli/
  ├── Cargo.toml
  └── src/
      ├── main.rs
      ├── commands/
      │   ├── deploy.rs       # Deploy verifier program
      │   ├── upload_vk.rs    # Upload VK to account
      │   ├── verify.rs       # Submit and verify proof
      │   └── status.rs       # Check verification status
      └── config.rs           # RPC/keypair config
  ```

- [ ] **Commands**
  ```bash
  # Deploy the verifier program
  noir-solana-verify deploy --network devnet
  
  # Upload a VK (returns VK account address)
  noir-solana-verify upload-vk \
    --vk ./target/keccak/vk \
    --network devnet
  
  # Verify a proof
  noir-solana-verify verify \
    --proof ./target/keccak/proof \
    --public-inputs ./target/keccak/public_inputs \
    --vk-account <pubkey> \
    --network devnet
  
  # Check verification status
  noir-solana-verify status --account <state_pubkey>
  ```

- [ ] **Configuration**
  - Support `~/.config/noir-solana-verify/config.toml`
  - RPC endpoints for mainnet/devnet/localnet
  - Keypair path

### 1.5 VK Account Support

Currently VK is embedded at compile time. For production:

- [ ] **Add VK account instruction**
  - New instruction: `UploadVK` (or use chunked upload pattern)
  - VK account structure: `[owner][vk_data]`
  
- [ ] **Update all phases to accept VK account**
  - Add optional `vk_account` to instruction account lists
  - Fall back to embedded VK if not provided (backwards compat)

- [ ] **VK account validation**
  - Verify VK account owner matches expected authority
  - Cache parsed VK to avoid re-parsing each phase

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

All circuits verified with `bb 0.87` (ZK proofs):

| Circuit                | ACIR Opcodes | log_n | Proof Size | Status |
| ---------------------- | ------------ | ----- | ---------- | ------ |
| `simple_square`        | 1            | 12    | 16,224     | ✅     |
| `iterated_square_100`  | 100          | 12    | 16,224     | ✅     |
| `iterated_square_1000` | 1,000        | 13    | 16,224     | ✅     |
| `iterated_square_10k`  | 10,000       | 14    | 16,224     | ✅     |
| `hash_batch`           | 2,112        | 17    | 16,224     | ✅     |
| `merkle_membership`    | 2,688        | 18    | 16,224     | ✅     |
| `fib_chain_100`        | 1            | 12    | 16,224     | ✅     |

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
│   └── vk-codegen/              # CLI for VK → Rust constants
├── programs/
│   └── ultrahonk-verifier/      # Solana program
│       ├── src/
│       │   ├── lib.rs           # Entry point + instructions ✅
│       │   └── phased.rs        # Verification state ✅
│       └── tests/
│           └── integration_test.rs  # E2E test ✅
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
