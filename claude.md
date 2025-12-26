# Claude Development Guide for Solana Noir Verifier

This file contains essential context and rules for working on the Solana Noir Verifier project.

## Project Overview

A circuit-specific verifier for Noir zero-knowledge proofs on Solana, using UltraHonk proving system with Solana's native BN254 syscalls.

**Status**: ✅ Core implementation complete (56 tests passing, 7 circuits verified)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CIRCUIT DEPLOYMENT                        │
│                     (once per circuit)                       │
├─────────────────────────────────────────────────────────────┤
│  1. Create VK account                                        │
│  2. Upload VK (2 chunks for 1,760 bytes)                    │
│  → VK Account pubkey (save for proof verification)          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   PROOF VERIFICATION                         │
│                      (per proof)                             │
├─────────────────────────────────────────────────────────────┤
│  1. Create proof + state accounts (1 TX)                    │
│  2. Upload proof (19 chunks in parallel)                    │
│  3. Phase 1: Challenges (pass VK account)                   │
│  4. Phase 2: Sumcheck (3 TXs)                               │
│  5. Phase 3c+4: MSM + Pairing (pass VK account)             │
│  → Verification result                                       │
└─────────────────────────────────────────────────────────────┘
```

## Critical Development Rules

### 1. VK Registry Pattern (VERY IMPORTANT)

VK is loaded from a **separate account**, NOT embedded in the program:

- One verifier program supports ANY UltraHonk circuit
- Circuit deployer uploads VK once, reuses for all proofs
- Phase 1 and Phase 3c+4 require VK account as parameter
- **Never use embedded VK in production** - it's a security risk

```rust
// VK account is REQUIRED for verification
let vk_account = next_account_info(account_iter)?;  // REQUIRED
let vk = parse_vk(vk_account)?;
```

### 2. Account Structure

| Account | Size | Purpose |
|---------|------|---------|
| VK Buffer | 1,763 bytes | Header (3) + VK (1,760) |
| Proof Buffer | ~16,261 bytes | Header (5) + PI (32×n) + Proof (16,224) |
| State Buffer | 6,376 bytes | Verification state between TXs |

### 3. Solana BN254 Syscalls

Use `solana-bn254` crate for all heavy curve operations:

- `alt_bn128_addition` - G1 point addition
- `alt_bn128_multiplication` - G1 scalar multiplication
- `alt_bn128_pairing` - Pairing check

**Never** use pure Rust arkworks pairing in on-chain code - it will exceed compute limits.

### 4. Field/Curve Serialization (bb 0.87)

**VK format (64-byte G1 points):**
- G1 points: big-endian coordinates (x, y), 64 bytes total
- VK size: **1,760 bytes** (32-byte header + 27 G1 commitments)

**Proof format (limbed G1 points):**
- G1 points in proofs use **128-byte limbed format** (4 × 32-byte limbs: x_lo, x_hi, y_lo, y_hi)
- Proof size: **16,224 bytes** (fixed, ZK mode)
- Fr scalars: big-endian, 32 bytes

**Transcript format:**
- G1 points added to transcript in **limbed format** (128 bytes, not 64!)
- This is critical for challenge matching

### 5. Phased Verification (8 TXs total)

Solana's **1.4M CU per-TX limit** requires splitting verification:

| Phase | TXs | CUs | Description |
|-------|-----|-----|-------------|
| Phase 1 | 1 | ~273K | Challenge generation (needs VK) |
| Phase 2 | 3 | ~3.1M | Sumcheck (rounds + relations) |
| Phase 3+4 | 4 | ~2.1M | MSM + Pairing (needs VK) |
| **Total** | **8** | **~5.4M** | |

State stored in verification account between TXs.

### 6. Instruction Codes

```rust
// Buffer management
IX_INIT_BUFFER = 0        // Init proof buffer
IX_UPLOAD_CHUNK = 1       // Upload proof chunk
IX_SET_PUBLIC_INPUTS = 3  // Set public inputs
IX_INIT_VK_BUFFER = 4     // Init VK buffer
IX_UPLOAD_VK_CHUNK = 5    // Upload VK chunk

// Verification phases
IX_PHASE1_FULL = 30       // All challenges (VK required)
IX_PHASE2_ROUNDS = 40     // Sumcheck rounds
IX_PHASE2D_RELATIONS = 43 // Relations check
IX_PHASE3A_WEIGHTS = 50   // Shplemini weights
IX_PHASE3B1_FOLDING = 51  // Folding
IX_PHASE3B2_GEMINI = 52   // Gemini + libra
IX_PHASE3C_AND_PAIRING = 54  // MSM + Pairing (VK required)

// Receipts (for integrators)
IX_CREATE_RECEIPT = 60    // Create verification receipt PDA
```

### 7. ZK Mode

**Always use `--zk` flag** for Solana verification:
- bb command: `bb prove --oracle_hash keccak --zk`
- All test circuits use ZK mode

### 8. no_std Compatibility

Core verification code in `plonk-core` must be `no_std` compatible for Solana BPF:

```rust
#![cfg_attr(not(feature = "std"), no_std)]
```

## Version Compatibility

| Component | Version | Notes |
|-----------|---------|-------|
| Noir/Nargo | 1.0.0-beta.8 | UltraHonk/Keccak support |
| bb | 0.87.x | Install via `bbup` |
| Solana SDK | 3.0+ | BN254 syscalls stable |
| Rust | 1.75+ stable | |

## Project Structure

```
solana-noir-verifier/
├── programs/ultrahonk-verifier/   # Solana program
│   └── src/
│       ├── lib.rs                 # Main verifier + instruction handlers
│       └── phased.rs              # Verification state management
├── crates/
│   ├── plonk-core/               # Core verification library (no_std)
│   │   ├── ops.rs                # BN254 syscall wrappers
│   │   ├── transcript.rs         # Keccak Fiat-Shamir
│   │   ├── key.rs                # VK parsing
│   │   ├── proof.rs              # Proof parsing
│   │   ├── sumcheck.rs           # Sumcheck verification
│   │   ├── relations.rs          # 26 subrelations
│   │   ├── shplemini.rs          # Batch opening
│   │   └── verifier.rs           # Main verification logic
│   ├── vk-codegen/               # VK → Rust constants CLI
│   └── verifier-cpi/             # CPI helper for integrators
├── sdk/                           # TypeScript SDK
│   └── src/
│       ├── client.ts             # SolanaNoirVerifier class
│       ├── instructions.ts       # Instruction builders
│       └── types.ts              # Types & constants
├── examples/
│   └── sample-integrator/        # Example program using receipts
├── scripts/solana/
│   └── test_phased.mjs           # E2E test script
├── test-circuits/                # Noir test circuits
│   ├── simple_square/
│   ├── hash_batch/
│   └── merkle_membership/
├── docs/
│   ├── knowledge.md              # Implementation notes
│   ├── theory.md                 # Protocol documentation
│   └── suggested-optimizations.md # Performance ideas
├── tasks.md                      # Task tracking
├── SPEC.md                       # Original specification
└── README.md                     # User-facing documentation
```

## Development Workflow

### 1. Proof Generation (Noir + bb)

```bash
cd test-circuits/<circuit_name>

# Compile + execute
nargo compile && nargo execute

# Generate ZK proof (ALWAYS use keccak + zk for Solana)
~/.bb/bb prove \
    -b ./target/<circuit>.json \
    -w ./target/<circuit>.gz \
    --oracle_hash keccak --zk \
    -o ./target/keccak

# Generate VK
~/.bb/bb write_vk \
    -b ./target/<circuit>.json \
    --oracle_hash keccak \
    -o ./target/keccak
```

Or use `./build_all.sh <circuit_name>` from `test-circuits/`.

### 2. Build & Deploy Verifier Program

```bash
# Build the verifier program (circuit-agnostic)
cd programs/ultrahonk-verifier
cargo build-sbf

# Start local validator
surfpool  # or: solana-test-validator

# Deploy
solana program deploy target/deploy/ultrahonk_verifier.so \
    --url http://127.0.0.1:8899 --use-rpc
# → Note the Program Id
```

### 3. Run End-to-End Test

```bash
cd /path/to/solana-noir-verifier

# Set environment variables
export PROGRAM_ID=<program_id_from_deploy>
export RPC_URL=http://127.0.0.1:8899
export CIRCUIT=simple_square  # optional, defaults to simple_square

# Run test
node scripts/solana/test_phased.mjs
```

Expected output:
- Circuit Deployment: ~0.8s (one-time)
- Proof Verification: ~6s (8 TXs, ~5.4M CUs)

### 4. Testing

```bash
# Unit tests
cargo test -p plonk-solana-core

# All tests
cargo test --workspace

# On-chain test (requires surfpool running)
PROGRAM_ID=<id> RPC_URL=http://127.0.0.1:8899 node scripts/solana/test_phased.mjs
```

## Key External References

### Barretenberg Solidity Verifier

- **Source**: Generated via `bb contract -k ./vk -o ./HonkVerifier.sol --oracle_hash keccak`
- **Ground truth** for challenge generation, subrelation formulas, wire indices
- Use `-d` flag with `bb verify` for debug output showing internal values

### yugocabrio/ultrahonk-rust-verifier

- **GitHub**: `https://github.com/yugocabrio/ultrahonk-rust-verifier`
- Complete Rust UltraHonk verifier matching bb 0.87
- **Algorithm reference** (uses arkworks, not Solana-compatible)
- Key modules: `transcript.rs`, `sumcheck.rs`, `shplemini.rs`, `relations.rs`

### groth16-solana (Light Protocol)

- **GitHub**: `https://github.com/Lightprotocol/groth16-solana`
- Reference for Solana BN254 syscall usage patterns
- ~81k CUs for Groth16 (much simpler than UltraHonk's ~5.4M)

### Barretenberg

- **GitHub**: `https://github.com/AztecProtocol/barretenberg`
- Source of truth for Noir proof format
- Use `bb --version` to verify you're on 0.87.x

## bb 0.87 Constants

```rust
PROOF_SIZE = 16_224         // ZK mode proof size
VK_SIZE = 1_760             // VK size
CONST_PROOF_SIZE_LOG_N = 28 // Max supported log_n
NUMBER_OF_ENTITIES = 40     // Wire count
NUMBER_OF_SUBRELATIONS = 26 // Relation count
NUMBER_OF_ALPHAS = 25       // Alpha challenges
VK_NUM_COMMITMENTS = 27     // G1 points in VK
```

## Test Circuits

| Circuit | log_n | Description |
|---------|-------|-------------|
| simple_square | 12 | Basic x²=y (fastest) |
| iterated_square_* | 12-16 | Scalability tests |
| hash_batch | 17 | Blake3 hashing |
| merkle_membership | 18 | Merkle proofs |

Files per circuit: `proof` (16,224 bytes), `vk` (1,760 bytes), `public_inputs`

Rebuild: `cd test-circuits && ./build_all.sh`

## Debugging Commands

```bash
# Get bb's internal challenge values
bb verify -d -p ./proof -k ./vk --oracle_hash keccak --zk

# Generate Solidity verifier for reference
bb contract -k ./vk -o ./HonkVerifier.sol --oracle_hash keccak

# Check bb version
~/.bb/bb --version  # Should be 0.87.x

# Run local validator
surfpool  # Surfnet (recommended)
# or
solana-test-validator
```

If challenges don't match:
1. Check transcript element order matches Solidity
2. Verify G1 points are in **limbed format** (128 bytes)
3. Check for missing libra commitments (ZK mode)

## Error Handling

- Use custom error types, not panics
- Return `ProgramError::Custom(code)` in Solana programs
- Surface verification failures clearly, don't mask them

## Documentation Updates

After completing work:
- Update `tasks.md` with status
- Update `docs/knowledge.md` with discoveries
- Update `README.md` if commands change

## Cost Estimates (Mainnet)

| Component | Cost |
|-----------|------|
| Per proof verification | ~$1.10 (8 TXs, priority fees) |
| Circuit deployment | ~$0.003 (one-time) |
| Rent deposits (recoverable) | ~$33 per proof |

## Current Priority Tasks (from tasks.md)

### Phase 1: SDK & Production Readiness (CURRENT)

1. **Production-Grade Abstractions** (Research Required)
   - [ ] Upload integrity verification
   - [ ] Enhanced verification status tracking
   - [ ] Error handling and recovery
   - [ ] Document findings in `docs/design-decisions.md`

2. **Rust CLI Tool** (NOT STARTED)
   - [ ] Create `noir-solana-verify` CLI
   - [ ] Commands: deploy, upload-vk, verify, status

3. **VK Account Support** (NOT STARTED)
   - [ ] Add `UploadVK` instruction
   - [ ] Update phases to accept VK account
   - [ ] VK account validation

4. **Code Cleanup** (Ongoing)
   - [ ] Clean up test scripts
   - [ ] Improve program organization
   - [ ] Update README

### Phase 2: Code Reorganization (Prep for UltraPlonk)

- [ ] Move UltraHonk code into dedicated directories
- [ ] Extract shared code into `common` crate
- [ ] Prepare for multi-system support

## Recent Work (Last 5 Commits)

1. **866a7c2**: Added notes for future documentation on integrator-funded verification rent
2. **2e355f0**: Optimization and account closing improvements
3. **166c2c9**: Code cleanup
4. **65c46bb**: Cleaner execution patterns
5. **d6d4d97**: Chunk management improvements

## Performance Highlights

**Current (simple_square circuit)**:
- Total: 6.64M CUs across 9 transactions
- Phase 1 (Challenges): 287K CUs, 1 TX
- Phase 2 (Sumcheck): 3.82M CUs, 3 TXs
- Phase 3 (MSM): 2.48M CUs, 4 TXs
- Phase 4 (Pairing): 55K CUs, 1 TX

**Optimizations Implemented**:
- Montgomery multiplication: **-87% CUs**
- Batch inversion: **-38% sumcheck CUs, -60% fold CUs**
- FrLimbs in sumcheck: **-24% Phase 2**
- Zero-copy proof parsing: **-47% transactions**
- Parallel proof upload: **19 chunks in ~0.8s**
