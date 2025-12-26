# Testing Guide

This document describes the testing strategy for the Solana Noir Verifier.

## Quick Test

Run all tests:

```bash
cargo test --workspace
```

Expected: **62 tests pass, 0 failures**

## Test Levels

### 1. Unit Tests

Located in each module's `#[cfg(test)]` section:

- **plonk-core** (59 tests): Core verification logic
  - Field arithmetic
  - Transcript operations
  - Sumcheck protocol
  - Relation evaluation
  - Shplemini batch opening
  - Full proof verification for 7 circuits
- **vk-codegen** (1 test): VK parsing and code generation
- **sample-integrator** (1 test): Example integration
- **verifier-cpi** (1 test): CPI interface

Run specific test suites:

```bash
# Core library only
cargo test -p plonk-solana-core

# With output
cargo test -- --nocapture

# Specific test
cargo test test_valid_proof_verifies
```

### 2. Integration Tests

Integration tests verify end-to-end workflows:

```bash
# Test all 7 circuits
cargo test -p plonk-solana-core test_all_available_circuits -- --nocapture
```

Test circuits:
- `simple_square` (log_n=12, 1 public input)
- `iterated_square_100` (log_n=12, 1 public input)
- `iterated_square_1000` (log_n=13, 1 public input)
- `iterated_square_10k` (log_n=14, 1 public input)
- `fib_chain_100` (log_n=12, 1 public input)
- `hash_batch` (log_n=17, 32 public inputs)
- `merkle_membership` (log_n=18, 32 public inputs)

### 3. Solana BPF Build

Verify the program compiles to BPF:

```bash
cd programs/ultrahonk-verifier
CIRCUIT=simple_square cargo build-sbf

# Verify artifact exists
ls -lh target/deploy/ultrahonk_verifier.so
```

### 4. Surfpool Testing (Optional)

Test on a local Solana validator using [Surfpool](https://github.com/txtx/surfpool).

#### Prerequisites

```bash
# Install Surfpool
npm install -g @txtx/surfpool

# Install Solana CLI (if not already installed)
sh -c "$(curl -sSfL https://release.solana.com/stable/install)"
```

#### Run Test

```bash
# Terminal 1: Start local validator
surfpool start

# Terminal 2: Build, deploy, and test
cd programs/ultrahonk-verifier
CIRCUIT=simple_square cargo build-sbf
solana program deploy target/deploy/ultrahonk_verifier.so \
  --url http://127.0.0.1:8899 \
  --use-rpc

cd ../..
CIRCUIT=simple_square node scripts/solana/test_phased.mjs
```

Expected output:
```
Phase 1 (Challenges): 287K CUs (1 TX)
Phase 2 (Sumcheck):   3.82M CUs (3 TXs)
Phase 3 (MSM):        2.48M CUs (4 TXs)
Phase 4 (Pairing):    55K CUs (1 TX)
Total: 6.64M CUs across 9 transactions
🎉 All phases passed! Verification complete.
```

Test other circuits:
```bash
CIRCUIT=hash_batch cargo build-sbf
solana program deploy target/deploy/ultrahonk_verifier.so --url http://127.0.0.1:8899 --use-rpc
CIRCUIT=hash_batch node scripts/solana/test_phased.mjs
```

## Continuous Integration

### Automated Workflows

The project uses GitHub Actions for CI:

1. **CI Workflow** (`.github/workflows/ci.yml`)
   - Runs on all PRs and pushes to main
   - Checks code formatting
   - Builds debug and release
   - Runs all tests
   - Runs clippy lints
   - Builds BPF programs
   - Ensures zero compilation warnings

2. **Surfpool Test Workflow** (`.github/workflows/surfpool-test.yml`)
   - Manual trigger or on releases
   - Deploys to local Surfpool validator
   - Runs end-to-end verification test

### Local CI Checks

Run the same checks as CI locally:

```bash
# Format check
cargo fmt --all -- --check

# Build both debug and release
cargo build --workspace --all-targets
cargo build --workspace --release

# Run all tests
cargo test --workspace --all-targets

# Clippy (lib only, no warnings allowed)
cargo clippy --workspace --lib --all-features -- -D warnings

# Build BPF
cd programs/ultrahonk-verifier
CIRCUIT=simple_square cargo build-sbf
cd ../..
```

## Rebuilding Test Circuits

If you modify circuits or need fresh proofs:

```bash
cd test-circuits

# Build all circuits
./build_all.sh

# Or build specific circuit
./build_all.sh simple_square
```

This runs: `nargo compile` → `nargo execute` → `bb prove` → `bb write_vk`

## Troubleshooting

### Tests Fail After Changes

1. Check if test circuits need rebuilding:
   ```bash
   cd test-circuits && ./build_all.sh && cd ..
   cargo test
   ```

2. Verify Noir and bb versions match:
   ```bash
   nargo --version  # Should be 1.0.0-beta.8
   bb --version     # Should be 0.87.x
   ```

### BPF Build Fails

1. Check Solana CLI is installed:
   ```bash
   solana --version
   cargo build-sbf --version
   ```

2. Try clean build:
   ```bash
   cd programs/ultrahonk-verifier
   cargo clean
   CIRCUIT=simple_square cargo build-sbf
   ```

### Surfpool Connection Issues

1. Verify Surfpool is running:
   ```bash
   solana cluster-version --url http://127.0.0.1:8899
   ```

2. Check logs:
   ```bash
   surfpool logs
   ```

3. Restart if needed:
   ```bash
   surfpool stop
   surfpool start
   ```

## Performance Testing

Measure compute units for different circuits:

```bash
# Requires deployed program on Surfpool
CIRCUIT=simple_square node scripts/solana/measure_cu.mjs
CIRCUIT=hash_batch node scripts/solana/measure_cu.mjs
```

## Test Coverage

Current test coverage:

- **Field operations**: 100% (tested via higher-level tests)
- **Transcript**: 100% (unit tests + integration)
- **VK/Proof parsing**: 100% (7 different circuits)
- **Sumcheck**: 100% (7 circuits with varying complexity)
- **Relations**: 100% (all 26 subrelations tested)
- **Shplemini**: 100% (batch opening with multiple polys)
- **Pairing**: 100% (KZG check on all circuits)
- **End-to-end**: 7 complete circuits verified
