# Manual Testing Guide: Groth16 on Solana

This guide walks you through manually testing Groth16 proof generation and verification on Solana using two approaches.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Option 1: Direct gnark (Go)](#option-1-direct-gnark-go)
3. [Option 2: Noir → gnark Backend](#option-2-noir--gnark-backend)
4. [Deploy & Verify on Solana](#deploy--verify-on-solana)
5. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Tools

```bash
# Check Go (for gnark)
go version  # Need Go 1.21+

# Check Rust (for Solana verifier)
rustc --version  # Need 1.70+
cargo --version

# Check Solana CLI
solana --version  # Need 1.18+ or Anza 2.x

# Check Surfpool (optional, for local Solana testing)
# Install from: https://github.com/txtx/surfpool
```

### Install Surfpool MCP (for Cursor integration)

Surfpool integrates with Cursor for local Solana testing. It should already be running if you're using this repo.

---

## Option 1: Direct gnark (Go)

### Step 1: Locate the Circuit

The circuit is defined in Go using gnark's DSL:

```bash
cat gnark/circuit.go
```

```go
// SimpleCircuit proves knowledge of x such that x*x == y
type SimpleCircuit struct {
    X frontend.Variable `gnark:",private"`  // Private input
    Y frontend.Variable `gnark:",public"`   // Public input
}

func (circuit *SimpleCircuit) Define(api frontend.API) error {
    result := api.Mul(circuit.X, circuit.X)
    api.AssertIsEqual(result, circuit.Y)
    return nil
}
```

**Circuit location:** `experiments/groth16-alternative/gnark/circuit.go`

### Step 2: Compile & Trusted Setup

```bash
cd experiments/groth16-alternative/gnark

# Build the gnark program
go build -o groth16-experiment .

# Run with default witness (x=3, y=9)
./groth16-experiment

# Or run with custom values
# (edit main.go to change witness values)
```

**Expected output:**

```
=== gnark Groth16 Experiment ===

Step 1: Compiling circuit...
  Circuit compiled in 605.958µs
  Number of constraints: 2
  Number of public inputs: 1

Step 2: Running trusted setup...
  Setup completed in 3.979959ms

Step 3: Creating witness...
  Witness created (x=3, y=9)

Step 4: Generating proof...
  Proof generated in 1.419541ms

Step 5: Verifying proof...
  Proof verified in 1.119416ms

Step 6: Exporting for Solana...
  Proof size: 256 bytes
  VK size: 488 bytes
```

### Step 3: Check Generated Artifacts

```bash
ls -la gnark/output/

# proof.bin    - 256 bytes, the Groth16 proof
# proof.hex    - Hex-encoded proof (for debugging)
# public.bin   - 32 bytes, public input (y=9)
# vk.bin       - Verification key (raw)
# vk_rust.rs   - Rust constants for Solana program
```

### Step 4: Verify Locally (Off-chain)

The gnark program already verifies locally during Step 5. To re-verify:

```bash
cd gnark
./groth16-experiment
# Look for "Step 5: Verifying proof... Proof verified"
```

### Step 5: Run Scalability Benchmarks (Optional)

```bash
cd gnark
./groth16-experiment benchmark

# Tests circuits from 100 to 100,000 constraints
# Shows proving time, verification time, and proof size
```

---

## Option 2: Noir → gnark Backend

> ⚠️ **Important:** This backend only works with **OLD Noir** (pre-1.0, ACVM 0.5).
> It is NOT compatible with Noir 1.0+.

### Step 1: Setup the Backend

```bash
cd experiments/groth16-alternative/noir-gnark

# Clone and build the backend
./setup.sh
```

This will:

1. Clone `lambdaclass/noir_backend_using_gnark`
2. Build the Go library (gnark backend FFI)
3. Build the Rust binary

### Step 2: Locate Test Circuits

The backend includes several test circuits:

```bash
ls noir-gnark/noir_backend_using_gnark/tests/test_programs/
```

**Simple circuits available:**

- `priv_x_eq_pub_y/` - Proves x == y
- `bool_not/` - Boolean NOT
- `bool_or/` - Boolean OR
- `pred_eq/` - Predicate equality

### Step 3: View a Test Circuit

```bash
cat noir-gnark/noir_backend_using_gnark/tests/test_programs/priv_x_eq_pub_y/src/main.nr
```

```noir
fn main(x: pub Field, y: Field) {
    assert(x == y);
}
```

**Witness values:** `Prover.toml`

```toml
x = "5"
y = "5"
```

### Step 4: Compile & Prove (Experimental)

```bash
cd noir-gnark

# The backend expects old-style nargo compile output
# This is experimental and may require manual intervention

./noir_backend_using_gnark/target/release/noir_backend_using_gnark --help
```

**Note:** Since this backend is for old Noir, you may need to:

1. Install an old version of nargo (pre-1.0)
2. Compile circuits to ACIR 0.5 format
3. Use the backend to generate Groth16 proofs

See `noir-gnark/README.md` for detailed compatibility notes.

---

## Deploy & Verify on Solana

### Step 1: Check the Solana Verifier Program

The verifier program is pre-configured with the gnark-generated VK:

```bash
cat solana-verifier/src/lib.rs
```

Key components:

- `VERIFYING_KEY` - Embedded verification key
- `process_instruction()` - Parses proof + public inputs, calls `groth16-solana`

### Step 2: Run Integration Tests

```bash
cd experiments/groth16-alternative/solana-verifier

# Run all tests
cargo test -- --nocapture
```

**Expected output:**

```
running 5 tests
test test_id ... ok
test tests::test_vk_structure ... ok
✅ Invalid proof correctly rejected
test test_groth16_verify_invalid_proof ... ok
✅ Groth16 proof verified successfully!
test test_groth16_verify_valid_proof ... ok
✅ Wrong public input correctly rejected
test test_groth16_verify_wrong_public_input ... ok

test result: ok. 5 passed; 0 failed
```

### Step 3: Start Surfpool (Local Solana)

**Option A: Via Cursor MCP (recommended)**

Surfpool should start automatically. Check if it's running:

```bash
# If using Surfpool MCP, it will show the URL
# Example: http://127.0.0.1:18899
```

**Option B: Manual Start**

```bash
# In a separate terminal
surfpool start
```

### Step 4: Build & Deploy the Program

> ⚠️ **Note:** BPF build may have toolchain issues. The integration tests use `ProgramTest` which accurately simulates the BPF environment.

```bash
cd solana-verifier

# Try building for Solana BPF
cargo build-sbf

# If build succeeds, deploy to Surfpool
solana config set --url http://127.0.0.1:18899
solana program deploy target/deploy/groth16_verifier.so
```

If `cargo build-sbf` fails (common issue with newer dependencies), the integration tests still validate the full verification logic.

### Step 5: Verify a Proof On-Chain

**Option A: Using the Node.js script (recommended for manual testing)**

```bash
cd scripts
npm install  # First time only
node verify.mjs
```

**Expected output:**

```
=== Groth16 Manual Verification on Solana ===

RPC URL: http://127.0.0.1:8899
Program ID: 4ac1awNJe1AyXQnmZN9yyMKAmNo45fknjtyD4FDEmGez
Proof size: 256 bytes
Public input size: 32 bytes
Public input (y=9): 0x0000000000000000000000000000000000000000000000000000000000000009

✅ Groth16 proof verified successfully!

Signature: dKhDWdGyd4K7Vy7jywMLuNtGN9zsuKRQeVTayUbLFYk...
Time: 307ms
Compute Units: 81147
```

**Option B: Using the test harness**

The integration test also works:

```rust
// From integration_test.rs
let mut instruction_data = Vec::with_capacity(256 + 32);
instruction_data.extend_from_slice(PROOF);       // 256 bytes
instruction_data.extend_from_slice(PUBLIC_INPUT); // 32 bytes

let instruction = Instruction {
    program_id: groth16_verifier::id(),
    accounts: vec![],
    data: instruction_data,
};
```

**Instruction data format:**

- Bytes 0-255: Proof (π_A negated || π_B || π_C)
- Bytes 256-287: Public input (32-byte big-endian field element)

---

## Full End-to-End Test (Direct gnark)

```bash
# 1. Generate fresh proof and VK
cd experiments/groth16-alternative/gnark
go run .
# This creates:
#   - output/proof.bin     (256 bytes - the proof)
#   - output/public.bin    (32 bytes - public input y=9)
#   - output/vk_solana.bin (576 bytes - VK in binary format)

# 2. Rebuild and test Solana verifier
cd ../solana-verifier
cargo test -- --nocapture
# The VK is loaded from vk_solana.bin via include_bytes!
# No manual copying required!

# 3. Check verification passed
# Look for: "✅ Groth16 proof verified successfully!"
```

### How VK Auto-Loading Works

The Solana verifier uses `include_bytes!("../../gnark/output/vk_solana.bin")` to embed the VK at compile time. Binary layout:

| Offset    | Size    | Component |
| --------- | ------- | --------- |
| 0         | 64      | Alpha G1  |
| 64        | 128     | Beta G2   |
| 192       | 128     | Gamma G2  |
| 320       | 128     | Delta G2  |
| 448       | 64      | IC[0]     |
| 512       | 64      | IC[1]     |
| **Total** | **576** |           |

---

## File Summary

| Path                                        | Description                                         |
| ------------------------------------------- | --------------------------------------------------- |
| `gnark/circuit.go`                          | Circuit definition (x\*x == y)                      |
| `gnark/main.go`                             | Proof generation & export                           |
| `gnark/output/proof.bin`                    | Generated proof (256 bytes)                         |
| `gnark/output/public.bin`                   | Public input (32 bytes)                             |
| `gnark/output/vk_solana.bin`                | **Binary VK for Solana (576 bytes)** ← Auto-loaded! |
| `gnark/output/vk_rust.rs`                   | VK as Rust constants (reference)                    |
| `solana-verifier/src/lib.rs`                | Solana verifier program                             |
| `solana-verifier/tests/integration_test.rs` | E2E tests                                           |
| `scripts/verify.mjs`                        | **Manual verification script (Node.js)** ← NEW!     |
| `noir-gnark/setup.sh`                       | Noir backend setup                                  |
| `noir-gnark/README.md`                      | Noir backend details                                |

---

## Troubleshooting

### "Proof verification failed" after regenerating proof

**This should no longer happen!** The Solana verifier now loads the VK from `vk_solana.bin` using `include_bytes!`. After regenerating the proof:

```bash
# 1. Generate new proof and VK
cd gnark && go run .

# 2. Rebuild Solana verifier (picks up new VK automatically)
cd ../solana-verifier && cargo test
```

The VK is embedded at compile time from `gnark/output/vk_solana.bin`.

### "cargo build-sbf fails with edition2024"

This is a toolchain compatibility issue. The integration tests still work because they use `ProgramTest` which doesn't require BPF compilation.

**Workaround:** Use the integration tests to validate logic.

### "noir_backend_using_gnark not compatible"

The LambdaClass backend only supports old Noir (ACVM 0.5). If you need Noir 1.0+, use the direct gnark approach and rewrite your circuit in Go.

### "Proof verification failed"

1. Ensure proof and VK were generated together (same trusted setup)
2. Check public input encoding (32-byte big-endian)
3. Verify proof_a negation is handled correctly

### "Surfpool not responding"

```bash
# Check if Surfpool is running
curl http://127.0.0.1:18899 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}'
```

---

## Quick Reference: CU Costs

### Actual Measurement (Surfpool)

| Metric               | Value            |
| -------------------- | ---------------- |
| **Compute Units**    | **81,147 CU** ✅ |
| **Transaction Time** | ~300ms           |

### Theoretical Breakdown

| Operation     | Compute Units    |
| ------------- | ---------------- |
| Pairing check | ~113K × 2 = 226K |
| G1 scalar mul | ~12.5K           |
| G1 addition   | ~500             |
| **Estimated** | ~200K CU         |
| **Actual**    | **~81K CU** ✅   |

The actual CU is much lower than estimated! This is **constant** regardless of circuit size.

---

## Next Steps

1. **Modify the circuit** - Edit `gnark/circuit.go`
2. **Regenerate proof** - Run `go run .` in gnark/
3. **Rebuild verifier** - Run `cargo test` in solana-verifier/ (VK auto-loads!)
4. **Deploy to devnet** - Use `solana program deploy` with devnet RPC
5. **Measure real CU** - Check transaction logs on devnet/mainnet
