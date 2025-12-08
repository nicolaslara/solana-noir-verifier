# Groth16 Alternative Experiment

This experiment explores using **Groth16** as an alternative to **UltraHonk** for Solana ZK verification.

## Two Approaches

We explore **two different paths** to Groth16 proofs, each with tradeoffs:

| Approach         | Circuit Language | Status               | Best For                   |
| ---------------- | ---------------- | -------------------- | -------------------------- |
| **Direct gnark** | Go               | ✅ Working           | New projects, full control |
| **Noir → gnark** | Noir             | ⚠️ Requires old Noir | Existing Noir codebases    |

## Comparison

| Aspect               | Direct gnark    | Noir + gnark Backend |
| -------------------- | --------------- | -------------------- |
| **Proof Size**       | 256 bytes       | 256 bytes            |
| **Verification CU**  | <200K           | <200K                |
| **Circuit Language** | Go              | Noir                 |
| **Learning Curve**   | Learn gnark DSL | Know Noir            |
| **Noir Version**     | N/A             | Pre-1.0 only         |
| **Gadget Support**   | Full gnark      | Limited              |
| **Trusted Setup**    | Per-circuit     | Per-circuit          |

## Approach 1: Direct gnark (✅ Recommended)

Write circuits directly in gnark's Go DSL.

```bash
cd gnark
go run .           # Generate proof
go run . benchmark # Scalability test
```

**Pros:**

- Full gnark feature support
- No compatibility issues
- Already integrated with groth16-solana
- All tests passing

**Cons:**

- Must write circuits in Go (not Noir)
- Different DSL to learn

**Files:**

- `gnark/circuit.go` - Circuit definition
- `gnark/main.go` - Proof generation
- `gnark/output/` - Proof & VK files

## Approach 2: Noir → gnark Backend

Uses [lambdaclass/noir_backend_using_gnark](https://github.com/lambdaclass/noir_backend_using_gnark) to compile Noir circuits to gnark.

```bash
cd noir-gnark
./setup.sh  # Clone and build
```

**Pros:**

- Write circuits in Noir
- Familiar syntax for Noir developers
- SHA256, Blake2s, ECDSA supported

**Cons:**

- ⚠️ Only works with **OLD Noir** (pre-1.0, ACVM 0.5)
- Requires forked nargo
- Limited gadget support (no Pedersen, Keccak)

**Files:**

- `noir-gnark/setup.sh` - Build script
- `noir-gnark/noir_backend_using_gnark/` - Cloned backend

## Solana Verification

Both approaches produce the same Groth16 proof format (256 bytes) that can be verified on Solana using [groth16-solana](https://github.com/Lightprotocol/groth16-solana).

```bash
cd solana-verifier
cargo test -- --nocapture
```

**Results:**

- ✅ Valid proof verified
- ✅ Invalid proof rejected
- ✅ Wrong public input rejected

## Why Groth16?

Compare with the default Noir backend (UltraHonk):

| Metric            | UltraHonk | Groth16                      |
| ----------------- | --------- | ---------------------------- |
| **Proof Size**    | ~5 KB     | **256 bytes** (20x smaller!) |
| **Verification**  | Variable  | **Constant**                 |
| **Solana CU**     | ~200-400K | **<200K**                    |
| **Trusted Setup** | Universal | Per-circuit                  |

## Quick Start

See **[TESTING.md](./TESTING.md)** for detailed step-by-step manual testing instructions.

### Option A: Direct gnark (Go)

```bash
# 1. Generate proof
cd gnark
go run .

# 2. Test on Solana
cd ../solana-verifier
cargo test -- --nocapture
```

### Option B: Noir → gnark (Old Noir)

```bash
# 1. Setup the backend
cd noir-gnark
./setup.sh

# 2. Install forked nargo (old Noir)
cargo install --force --git https://github.com/lambdaclass/noir --branch fork nargo

# 3. Use with Noir circuits
nargo compile
nargo prove
```

## Directory Structure

```
groth16-alternative/
├── README.md                # This file
├── TESTING.md               # 📋 Manual testing guide
├── gnark/                   # Approach 1: Direct gnark (Go)
│   ├── circuit.go          # SimpleSquare circuit
│   ├── main.go             # Proof generation
│   ├── benchmark.go        # Scalability tests
│   └── output/             # Generated proof & VK
├── noir-gnark/              # Approach 2: Noir → gnark
│   ├── README.md           # Detailed setup guide
│   ├── setup.sh            # Build script
│   └── noir_backend_using_gnark/  # Cloned backend
├── solana-verifier/         # Solana program (works with both!)
│   ├── src/lib.rs          # Verifier with embedded VK
│   └── tests/              # Integration tests
└── benchmarks/
    └── results.md          # Performance comparison
```

## Benchmarks

### gnark Performance (Apple Silicon)

| Constraints | Proving | Verification | Proof Size |
| ----------- | ------- | ------------ | ---------- |
| 100         | 2.8ms   | 1.5ms        | 256 bytes  |
| 1,000       | 11.6ms  | 1.1ms        | 256 bytes  |
| 10,000      | 61.7ms  | 1.1ms        | 256 bytes  |
| 100,000     | 431ms   | 1.1ms        | 256 bytes  |

**Key insight:** Verification time and proof size remain **constant** regardless of circuit complexity!

## Future Work

1. **Port lambdaclass backend to Noir 1.0** - Major effort but valuable
2. **Benchmark UltraHonk CU** on Solana for direct comparison
3. **Deploy to devnet** for real-world CU measurement
4. **Evaluate trusted setup** requirements for production circuits
