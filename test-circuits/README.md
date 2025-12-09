# Test Circuits

This directory contains Noir test circuits for benchmarking and testing the UltraHonk verifier.

## Building Circuits

```bash
# Build all circuits
./build_all.sh

# Build a specific circuit
./build_all.sh <circuit_name>
```

Each circuit is compiled with `nargo`, then proved and verified with `bb` (Barretenberg CLI) using:

- `--scheme ultra_honk`
- `--oracle_hash keccak`

## Circuit Summary

| Circuit                | ACIR Opcodes | n (circuit size) | log_n | Proof Size | Features             |
| ---------------------- | ------------ | ---------------- | ----- | ---------- | -------------------- |
| `simple_square`        | 1            | 4,096            | 12    | 16,224     | Basic arithmetic     |
| `iterated_square_100`  | 100          | 4,096            | 12    | 14,592     | 100 iterations       |
| `iterated_square_1000` | 1,000        | 8,192            | 13    | 14,592     | 1k iterations        |
| `iterated_square_10k`  | 10,000       | 16,384           | 14    | 14,592     | 10k iterations       |
| `iterated_square_100k` | 100,000      | 131,072          | 17    | 14,592     | 100k iterations      |
| `hash_batch`           | 2,112        | 131,072          | 17    | 14,592     | 32× blake3 + XOR     |
| `merkle_membership`    | 2,688        | 262,144          | 18    | 14,592     | 16-level Merkle tree |
| `fib_chain_100`        | 1            | 4,096            | 12    | 14,592     | Fibonacci chain      |

## Key Observations

- **Proof size is constant** (14,592 bytes) regardless of circuit complexity
- All proofs have exactly **456 field elements**
- Hash operations (blake3) expand circuit size significantly more than arithmetic:
  - `hash_batch` (2,112 opcodes) → log_n=17
  - `merkle_membership` (2,688 opcodes) → log_n=18
  - `iterated_square_100k` (100,000 opcodes) → log_n=17

## Circuit Descriptions

### Arithmetic Circuits

- **`simple_square`** - Basic `x² = y` constraint (minimal circuit)
- **`iterated_square_*`** - Repeated squaring: `x^(2^n)` where n = 100, 1000, 10000, 100000
- **`fib_chain_100`** - 100 Fibonacci iterations

### Hash-Heavy Circuits

- **`hash_batch`** - Processes 1024 bytes in 32-byte chunks with blake3, XOR-folds results
- **`merkle_membership`** - 16-level Merkle tree membership proof using blake3

## Output Structure

After building, each circuit has:

```
<circuit>/
├── Nargo.toml          # Circuit manifest
├── Prover.toml         # Witness inputs
├── src/main.nr         # Circuit code
└── target/
    ├── <circuit>.json  # Compiled circuit (ACIR)
    ├── <circuit>.gz    # Witness
    └── keccak/
        ├── proof                    # Binary proof
        ├── proof_fields.json        # Proof as field elements
        ├── vk                       # Binary verification key
        ├── vk_fields.json           # VK as field elements
        ├── public_inputs            # Binary public inputs
        └── public_inputs_fields.json
```

## Getting Circuit Info

```bash
cd <circuit>
nargo info  # Shows ACIR opcode count
```
