# Noir → gnark Groth16 Backend

This experiment explores using [lambdaclass/noir_backend_using_gnark](https://github.com/lambdaclass/noir_backend_using_gnark) to generate **Groth16 proofs from Noir circuits**.

## ⚠️ Compatibility Warning

**The lambdaclass backend is built for OLD Noir (pre-1.0):**

| Component | lambdaclass version | Current version |
| --------- | ------------------- | --------------- |
| ACVM      | 0.5.0               | ~0.50+          |
| Noir      | Pre-1.0             | 1.0.0-beta.15   |
| nargo     | Forked version      | Standard nargo  |

**This means you CANNOT use this backend with Noir 1.0 circuits directly.**

## Options for Noir → Groth16

### Option 1: Direct gnark (✅ Working)

Write circuits directly in gnark's Go DSL. This is what we implemented in `../gnark/`.

**Pros:**

- Full gnark feature support
- No compatibility issues
- Already working with Solana

**Cons:**

- Must rewrite circuits in Go (not Noir)

### Option 2: Port lambdaclass Backend to Noir 1.0 (🔧 Major Effort)

Update the lambdaclass backend to work with modern Noir:

1. Update ACVM dependency (0.5 → 0.50+)
2. Implement new Noir backend protocol
3. Update ACIR parsing for new format
4. Test with Noir 1.0 circuits

**Effort:** Significant (weeks of work)

### Option 3: Use lambdaclass Backend with OLD Noir

Install their forked nargo and use older Noir syntax:

```bash
# Install their forked nargo (old Noir)
cargo install --force --git https://github.com/lambdaclass/noir --branch fork nargo

# Write circuits in old Noir syntax
```

**Cons:**

- Old Noir syntax/features
- Can't use modern Noir features
- Maintenance burden

## Architecture (How It Was Designed)

```
┌─────────────────────────────────────────────────────────────┐
│                    Noir Circuit (.nr)                       │
│  fn main(x: Field, y: pub Field) { constrain x == y; }      │
│  (Note: OLD syntax - 'constrain' vs 'assert')               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ nargo compile (FORKED)
┌─────────────────────────────────────────────────────────────┐
│                    ACIR v0.5 (JSON)                         │
│  Old format - different from modern ACIR                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ noir_backend_using_gnark
┌─────────────────────────────────────────────────────────────┐
│                    gnark (Go)                               │
│  - Translates ACIR → R1CS constraints                       │
│  - Trusted setup (circuit-specific)                         │
│  - Groth16/Plonk proving                                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 Groth16 Proof (256 bytes)                   │
│  π_A (G1) + π_B (G2) + π_C (G1)                             │
└─────────────────────────────────────────────────────────────┘
```

## Supported Black Box Functions (from backend.rs)

The lambdaclass backend supports:

- ✅ AND, XOR
- ✅ RANGE
- ✅ SHA256
- ✅ Blake2s
- ✅ HashToField128Security
- ✅ EcdsaSecp256k1

**Not Supported:**

- ❌ AES
- ❌ MerkleMembership
- ❌ SchnorrVerify
- ❌ Pedersen
- ❌ FixedBaseScalarMul
- ❌ Keccak256

## What We Built Instead

Since the lambdaclass backend doesn't work with modern Noir, we built a **direct gnark implementation** that:

1. ✅ Generates Groth16 proofs (256 bytes)
2. ✅ Exports VK in groth16-solana format
3. ✅ Verifies on Solana (<200K CU)
4. ✅ All tests passing

See `../gnark/` for the working implementation.

## Recommendations

### For production use:

1. **Use direct gnark** if you can rewrite circuits in Go
2. **Use UltraHonk** (default Noir backend) for full Noir support

### If you NEED Noir → Groth16:

1. **Contribute to lambdaclass** - Help update for Noir 1.0
2. **Fork and update** - Port the backend yourself
3. **Watch for updates** - The project may be updated eventually

## Files

```
noir-gnark/
├── README.md                    # This file
├── setup.sh                     # Setup script (builds, but incompatible)
├── prove.sh                     # Example workflow
└── noir_backend_using_gnark/    # Cloned repo
    ├── src/backend.rs           # Rust backend implementation
    └── gnark_backend_ffi/       # Go FFI code
```

## References

- [lambdaclass/noir_backend_using_gnark](https://github.com/lambdaclass/noir_backend_using_gnark) - Original repo
- [groth16-solana](https://github.com/Lightprotocol/groth16-solana) - Solana verification
- [gnark](https://github.com/consensys/gnark) - Go zk-SNARK library
