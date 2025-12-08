# zkVerify Proof Compression Experiment

**Goal**: Generate UltraHonk proofs from Noir circuits, compress them via zkVerify, and verify the resulting Groth16 proof on Solana.

## Pipeline Overview

```
┌─────────────┐     ┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│    Noir     │     │  UltraHonk  │     │   zkVerify   │     │   Solana    │
│   Circuit   │────▶│    Proof    │────▶│  Aggregation │────▶│   Groth16   │
│  (any size) │     │   (~5 KB)   │     │   Receipt    │     │  Verifier   │
└─────────────┘     └─────────────┘     └──────────────┘     └─────────────┘
                                              │
                                              ▼
                                        ┌──────────────┐
                                        │  Groth16     │
                                        │  Proof       │
                                        │  (256 bytes) │
                                        └──────────────┘
```

## Why This Matters

| Aspect            | Direct UltraHonk    | zkVerify Compression           |
| ----------------- | ------------------- | ------------------------------ |
| **Proof Size**    | ~5 KB               | **256 bytes**                  |
| **Solana CU**     | ~200-400K (complex) | **~81K**                       |
| **Trusted Setup** | Universal           | Per-circuit (done by zkVerify) |
| **Latency**       | Instant             | ~minutes (aggregation)         |

**Trade-off**: You trade latency for smaller proofs and cheaper verification.

## Directory Structure

```
zkverify-compression/
├── README.md                 # This file
├── TESTING.md               # Step-by-step testing guide
├── circuits/
│   └── hello_world/         # Sample Noir circuit
│       ├── src/main.nr
│       ├── Nargo.toml
│       └── Prover.toml
├── scripts/
│   ├── 1-generate-proof.sh  # Generate UltraHonk proof
│   ├── 2-convert-hex.sh     # Convert to zkVerify format
│   ├── 3-submit-zkverify.mjs # Submit to zkVerify
│   └── 4-verify-solana.mjs  # Verify on Solana
├── solana-verifier/         # Reuse from groth16-alternative
└── output/                  # Generated artifacts
```

## Prerequisites

### 1. Noir Toolchain

```bash
# Install noirup
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
noirup

# Install bbup (Barretenberg)
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash

# Use version compatible with zkVerify (0.84.x)
bbup -v 0.84.0
```

### 2. zkVerify Account

1. Create a wallet on [zkVerify Volta testnet](https://docs.zkverify.io)
2. Get testnet $tVFY tokens from faucet
3. Save your seed phrase for the scripts

### 3. Node.js Dependencies

```bash
cd scripts
npm install
```

## Quick Start

```bash
# 1. Generate UltraHonk proof from Noir circuit
./scripts/1-generate-proof.sh

# 2. Convert to zkVerify hex format
./scripts/2-convert-hex.sh

# 3. Submit to zkVerify and get Groth16 receipt
node scripts/3-submit-zkverify.mjs

# 4. Verify Groth16 receipt on Solana (Surfpool)
node scripts/4-verify-solana.mjs
```

## How zkVerify Compression Works

1. **You submit**: UltraHonk proof (~5KB) + VK + public inputs
2. **zkVerify verifies**: The UltraHonk proof is verified on zkVerify's chain
3. **Aggregation**: Multiple proofs are batched into a single Groth16 proof
4. **Receipt**: You get an "attestation" containing:
   - Groth16 proof (256 bytes)
   - Merkle path proving your proof was included
   - Public commitment to verify

## Integration with Solana

The attestation from zkVerify contains a Groth16 proof that can be verified using our existing `groth16-solana` verifier from `experiments/groth16-alternative/`.

The key insight: **The Groth16 proof attests that zkVerify correctly verified your UltraHonk proof.**

## Cost Comparison

| Step                     | Cost                   |
| ------------------------ | ---------------------- |
| Generate UltraHonk proof | Free (local)           |
| Submit to zkVerify       | ~$0.01 in $tVFY        |
| Verify Groth16 on Solana | ~81K CU (~0.00008 SOL) |
| **Total**                | **~$0.01**             |

Compare to verifying UltraHonk directly on Solana: ~200-400K CU, larger tx size.

## Limitations

1. **Latency**: Aggregation takes minutes, not instant
2. **Trust**: You trust zkVerify's aggregation is correct
3. **Availability**: Depends on zkVerify service being online
4. **No Local Option**: zkVerify runs aggregation on their network (see alternatives below)

## Local Alternatives

**Can't use zkVerify?** See [LOCAL_ALTERNATIVES.md](./LOCAL_ALTERNATIVES.md) for options:

| Approach | Noir Support | Local | Complexity |
|----------|--------------|-------|------------|
| **Direct gnark** | ❌ Go DSL | ✅ | Low |
| **zkVerify** | ✅ Full | ❌ | Low |
| **SP1 Wrapping** | ✅ Full | ✅ | Medium |
| **gnark Recursive** | ❌ Custom | ✅ | Very High |

**Recommendation**: 
- Simple circuits → Direct gnark (`../groth16-alternative/`)
- Full Noir support needed → zkVerify or SP1

## References

- [zkVerify Documentation](https://docs.zkverify.io)
- [Generating Proofs (Noir UltraHonk)](https://docs.zkverify.io/tutorials/submit-proofs/noir)
- [zkVerifyJS SDK](https://docs.zkverify.io/overview/getting-started/zkverify-js)
- [Our Groth16 Solana Verifier](../groth16-alternative/)
