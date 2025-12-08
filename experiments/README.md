# Experiments

This directory contains experimental work exploring alternative ZK verification approaches on Solana.

## Experiments Overview

| Experiment                                      | Description                                                      | Status         |
| ----------------------------------------------- | ---------------------------------------------------------------- | -------------- |
| [groth16-alternative](./groth16-alternative/)   | Direct Groth16 proving/verification using gnark + groth16-solana | ✅ Complete    |
| [zkverify-compression](./zkverify-compression/) | UltraHonk → zkVerify compression → Groth16 on Solana             | 🚧 In Progress |

## groth16-alternative

Compares direct Groth16 proving (using gnark) with UltraHonk for Solana verification.

**Key Findings:**

- Groth16 proof size: **256 bytes** (vs ~5KB for UltraHonk)
- Verification CU: **81K** (constant, regardless of circuit size)
- 1M constraints: **~4s** proving time

**When to use:**

- Proof size matters (on-chain storage)
- Verification cost is critical
- Circuit is stable (amortize trusted setup)

See [groth16-alternative/benchmarks/results.md](./groth16-alternative/benchmarks/results.md) for full results.

## zkverify-compression

Pipeline for compressing UltraHonk proofs via zkVerify's aggregation service.

```
Noir → UltraHonk → zkVerify → Groth16 → Solana
```

**Benefits:**

- Use full Noir/UltraHonk ecosystem
- No per-circuit trusted setup (handled by zkVerify)
- Small Groth16 proof for Solana verification

**Trade-offs:**

- Latency: Aggregation takes minutes
- Trust: Depends on zkVerify service

See [zkverify-compression/TESTING.md](./zkverify-compression/TESTING.md) for usage guide.

## Running Experiments

Each experiment has its own README and testing guide. Generally:

```bash
cd <experiment-name>
# Follow the README.md or TESTING.md
```

## Comparison Matrix

| Aspect            | Direct UltraHonk | Direct Groth16 | zkVerify Compression   |
| ----------------- | ---------------- | -------------- | ---------------------- |
| **Proof Size**    | ~5 KB            | **256 bytes**  | **256 bytes**          |
| **Solana CU**     | 200-400K (est)   | **81K**        | **81K**                |
| **Trusted Setup** | Universal        | Per-circuit    | Per-circuit (zkVerify) |
| **Latency**       | Instant          | Instant        | ~minutes               |
| **Noir Support**  | ✅ Full          | ❌ Go DSL      | ✅ Full                |
