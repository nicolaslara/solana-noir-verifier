# Sapling-Style Spend Circuit

A Noir implementation of a Sapling-style shielded spend circuit, designed to prove knowledge of a valid note spend without revealing sensitive details.

## Overview

This circuit proves that the spender:

1. Knows the spending key that controls a note
2. The note exists in the commitment tree (Merkle membership)
3. Can produce a valid nullifier bound to that specific note
4. Controls the randomized authorization key for spend signatures

**Public Outputs:**

- `nullifier` — Double-spend prevention tag (deterministic per note)
- `anchor` — Merkle root of the commitment tree at spend time
- `rk.x`, `rk.y` — Randomized authorization key for signature verification

## Security Properties

### ✅ Nullifier Binding (Critical)

The nullifier seed `rho` is included in both the note commitment AND the nullifier derivation:

```
cm = Hash(DOMAIN_NOTE_COMMIT, g_d.x, pk_d.x, value, rho, rcm)
nf = Hash(DOMAIN_NULLIFIER, nk.x, nk.y, rho)
```

**Why this matters:** Without binding `rho` to `cm`, an attacker could:

- Spend the same note multiple times with different `rho` values
- Each spend would produce a different nullifier, bypassing double-spend detection

**Guarantee:** Same note → same `rho` (from `cm`) → same `nf`. Double-spending is prevented.

### ✅ Unified Key Derivation

Both the authorization key (`ak`) and nullifier key (`nk`) derive from the same master spending key:

```
ask = Hash(DOMAIN_ASK, sk)   // Authorization spending key
nsk = Hash(DOMAIN_NSK, sk)   // Nullifier spending key
ak  = ask · G
nk  = nsk · G
```

**Why this matters:** If `ak` and `nk` came from different keys:

- An attacker could create nullifiers using victim's `nsk`
- But sign spends with their own `ak`
- Breaking the "same entity controls both" invariant

**Guarantee:** Whoever can create valid nullifiers also controls spend authorization.

### ✅ Proper Randomized Authorization Key

The output `rk` follows proper Sapling derivation:

```
rk = ak + ar · G
```

Where `ar` is a per-spend randomizer.

**Why this matters:**

- `rk` is used for spend authorization signatures outside the circuit
- Ties the signature to the same spending key that controls the nullifier
- Randomization (`ar`) provides unlinkability between spends

## Design Choices

### Sapling-Style vs Position-Based Nullifiers

We use **Sapling-style nullifiers**: `nf = Hash(nk, rho)` where `rho` is baked into the note commitment.

**Alternative (Penumbra-style):** Some systems derive nullifiers from `(cm, position)` to handle duplicate commitments differently.

**Our choice:** Sapling-style is simpler and sufficient. If the same commitment appears twice in the tree (unusual), it behaves as a single spendable coin—same nullifier for both positions.

### Hash Function: Pedersen

We use Noir's built-in `pedersen_hash` for all commitments and derivations.

**Rationale:**

- Native to Noir, well-optimized
- Provides binding and hiding properties needed for commitments
- Domain separation via prefix tags prevents cross-context collisions

### Curve: Grumpkin (Noir's Embedded Curve)

Scalar multiplications use Noir's `embedded_curve_ops` (Grumpkin curve).

**Rationale:**

- Native to Noir's constraint system
- Efficient for in-circuit operations
- Not compatible with external Baby JubJub implementations (intentional—we don't need interop)

### Merkle Tree: 32 Levels

The commitment tree has 2³² leaf capacity.

**Rationale:**

- Matches Zcash Sapling's tree depth
- Supports ~4 billion notes
- Realistic for production deployment

## Circuit Structure

```
PRIVATE INPUTS:
├── Spending Key
│   ├── sk    Master spending key
│   └── ar    Per-spend randomizer
├── Note Data
│   ├── value Note value
│   ├── rho   Nullifier seed (in commitment!)
│   ├── rcm   Commitment randomness
│   └── d     Diversifier
└── Merkle Path
    ├── siblings[32]     Sibling hashes
    └── path_indices[32] Position bits

PUBLIC OUTPUTS:
├── nullifier  Double-spend tag
├── anchor     Merkle root
├── rk.x       Auth key x-coordinate
└── rk.y       Auth key y-coordinate
```

## What's Missing for Production

### 1. Value Range Checks (High Priority)

**Current state:** `value` is an unconstrained field element.

**Risk:** Without range checks, arithmetic wraparound could create value from nothing or destroy value unexpectedly.

**Fix needed:**

```noir
// Constrain value to 64 bits
assert(value < 2.pow(64), "value must be < 2^64");
// Or use bit decomposition for tighter constraint
```

### 2. Asset Type Support (For Multi-Asset)

**Current state:** Single-asset (implicit native token).

**For MASP-style multi-asset:**

```noir
// Add to note commitment:
cm = Hash(DOMAIN_NOTE_COMMIT, g_d.x, pk_d.x, asset_type, value, rho, rcm)
```

Plus value balance checks across all spends/outputs per asset type.

### 3. Stronger Domain Separation Tags

**Current state:** Small integers (1-6).

**Improvement:** Use larger, more unique constants:

```noir
// Instead of:
global DOMAIN_ASK: Field = 1;

// Consider:
global DOMAIN_ASK: Field = 0x5361706c696e675f41534b; // "Sapling_ASK" as hex
```

This prevents accidental collision with other protocols using similar patterns.

### 4. Comprehensive Test Vectors

**Current tests verify:**

- Non-zero outputs
- Nullifier determinism (same inputs → same nf)
- Merkle path correctness

**Should add:**

- Different `sk` with same note → different `nf`
- Tampered Merkle sibling → anchor mismatch
- Edge cases (zero value, max value, etc.)
- Known-answer tests against reference implementation

### 5. Spend Authorization Signature Verification

**Current state:** Circuit outputs `rk` but doesn't verify any signature.

**Production integration:** The verifying program must:

1. Check a signature over the transaction under `rk`
2. Verify the ZK proof
3. Both must pass for valid spend

This is outside the circuit—handled by the Solana program.

## Verification Cost (Solana)

| Phase                | Compute Units | Transactions |
| -------------------- | ------------- | ------------ |
| Challenge Generation | ~318,000      | 1            |
| Sumcheck (16 rounds) | ~4,735,000    | 4            |
| MSM Computation      | ~2,703,000    | 4            |
| Pairing Check        | ~55,000       | 1            |
| **Total**            | **~7.8M CUs** | **10 TXs**   |

Circuit complexity: `log_n = 16` (~65k constraints)

## Usage

### Compile

```bash
cd test-circuits/sapling_spend
nargo compile
```

### Test

```bash
nargo test
```

### Generate Proof

```bash
nargo execute
bb prove -b ./target/sapling_spend.json -w ./target/sapling_spend.gz \
    --oracle_hash keccak --zk -o ./target/keccak
```

### Verify Locally

```bash
bb verify -p ./target/keccak/proof -k ./target/keccak/vk \
    -i ./target/keccak/public_inputs --oracle_hash keccak --zk
```

### Verify on Solana (surfpool)

```bash
# Build program with this circuit's VK
cd programs/ultrahonk-verifier
CIRCUIT=sapling_spend cargo build-sbf

# Deploy
solana program deploy target/deploy/ultrahonk_verifier.so \
    --url http://127.0.0.1:8899 --use-rpc

# Run phased verification
cd scripts/solana
CIRCUIT=sapling_spend node test_phased.mjs
```

## References

- [Zcash Sapling Protocol Specification](https://zips.z.cash/protocol/protocol.pdf) — Original Sapling design
- [Namada MASP Documentation](https://namada.net/blog/understanding-the-masp-and-cc-circuits) — Multi-asset extension concepts
- [Penumbra Nullifier Design](https://protocol.penumbra.zone/main/sct/nullifiers.html) — Position-based nullifier alternative

## License

Part of the solana-noir-verifier project.
