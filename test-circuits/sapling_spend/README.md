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

### Scalar Representation

Field elements are converted to curve scalars using Noir's built-in `EmbeddedCurveScalar::from_field()`:

```noir
fn field_to_scalar(f: Field) -> EmbeddedCurveScalar {
    EmbeddedCurveScalar::from_field(f)
}
```

This uses Noir's `bn254::decompose` which correctly splits a 254-bit field element into two 128-bit limbs `(lo, hi)` where `scalar = lo + hi * 2^128`. This is the canonical representation expected by `multi_scalar_mul` and `fixed_base_scalar_mul`.

### Diversifier Semantics

The diversifier `d` is treated as a full field element, uniformly random in `[1, p-1]`:

- `g_d = d · G` (fixed-base scalar multiplication)
- `pk_d = ivk · g_d` (diversified transmission key)

**Constraints:**

- `d != 0` is enforced in-circuit (prevents `g_d` being the point at infinity)
- No other constraints on `d`'s bit-width or format

**Note:** This is _not_ Sapling's `hash_to_curve(diversifier)` approach. Addresses are `(d, pk_d)` pairs where `d` is chosen uniformly at random. This is simpler and sufficient for our use case, but not interoperable with Sapling/MASP address formats.

### Value Semantics

The `value` field has a **64-bit range check** enforced in-circuit:

```noir
fn assert_64_bits(v: Field) {
    let bytes: [u8; 32] = v.to_be_bytes();
    for i in 0..24 {
        assert(bytes[i] == 0, "value exceeds 64 bits");
    }
}
```

**Design rationale:** We enforce the range check here rather than deferring to a balance circuit because:

1. It catches invalid values at proof generation time
2. It prevents any ambiguity about value encoding between circuits
3. The cost is minimal (~few hundred gates)

For value balance (Σin - Σout - fees = 0), that invariant is enforced at the transaction level, not in this single-note spend gadget.

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
│   ├── value Note value (64-bit range checked!)
│   ├── rho   Nullifier seed (in commitment!)
│   ├── rcm   Commitment randomness
│   └── d     Diversifier
└── Merkle Path
    ├── siblings[32]     Sibling hashes
    └── path_indices[32] Position bits

COMPUTATION STEPS:
0. Range check: value < 2^64
1. Derive ask, nsk from sk
2. Compute ak = ask·G, nk = nsk·G
3. Compute ivk = Hash(ak, nk)
4. Derive g_d, pk_d from diversifier
5. Compute cm = Hash(g_d, pk_d, value, rho, rcm)
6. Verify Merkle membership → anchor
7. Compute nullifier = Hash(nk, rho)
8. Compute rk = ak + ar·G

PUBLIC OUTPUTS:
├── nullifier  Double-spend tag
├── anchor     Merkle root
├── rk.x       Auth key x-coordinate
└── rk.y       Auth key y-coordinate
```

### ✅ 64-bit Value Range Check

The circuit enforces that `value` fits in 64 bits:

```noir
fn assert_64_bits(v: Field) {
    let bytes: [u8; 32] = v.to_be_bytes();
    for i in 0..24 {
        assert(bytes[i] == 0, "value exceeds 64 bits");
    }
}
```

**Why this matters:** Without range checks, field arithmetic wraparound could create value from nothing or destroy value unexpectedly.

**Guarantee:** Values must be in range `[0, 2^64 - 1]`. Proof generation fails for values ≥ 2^64.

## Future Enhancements

### Asset Type Support (Optional)

**Current state:** Single-asset (implicit native token).

**For MASP-style multi-asset:**

```noir
// Add to note commitment:
cm = Hash(DOMAIN_NOTE_COMMIT, g_d.x, pk_d.x, asset_type, value, rho, rcm)
```

**Impact analysis:** Adding `asset_type` increases circuit size by only ~0.6% (337 gates), keeping log_n=16. Verification cost identical, proof generation negligibly slower.

### Spend Authorization Signature

**Current state:** Circuit outputs `rk` but doesn't verify any signature.

**Production integration:** The verifying program must:

1. Check a signature over the transaction under `rk`
2. Verify the ZK proof
3. Both must pass for valid spend

This is outside the circuit—handled by the Solana program.

## Test Suite

The circuit includes **10 comprehensive tests**:

| Test                                    | Security Property                          |
| --------------------------------------- | ------------------------------------------ |
| `test_sapling_spend`                    | Basic functionality, nullifier determinism |
| `test_nullifier_binding`                | rho correctly bound via note commitment    |
| `test_realistic_merkle_tree`            | Proper Merkle tree construction            |
| `test_different_sk_different_nullifier` | Only owner can create valid nullifiers     |
| `test_tampered_merkle_sibling`          | Merkle path integrity                      |
| `test_path_index_sensitivity`           | Position affects anchor                    |
| `test_rk_randomization`                 | Unlinkability via different ar             |
| `test_zero_value_note`                  | Edge case: zero value                      |
| `test_max_valid_value`                  | Edge case: max 64-bit value                |
| `test_determinism`                      | Same inputs → same outputs                 |

All tests pass and the circuit has been verified end-to-end on Solana (surfpool).

## Verification Cost (Solana)

| Phase                | Compute Units | Transactions |
| -------------------- | ------------- | ------------ |
| Challenge Generation | ~319,000      | 1            |
| Sumcheck (16 rounds) | ~4,736,000    | 4            |
| MSM Computation      | ~2,705,000    | 4            |
| Pairing Check        | ~55,000       | 1            |
| **Total**            | **~7.8M CUs** | **10 TXs**   |

Circuit complexity: `log_n = 16` (~55k gates)

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

## Ledger Integration

### Public Input Wiring

The circuit outputs four public values in this exact order:

```
(nullifier, anchor, rk_x, rk_y)
```

The on-chain verifier program **MUST**:

1. **Verify the ZK proof** with these as public inputs
2. **Check `anchor`** equals a valid commitment tree root (or follows your anchor policy)
3. **Check `nullifier`** is not in the nullifier set, then insert it
4. **Verify a signature** on the transaction data under `rk = (rk_x, rk_y)`

If you later add more public outputs (e.g., asset ID, value commitments), maintain backwards compatibility or version your circuit.

### Multi-Spend / Multi-Output Transactions

For transactions with multiple spends and/or outputs, you must decide on an **anchor policy**:

| Policy                            | Description                                     | Tradeoffs                                         |
| --------------------------------- | ----------------------------------------------- | ------------------------------------------------- |
| **Single anchor** (Sapling-style) | All spends in a transaction use the same anchor | Simpler; tx validity depends on one tree state    |
| **Multiple anchors** (MASP-style) | Each spend can use a different anchor           | More flexible; requires careful anchor validation |

**Current recommendation:** Use **single anchor** policy for simplicity:

```
For all spends in a transaction:
  - anchor[i] == anchor[0]  // All must match
```

The ledger should:

- Accept the transaction's anchor as the claimed tree root
- Verify it matches a recent/valid commitment tree root
- Ensure the anchor hasn't been pruned or is within an allowed window

### Value Balance Invariant

This circuit does **not** enforce value balance. At the transaction level, your validity predicate must ensure:

```
Σ(spend values) - Σ(output values) - fees = 0
```

For multi-asset support, this becomes per-asset-type.

### Nullifier Set Management

The nullifier set is append-only:

- Before accepting a spend, check `nullifier ∉ nullifier_set`
- After accepting, insert `nullifier` into `nullifier_set`
- Never remove nullifiers (they represent spent notes forever)

## References

- [Zcash Sapling Protocol Specification](https://zips.z.cash/protocol/protocol.pdf) — Original Sapling design
- [Namada MASP Documentation](https://namada.net/blog/understanding-the-masp-and-cc-circuits) — Multi-asset extension concepts
- [Penumbra Nullifier Design](https://protocol.penumbra.zone/main/sct/nullifiers.html) — Position-based nullifier alternative

## License

Part of the solana-noir-verifier project.
