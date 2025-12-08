# Local Alternatives to zkVerify

If you need proof compression without depending on zkVerify's network, here are your options.

## Why Local?

| Concern          | zkVerify                  | Local Alternative |
| ---------------- | ------------------------- | ----------------- |
| **Latency**      | Minutes (batching)        | Seconds           |
| **Privacy**      | Proof visible to zkVerify | Fully private     |
| **Availability** | Depends on service        | Self-hosted       |
| **Cost**         | $tVFY tokens              | Compute only      |
| **Complexity**   | Simple API                | More setup        |

---

## Option 1: Direct Groth16 with gnark (Recommended)

**Skip the compression step entirely.** Write your circuit in gnark's Go DSL and get Groth16 directly.

See: `../groth16-alternative/`

```
Circuit (Go) → gnark Groth16 → Solana (81K CU)
```

### Pros

- ✅ No external dependencies
- ✅ Full control over trusted setup
- ✅ Same end result (256 byte proof, 81K CU)

### Cons

- ❌ Must write circuits in Go, not Noir
- ❌ Different gadget ecosystem

### When to Use

- New projects
- Simple circuits
- Maximum control needed

---

## Option 2: gnark Recursive Proofs (Advanced)

Wrap your UltraHonk verifier in a Groth16 circuit.

### Concept

```go
// The "outer" Groth16 circuit that verifies the "inner" UltraHonk proof
type UltraHonkWrapperCircuit struct {
    // Inner proof components
    Proof        []frontend.Variable `gnark:",private"`
    VK           []frontend.Variable `gnark:",public"`
    PublicInputs []frontend.Variable `gnark:",public"`

    // Verification result (must be 1)
    Valid        frontend.Variable   `gnark:",public"`
}

func (c *UltraHonkWrapperCircuit) Define(api frontend.API) error {
    // Implement UltraHonk verification as gnark constraints
    // This is complex: ~100K+ constraints for the verifier itself

    // 1. Hash transcript elements
    // 2. Generate challenges
    // 3. Verify sumcheck rounds
    // 4. Verify shplemini opening
    // 5. Pairing check

    result := verifyUltraHonk(api, c.Proof, c.VK, c.PublicInputs)
    api.AssertIsEqual(result, 1)
    return nil
}
```

### Implementation Complexity

| Component        | Constraints (est.) | Difficulty    |
| ---------------- | ------------------ | ------------- |
| Keccak256        | ~100K per hash     | High          |
| BN254 pairing    | ~500K              | Very High     |
| Sumcheck         | ~10K               | Medium        |
| Field operations | ~1K                | Low           |
| **Total**        | **~1M+**           | **Very High** |

### Pros

- ✅ Fully local
- ✅ Use Noir for inner circuit
- ✅ Same output: Groth16 proof

### Cons

- ❌ Massive implementation effort
- ❌ 1M+ constraints = minutes to prove the wrapper
- ❌ Keccak inside circuit is expensive

### When to Use

- You have months to implement
- Need air-gapped proof generation
- Building a competitor to zkVerify

---

## Option 3: SP1/Risc0 zkVM (Practical)

Use a zkVM to prove execution of an UltraHonk verifier written in Rust.

### SP1 Approach

```rust
// sp1-program/src/main.rs
#![no_main]
sp1_zkvm::entrypoint!(main);

fn main() {
    // Read inputs
    let proof: Vec<u8> = sp1_zkvm::io::read_vec();
    let vk: Vec<u8> = sp1_zkvm::io::read_vec();
    let public_inputs: Vec<u8> = sp1_zkvm::io::read_vec();

    // Verify UltraHonk proof (your existing Rust verifier!)
    let result = ultrahonk_verifier::verify(&proof, &vk, &public_inputs);

    // Commit result
    sp1_zkvm::io::commit(&result);
}
```

Then generate a Groth16 proof of the SP1 execution:

```bash
# Generate SP1 proof of verification
sp1 prove --program ultrahonk-verifier --input proof.bin

# Wrap in Groth16 for Solana
sp1 wrap --groth16 --output wrapped_proof.bin
```

### SP1 Groth16 Wrapping

SP1 provides a `Groth16Bn254Prover` that wraps SP1 proofs in Groth16:

```rust
use sp1_sdk::{ProverClient, SP1Stdin};

let client = ProverClient::new();
let (pk, vk) = client.setup(ELF);

let mut stdin = SP1Stdin::new();
stdin.write(&proof_bytes);
stdin.write(&vk_bytes);

// Generate wrapped Groth16 proof
let proof = client.prove(&pk, stdin)
    .groth16()  // Wrap in Groth16!
    .run()
    .unwrap();
```

### Pros

- ✅ Reuse your existing Rust UltraHonk verifier
- ✅ SP1 handles the recursion complexity
- ✅ Groth16 output compatible with Solana

### Cons

- ❌ SP1 proving is slow (~minutes)
- ❌ New dependency (SP1 toolchain)
- ❌ SP1 provers are compute-intensive

### When to Use

- Already have Rust verifier code
- Don't want to re-implement in gnark
- Can tolerate SP1 proving time

---

## Option 4: Groth16 for Simple Circuits, UltraHonk for Complex

**Hybrid approach**: Use different proof systems based on circuit complexity.

```
Simple circuits (< 100K constraints) → gnark Groth16 → Solana
Complex circuits (> 100K constraints) → UltraHonk → zkVerify → Solana
```

### Decision Tree

```
Is your circuit < 100K constraints?
├── YES → Use gnark directly (experiments/groth16-alternative/)
│         - Write in Go, not Noir
│         - 256 byte proof, 81K CU
│
└── NO → Options:
    ├── Can wait minutes for aggregation? → zkVerify
    ├── Need privacy? → SP1 wrapping (local)
    └── Have dev time? → gnark recursive (custom)
```

---

## Comparison Summary

| Approach            | Setup       | Proving Time | Proof Size | Solana CU | Complexity |
| ------------------- | ----------- | ------------ | ---------- | --------- | ---------- |
| **Direct Groth16**  | Per-circuit | Seconds      | 256 bytes  | 81K       | Low        |
| **zkVerify**        | None        | Minutes      | 256 bytes  | 81K       | Low        |
| **gnark Recursive** | Per-wrapper | Minutes      | 256 bytes  | 81K       | Very High  |
| **SP1 Wrapping**    | One-time    | Minutes      | ~300 bytes | ~100K     | Medium     |

---

## Recommendation

1. **Start with direct gnark** (`../groth16-alternative/`) for simple circuits
2. **Use zkVerify** when you need full Noir support and can tolerate latency
3. **Consider SP1** if you need local + Noir compatibility in the future

The "holy grail" would be SP1 + your existing UltraHonk verifier + Groth16 wrapping. This gives you:

- Full Noir support
- Local proving
- Small Groth16 output
- Solana compatibility

But it requires SP1 toolchain setup and integration work.

---

## Future: Noir Native Recursion?

Aztec is working on native recursion in Noir. When available:

```noir
// Future Noir (hypothetical)
use std::recursion;

fn main(inner_proof: Proof, inner_vk: VerifyingKey) {
    // Verify another Noir proof inside this one
    recursion::verify(inner_proof, inner_vk);

    // Additional constraints...
}
```

This would let you wrap UltraHonk in UltraHonk, then potentially export to Groth16.

Watch: https://github.com/noir-lang/noir/issues?q=recursion
