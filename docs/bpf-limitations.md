# BPF Limitations for UltraHonk Verification

## Current State (December 2024)

### What Works

- ✅ **Off-chain verification**: All 54 unit tests pass
- ✅ **Integration tests**: `solana-program-test` simulator passes
- ✅ **Program deployment**: Deploys successfully to Surfpool/Solana
- ✅ **Proof upload**: Account-based chunked upload works
- ✅ **Stack overflow fixed**: Using `#[inline(never)]` and heap allocation

### What Doesn't Work

- ❌ **On-chain verification**: Exceeds 1.4M compute unit limit

## Compute Unit Analysis

| Metric        | Value              |
| ------------- | ------------------ |
| CUs requested | 1,400,000          |
| CUs consumed  | 1,399,850+         |
| Status        | **Exceeded limit** |

UltraHonk verification needs **more than 1.4M CUs** (the maximum per transaction).

## The Problem

### BPF Stack Limits

Solana's BPF (Berkeley Packet Filter) runtime has strict memory constraints:

| Resource        | Limit           |
| --------------- | --------------- |
| Stack per frame | 4 KB            |
| Total stack     | ~64 KB (varies) |
| Heap            | 32 KB default   |
| Compute Units   | 200,000 default |

### Why UltraHonk Verification Exceeds Limits

UltraHonk verification involves several operations that consume significant stack space:

1. **Large Arrays** (Fixed-size allocations on stack)

   ```rust
   // These blow up the stack:
   let gate_challenges: [Fr; 28] = ...;      // 28 × 32 = 896 bytes
   let sumcheck_challenges: [Fr; 28] = ...;  // 28 × 32 = 896 bytes
   let alphas: [Fr; 25] = ...;               // 25 × 32 = 800 bytes
   let subrelations: [Fr; 26] = ...;         // 26 × 32 = 832 bytes
   let evals: [Fr; 40] = ...;                // 40 × 32 = 1,280 bytes
   ```

2. **Nested Function Calls**

   ```
   verify()
   └─ verify_inner()
      └─ generate_challenges()
         └─ transcript operations (hash buffers)
      └─ perform_sumcheck()
         └─ accumulate_relation_evaluations()
            └─ 8 sub-relation accumulators
      └─ verify_shplemini()
         └─ MSM operations
   ```

3. **Intermediate Computations**
   - Each function call adds a new stack frame
   - Local variables accumulate across nested calls
   - Rust's optimizer may inline functions, combining stack frames

### Comparison: Why Groth16 Works

| Aspect        | Groth16                          | UltraHonk                        |
| ------------- | -------------------------------- | -------------------------------- |
| Proof size    | 192 bytes                        | 16,224 bytes                     |
| Public inputs | Small                            | 16 pairing points + user inputs  |
| Verification  | 1 pairing check                  | Sumcheck + Shplemini + pairing   |
| Stack usage   | ~500 bytes                       | ~10+ KB                          |
| Library       | `groth16-solana` (BPF-optimized) | `plonk-core` (not BPF-optimized) |

The `groth16-solana` library was specifically designed for Solana's constraints. Our `plonk-core` was ported from off-chain code without BPF optimization.

## Error Details

```
Program failed: Access violation in stack frame 3 at address 0x200003828 of size 8
```

This occurs when:

1. A function tries to allocate beyond its 4KB stack frame
2. A write occurs to memory outside the valid stack region
3. Nested calls exceed total stack budget

## Solutions

### 1. Heap Allocation (Recommended)

Move large arrays to heap using `Box`:

```rust
// Before (stack):
let challenges: [Fr; 28] = [SCALAR_ZERO; 28];

// After (heap):
let challenges: Box<[Fr]> = vec![SCALAR_ZERO; 28].into_boxed_slice();
```

### 2. Break Up Stack Frames

Use `#[inline(never)]` to prevent stack frame combination:

```rust
#[inline(never)]
fn compute_sumcheck(...) { ... }

#[inline(never)]
fn compute_shplemini(...) { ... }
```

### 3. Reduce Intermediate Values

Pre-compute values off-chain and pass them in.

### 4. Use Solana's Heap API

```rust
use solana_program::entrypoint::HEAP_START_ADDRESS;
// Manual heap management for large allocations
```

## Integration Test vs Real BPF

Why do integration tests pass but real execution fails?

| Environment           | Stack Behavior                        |
| --------------------- | ------------------------------------- |
| `solana-program-test` | Uses native Rust stack (MB available) |
| Real BPF/SBF          | Strict 4KB per frame limit            |
| Surfpool              | Real BPF constraints                  |

The `solana-program-test` framework runs your program as native code, not actual BPF bytecode, so it doesn't enforce BPF stack limits.

## Next Steps

1. **Profile stack usage** with `cargo build-sbf -- -Z print-type-sizes`
2. **Identify largest allocations** in hot paths
3. **Box the big arrays** in `plonk-core`
4. **Add `#[inline(never)]`** to deep call chains
5. **Re-test on Surfpool**

## References

- [Solana BPF Constraints](https://docs.solana.com/developing/on-chain-programs/limitations)
- [Stack Frame Debugging](https://solana.stackexchange.com/questions/tagged/stack)
- [groth16-solana approach](https://github.com/Lightprotocol/groth16-solana)
