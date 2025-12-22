# Sample Integrator Program

Example Solana program that requires ZK proof verification before executing business logic.

## Use Cases

- **Private voting**: Verify a vote proof before recording
- **Identity verification**: Verify a credential proof before granting access
- **Private transfers**: Verify a balance proof before executing
- **Game state**: Verify a game move proof before updating state

## How It Works

### Step 1: User verifies their proof (off-chain client)

```typescript
const verifier = new SolanaNoirVerifier(connection, { programId: VERIFIER });
const result = await verifier.verify(payer, proof, publicInputs, vkAccount);

// Create permanent receipt
await verifier.createReceipt(payer, result.stateAccount, result.proofAccount, vkAccount, publicInputs);
```

### Step 2: User calls your program with receipt

```
┌─────────────────────────────────────────────────────────────┐
│  Accounts passed to your program:                           │
│    0. Receipt account (PDA from verifier)                   │
│    1. User (signer)                                         │
│                                                             │
│  Instruction data:                                          │
│    [instruction_code, ...public_inputs]                     │
└─────────────────────────────────────────────────────────────┘
```

### Step 3: Your program validates the receipt

```rust
use solana_noir_verifier_cpi::is_verified;

const MY_VK: Pubkey = pubkey!("...");      // Your circuit's VK
const VERIFIER: Pubkey = pubkey!("...");   // Verifier program

fn process(accounts: &[AccountInfo], public_inputs: &[u8]) -> ProgramResult {
    let receipt = &accounts[0];
    
    if !is_verified(receipt, &MY_VK, public_inputs, &VERIFIER) {
        return Err(ProgramError::Custom(1)); // NotVerified
    }
    
    // Proof is valid! Continue...
    Ok(())
}
```

## Building

```bash
cargo build-sbf
```

## Key Points

1. **Receipt is a PDA**: Derived from `[b"receipt", vk_account, keccak(public_inputs)]`
2. **Receipt is permanent**: Once created, it persists until closed
3. **No CPI needed**: Just validate the receipt account
4. **~100 CUs**: Very cheap to check

## License

MIT
