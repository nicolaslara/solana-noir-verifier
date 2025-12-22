# solana-noir-verifier-cpi

Utility crate for Solana programs to check if a Noir proof was verified.

## Installation

```toml
[dependencies]
solana-noir-verifier-cpi = { git = "https://github.com/..." }
```

## Usage

```rust
use solana_noir_verifier_cpi::is_verified;
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

// Your circuit's VK account (deployed once, save this address)
const MY_VK: Pubkey = solana_program::pubkey!("...");
const VERIFIER: Pubkey = solana_program::pubkey!("...");

fn process(accounts: &[AccountInfo], public_inputs: &[u8]) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let receipt = next_account_info(account_iter)?;  // User provides
    
    // Check if proof was verified
    if !is_verified(receipt, &MY_VK, public_inputs, &VERIFIER) {
        return Err(ProgramError::Custom(1)); // NotVerified
    }
    
    // Proof is valid! Continue with business logic...
    Ok(())
}
```

## API

### `is_verified`

```rust
pub fn is_verified(
    receipt: &AccountInfo,    // Receipt account (user provides)
    vk_account: &Pubkey,      // Your circuit's VK account
    public_inputs: &[u8],     // The public inputs that were proven
    verifier_program: &Pubkey // The verifier program ID
) -> bool
```

Returns `true` if the proof was verified. Validates:
1. Receipt is at the correct PDA address (derived from VK + keccak(public_inputs))
2. Receipt is owned by the verifier program
3. Receipt has valid data (≥16 bytes)

### `get_verified_slot` / `get_verified_timestamp`

Read when the proof was verified:

```rust
if is_verified(receipt, &MY_VK, public_inputs, &VERIFIER) {
    let slot = get_verified_slot(receipt);           // Option<u64>
    let timestamp = get_verified_timestamp(receipt); // Option<i64>
}
```

## How It Works

1. User verifies their proof via the verifier program (8 transactions)
2. User calls `CreateReceipt` to create a permanent receipt PDA
3. The receipt PDA is derived from: `seeds = [b"receipt", vk_account, keccak(public_inputs)]`
4. Your program validates the receipt account matches the expected PDA

**Security**: The receipt can only be created by the verifier program after successful verification. The PDA derivation ensures each (VK, public_inputs) pair has a unique receipt address.

## Cost

~100 CUs for `is_verified` (PDA derivation + account checks).

## License

MIT
