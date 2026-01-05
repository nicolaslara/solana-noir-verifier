# solana-noir-verifier-sdk

Rust SDK for verifying Noir UltraHonk proofs on Solana.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
solana-noir-verifier-sdk = { path = "../path/to/crates/rust-sdk" }
```

## Usage

```rust
use solana_noir_verifier_sdk::{SolanaNoirVerifier, VerifierConfig, VerifyOptions};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{pubkey::Pubkey, signature::Keypair};
use std::sync::Arc;

// Create client
let client = Arc::new(RpcClient::new("http://localhost:8899"));
let program_id = Pubkey::from_str("7sfMWfVs6P1ACjouyvRwWHjiAj6AsFkYARP2v9RBSSoe")?;
let verifier = SolanaNoirVerifier::new(client, VerifierConfig::new(program_id));

// Upload VK (once per circuit)
let vk_bytes = std::fs::read("./target/keccak/vk")?;
let vk_result = verifier.upload_vk(&payer, &vk_bytes)?;
println!("VK Account: {}", vk_result.vk_account);

// Verify proof
let proof = std::fs::read("./target/keccak/proof")?;
let public_inputs = std::fs::read("./target/keccak/public_inputs")?;

let result = verifier.verify(
    &payer,
    &proof,
    &public_inputs,
    &vk_result.vk_account,
    Some(VerifyOptions::default()),
)?;

println!("Verified: {}", result.verified);
println!("Total CUs: {}", result.total_cus);
println!("Transactions: {}", result.num_transactions);
```

## API

### `SolanaNoirVerifier`

Main client for verifying proofs.

- `upload_vk(payer, vk_bytes)` - Upload a verification key (once per circuit)
- `verify(payer, proof, public_inputs, vk_account, options)` - Verify a proof
- `get_verification_state(state_account)` - Read verification state
- `derive_receipt_pda(vk_account, public_inputs)` - Derive receipt PDA address
- `create_receipt(payer, state, proof, vk, public_inputs)` - Create verification receipt
- `get_receipt(vk_account, public_inputs)` - Check if proof was verified
- `close_accounts(payer, state, proof)` - Close accounts to reclaim rent

### `VerifyOptions`

Options for verification:
- `skip_preflight: bool` - Skip preflight simulation (faster but less safe)
- `auto_close: bool` - Automatically close accounts after verification (default: true)

## Running Tests

```bash
# Start local validator
surfpool  # or: solana-test-validator

# Deploy verifier program (if needed)
cd programs/ultrahonk-verifier && cargo build-sbf
solana program deploy target/deploy/ultrahonk_verifier.so --url http://127.0.0.1:8899

# Run test
PROGRAM_ID=<program_id> cargo run --example test_phased -p solana-noir-verifier-sdk
```

## Environment Variables

- `RPC_URL` - RPC endpoint (default: `http://127.0.0.1:8899`)
- `PROGRAM_ID` - Verifier program ID (default: `7sfMWfVs6P1ACjouyvRwWHjiAj6AsFkYARP2v9RBSSoe`)
- `CIRCUIT` - Test circuit to verify (default: `simple_square`)
- `RUST_LOG` - Log level (e.g., `solana_noir_verifier_sdk=debug`)
