# solana-noir-verifier-sdk

Rust SDK and CLI for verifying Noir UltraHonk proofs on Solana.

## Prerequisites

### 1. Install Noir Toolchain

```bash
# Install noirup
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash

# Install Noir (pinned version for compatibility)
noirup -v 1.0.0-beta.8

# Verify installation
nargo --version  # Should show 1.0.0-beta.8
```

### 2. Install Barretenberg CLI

```bash
# Install bbup
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash

# Install bb (auto-detects compatible version from nargo)
bbup

# Verify installation
bb --version  # Should show v0.87.x
```

### 3. Set Up Solana Keypair

```bash
# Install Solana CLI (if not already installed)
sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"

# Generate a new keypair (or use existing)
solana-keygen new -o ~/.config/solana/id.json

# Fund your wallet (for devnet)
solana airdrop 5 --url devnet
```

### 4. Generate Proof and VK from Noir Circuit

```bash
cd your-noir-project/

# Compile the circuit
nargo compile

# Execute to generate witness
nargo execute

# Generate proof (MUST use keccak + zk for Solana)
bb prove \
  -b ./target/<circuit>.json \
  -w ./target/<circuit>.gz \
  --oracle_hash keccak --zk \
  -o ./target/keccak

# Generate verification key
bb write_vk \
  -b ./target/<circuit>.json \
  --oracle_hash keccak \
  -o ./target/keccak

# You now have:
# - ./target/keccak/proof        (16,224 bytes)
# - ./target/keccak/vk           (1,760 bytes)  
# - ./target/keccak/public_inputs
```

> **Important:** Always use `--oracle_hash keccak --zk` flags. The verifier only supports Keccak transcripts and ZK mode proofs.

## Installation

### As a Library

Add to your `Cargo.toml`:

```toml
[dependencies]
solana-noir-verifier-sdk = { path = "../path/to/crates/rust-sdk" }
```

### As a CLI

```bash
# Install from source
cargo install --path crates/rust-sdk --features cli

# Or build locally
cargo build -p solana-noir-verifier-sdk --features cli --release
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

## CLI Usage

The `noir-solana` CLI provides commands for deploying, uploading VKs, and verifying proofs.

### Commands

```bash
# Deploy verifier program
noir-solana deploy --keypair ~/.config/solana/id.json --network devnet

# Upload VK (once per circuit)
noir-solana upload-vk --vk ./target/keccak/vk \
  --program-id <program_id> --network devnet

# Verify a proof
noir-solana verify \
  --proof ./target/keccak/proof \
  --public-inputs ./target/keccak/public_inputs \
  --vk-account <vk_account_pubkey> \
  --program-id <program_id>

# Check verification status
noir-solana status --state-account <state_pubkey> \
  --program-id <program_id>

# Create verification receipt
noir-solana receipt create \
  --state-account <state_pubkey> \
  --proof-account <proof_pubkey> \
  --vk-account <vk_pubkey> \
  --public-inputs ./target/keccak/public_inputs \
  --program-id <program_id>

# Check receipt
noir-solana receipt check \
  --vk-account <vk_pubkey> \
  --public-inputs ./target/keccak/public_inputs \
  --program-id <program_id>

# Close accounts and reclaim rent
noir-solana close \
  --state-account <state_pubkey> \
  --proof-account <proof_pubkey> \
  --program-id <program_id>
```

**Tip:** Set environment variables to avoid repeating options:
```bash
export KEYPAIR_PATH=~/.config/solana/id.json
export VERIFIER_PROGRAM_ID=<program_id>
export SOLANA_RPC_URL=https://api.devnet.solana.com

# Now commands are simpler:
noir-solana deploy
noir-solana upload-vk --vk ./target/keccak/vk
noir-solana verify --proof ./proof --public-inputs ./pi --vk-account <vk>
```

### Configuration

Create `~/.config/noir-solana/config.toml`:

```toml
[default]
network = "devnet"
keypair = "~/.config/solana/id.json"

[networks.devnet]
rpc_url = "https://api.devnet.solana.com"
program_id = "7sfMWfVs6P1ACjouyvRwWHjiAj6AsFkYARP2v9RBSSoe"

[networks.localnet]
rpc_url = "http://127.0.0.1:8899"
# program_id = <set after deploy>
```

### Options

- `-n, --network <NETWORK>` - Network (mainnet, devnet, localnet, or URL)
- `-k, --keypair <KEYPAIR>` - Path to keypair file
- `-p, --program-id <PROGRAM_ID>` - Verifier program ID
- `--output <OUTPUT>` - Output format (human, json)
- `-q, --quiet` - Quiet mode

## Quick Start Example

Complete workflow from Noir circuit to verified proof on Solana:

```bash
# 1. Create a simple Noir circuit
mkdir my-circuit && cd my-circuit
nargo new simple_check
cd simple_check

# Edit src/main.nr:
# fn main(x: pub Field, y: Field) {
#     assert(x * x == y);
# }

# Edit Prover.toml:
# x = "3"
# y = "9"

# 2. Generate proof
nargo compile && nargo execute
bb prove -b ./target/simple_check.json -w ./target/simple_check.gz \
  --oracle_hash keccak --zk -o ./target/keccak
bb write_vk -b ./target/simple_check.json \
  --oracle_hash keccak -o ./target/keccak

# 3. Start local Solana validator
surfpool  # or: solana-test-validator

# 4. Deploy verifier and verify proof
noir-solana deploy --network localnet
# Note the program ID

noir-solana upload-vk --vk ./target/keccak/vk \
  --program-id <program_id> --network localnet
# Note the VK account

noir-solana verify \
  --proof ./target/keccak/proof \
  --public-inputs ./target/keccak/public_inputs \
  --vk-account <vk_account> \
  --program-id <program_id> --network localnet
# ✓ Proof verified successfully!
```

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

- `SOLANA_RPC_URL` - RPC endpoint (default: `http://127.0.0.1:8899`)
- `VERIFIER_PROGRAM_ID` - Verifier program ID
- `KEYPAIR_PATH` - Path to keypair file
- `RUST_LOG` - Log level (e.g., `solana_noir_verifier_sdk=debug`)
