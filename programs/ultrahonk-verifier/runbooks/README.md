# solana-noir-verifier Runbooks

[![Surfpool](https://img.shields.io/badge/Operated%20with-Surfpool-gree?labelColor=gray)](https://surfpool.run)

## Available Runbooks

### deployment

Deploy the UltraHonk verifier program to Solana.

## Getting Started

This repository uses [Surfpool](https://surfpool.run) for development and deployment.

### Installation

```console
# macOS (Homebrew)
brew install txtx/taps/surfpool

# Linux (Snap Store)
snap install surfpool
```

### Build the Program

Before deploying, build the Solana program:

```console
cd programs/ultrahonk-verifier
cargo build-sbf
```

This creates `target/deploy/ultrahonk_verifier.so`.

### Start Surfnet with Auto-Deploy

```console
surfpool start --watch
```

This starts a local Solana validator and auto-deploys when `.so` files change.

### Manual Deployment

```console
# Deploy to local Surfnet
surfpool run deployment --env localnet

# Deploy to devnet (requires funded wallet)
surfpool run deployment --env devnet
```

### List Available Runbooks

```console
surfpool ls
```

## Workflow

1. **Develop circuit** in `test-circuits/`
2. **Compile** with `nargo compile`
3. **Generate VK** with `bb write_vk`
4. **Build verifier** with `cargo build-sbf`
5. **Deploy** with `surfpool run deployment`
6. **Verify proofs** using the deployed program
