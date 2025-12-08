# Manual Testing Guide: Noir → zkVerify → Solana

This guide walks through the complete end-to-end pipeline for compressing UltraHonk proofs via zkVerify and verifying them on Solana.

## Prerequisites

### 1. Install Noir Toolchain

```bash
# Install noirup
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
source ~/.bashrc  # or restart terminal

# Install latest Noir
noirup

# Verify
nargo --version
```

### 2. Install Barretenberg (bb)

```bash
# Install bbup
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install | bash
source ~/.bashrc

# Install version compatible with zkVerify (0.84.x)
bbup -v 0.84.0

# Verify
bb --version
```

### 3. zkVerify Account Setup

1. Go to [zkVerify Volta Testnet](https://docs.zkverify.io)
2. Create a wallet and save your seed phrase
3. Get testnet $tVFY tokens from the faucet
4. (Optional) Get a Relayer API key if using REST API

### 4. Install Node.js Dependencies

```bash
cd experiments/zkverify-compression/scripts
npm install
```

### 5. Configure Environment

```bash
# Copy example config
cp env-example.txt .env

# Edit with your credentials
nano .env
```

---

## Step 1: Generate UltraHonk Proof

### 1.1 View the Circuit

The sample circuit proves knowledge of `x` such that `x * x == y`:

```nr
// circuits/hello_world/src/main.nr
fn main(x: Field, y: pub Field) {
    assert(x * x == y);
}
```

Witness values (in `Prover.toml`):

- `x = 3` (private)
- `y = 9` (public)

### 1.2 Generate Proof

```bash
chmod +x scripts/*.sh
./scripts/1-generate-proof.sh
```

Expected output:

```
=== Step 1: Generate UltraHonk Proof ===

Checking tools...
  nargo: nargo version = 1.0.0-beta.3
  bb: bb version = 0.84.0

Compiling Noir circuit...
  ✓ Circuit compiled

Generating witness...
  ✓ Witness generated

Generating UltraHonk proof...
  ✓ Proof generated

Generating verification key...
  ✓ VK generated

=== Output Files ===
-rw-r--r--  output/ultrahonk_proof.bin    ~5KB
-rw-r--r--  output/ultrahonk_vk.bin       ~2KB
```

---

## Step 2: Convert to zkVerify Format

```bash
./scripts/2-convert-hex.sh
```

Expected output:

```
=== Step 2: Convert to zkVerify Hex Format ===

✅ proof -> output/zkv_proof.hex
✅ vk -> output/zkv_vk.hex
✅ pubs -> output/zkv_pubs.hex
```

### Output Files

| File            | Description                      |
| --------------- | -------------------------------- |
| `zkv_proof.hex` | Proof as JSON: `{"ZK": "0x..."}` |
| `zkv_vk.hex`    | VK as hex string: `"0x..."`      |
| `zkv_pubs.hex`  | Public inputs: `["0x..."]`       |

---

## Step 3: Submit to zkVerify

You have two options:

### Option A: zkVerifyJS SDK (Recommended)

```bash
node scripts/3-submit-zkverify.mjs
```

This will:

1. Connect to zkVerify Volta testnet
2. Submit your UltraHonk proof for verification
3. Wait for the aggregation receipt
4. Save the Groth16 receipt to `output/groth16_receipt.json`

### Option B: Relayer REST API

```bash
node scripts/3-submit-relayer.mjs
```

This uses the REST API instead of the SDK.

### Expected Output

```
=== Step 3: Submit to zkVerify ===

Reading proof artifacts...
  ✓ Proof loaded
  ✓ VK loaded
  ✓ Public inputs loaded

Connecting to zkVerify Volta...
  ✓ Connected

Submitting UltraHonk proof...
  Library: Ultrahonk
  Curve: BN254
  Domain: 0

  ✓ Proof submitted!

Waiting for verification...
  Block hash: 0x...
  Proof type: ultrahonk
  Statement: {...}

✅ Attestation saved to output/attestation.json

Waiting for aggregation receipt...
🎉 Aggregation Receipt Received!
✅ Groth16 receipt saved to output/groth16_receipt.json
```

### What Happens During Aggregation

1. **Verification**: zkVerify verifies your UltraHonk proof
2. **Batching**: Multiple proofs are collected over a time window
3. **Aggregation**: A single Groth16 proof is generated attesting to all proofs
4. **Receipt**: You receive a Merkle proof showing your proof was included

---

## Step 4: Verify on Solana

### 4.1 Deploy Groth16 Verifier (if not done)

First, deploy our Groth16 verifier from the previous experiment:

```bash
cd ../groth16-alternative/solana-verifier
cargo build-sbf

# Start Surfpool
surfpool

# In another terminal, deploy
solana program deploy target/deploy/groth16_verifier.so
```

Note the program ID and update `.env`:

```
VERIFIER_PROGRAM_ID="your-program-id"
```

### 4.2 Verify the Groth16 Receipt

```bash
cd ../zkverify-compression/scripts
node 4-verify-solana.mjs
```

Expected output:

```
=== Step 4: Verify Groth16 on Solana ===

Reading Groth16 receipt...
  ✓ Receipt loaded

Connecting to Solana at http://localhost:8899...
  ✓ Connected (2.0.0)

Building verification instruction...
  Instruction data: 288 bytes

Sending verification transaction...

🎉 Verification successful!
  Signature: 5Kj...
  Time: 312ms
  Compute Units: 81,147

✅ End-to-end pipeline complete!
   Noir → UltraHonk → zkVerify → Groth16 → Solana ✓
```

---

## Complete Pipeline Summary

```
┌────────────────────────────────────────────────────────────────┐
│ 1. GENERATE PROOF (Local)                                      │
│    nargo compile → nargo execute → bb prove                    │
│    Output: ultrahonk_proof.bin (~5 KB)                         │
├────────────────────────────────────────────────────────────────┤
│ 2. CONVERT FORMAT (Local)                                      │
│    Binary → Hex JSON for zkVerify                              │
│    Output: zkv_proof.hex, zkv_vk.hex, zkv_pubs.hex            │
├────────────────────────────────────────────────────────────────┤
│ 3. SUBMIT TO ZKVERIFY (Network)                                │
│    UltraHonk proof → zkVerify verification → Aggregation       │
│    Output: groth16_receipt.json (256 bytes proof)              │
│    Latency: ~1-5 minutes                                       │
├────────────────────────────────────────────────────────────────┤
│ 4. VERIFY ON SOLANA (On-chain)                                 │
│    Groth16 proof → alt_bn128 pairing check                     │
│    Cost: ~81K CU (~0.00008 SOL)                                │
└────────────────────────────────────────────────────────────────┘
```

---

## Troubleshooting

### "bb: command not found"

```bash
source ~/.bashrc
# or
export PATH="$HOME/.bb:$PATH"
```

### "nargo: command not found"

```bash
source ~/.bashrc
# or
export PATH="$HOME/.nargo/bin:$PATH"
```

### "zkverifyjs module not found"

```bash
cd scripts
npm install
```

### "SEED_PHRASE not found"

Create `scripts/.env`:

```bash
cp env-example.txt .env
nano .env
```

### "Insufficient balance" on zkVerify

Get testnet $tVFY tokens from the faucet:
https://docs.zkverify.io/overview/getting-started

### "Verification failed" on Solana

1. Ensure the Groth16 verifier is deployed
2. Check the program ID matches in `.env`
3. Verify Surfpool is running

### Aggregation timeout

zkVerify batches proofs for aggregation. If you're the only one submitting:

- Wait longer (up to 10 minutes)
- Or use a domain with faster aggregation settings

---

## Customizing the Circuit

To use your own Noir circuit:

1. Create a new circuit:

   ```bash
   cd circuits
   nargo new my_circuit
   cd my_circuit
   ```

2. Edit `src/main.nr` with your logic

3. Create `Prover.toml` with witness values

4. Update `1-generate-proof.sh` to use your circuit name

5. Run the pipeline as before

---

## Cost Analysis

| Step                | Cost       | Notes             |
| ------------------- | ---------- | ----------------- |
| Proof generation    | Free       | Local computation |
| zkVerify submission | ~$0.01     | $tVFY tokens      |
| Solana verification | ~$0.00008  | 81K CU            |
| **Total**           | **~$0.01** | Per proof         |

Compare to:

- Direct UltraHonk on Solana: Would need complex verifier, ~200-400K CU
- Direct Groth16 (our gnark experiment): ~81K CU, but requires trusted setup

---

## Next Steps

1. **Production**: Use mainnet zkVerify and Solana mainnet
2. **Custom Circuits**: Replace hello_world with your actual circuit
3. **Automation**: Set up CI/CD for proof generation and submission
4. **Batching**: Submit multiple proofs for better cost efficiency
