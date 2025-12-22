# @solana-noir-verifier/sdk

TypeScript SDK for verifying Noir UltraHonk proofs on Solana.

## Installation

```bash
npm install @solana-noir-verifier/sdk @solana/web3.js
```

## Quick Start

```typescript
import { SolanaNoirVerifier } from '@solana-noir-verifier/sdk';
import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import fs from 'fs';

const connection = new Connection('http://127.0.0.1:8899');
const payer = Keypair.generate(); // Fund this keypair!

const verifier = new SolanaNoirVerifier(connection, {
  programId: new PublicKey('YOUR_DEPLOYED_PROGRAM_ID'),
});

// 1. Upload VK once per circuit
const vk = fs.readFileSync('./target/keccak/vk');
const { vkAccount } = await verifier.uploadVK(payer, vk);
console.log('VK Account:', vkAccount.toBase58());

// 2. Verify a proof
const proof = fs.readFileSync('./target/keccak/proof');
const publicInputs = [Buffer.alloc(32)]; // Your 32-byte public inputs
const result = await verifier.verify(payer, proof, publicInputs, vkAccount);

if (!result.verified) {
  throw new Error('Proof verification failed!');
}

// 3. Create a receipt for integrator lookup
await verifier.createReceipt(
  payer, result.stateAccount, result.proofAccount, vkAccount, publicInputs
);

// 4. Later: Check if proof was verified
const receipt = await verifier.getReceipt(vkAccount, publicInputs);
if (receipt) {
  console.log('Verified at slot:', receipt.verifiedSlot);
}
```

## API

### `SolanaNoirVerifier`

Main client class for proof verification.

#### Constructor

```typescript
new SolanaNoirVerifier(connection: Connection, config: VerifierConfig)
```

- `connection` - Solana connection
- `config.programId` - Deployed verifier program ID
- `config.chunkSize` - Optional chunk size (default: 1020 bytes)
- `config.computeUnitLimit` - Optional CU limit per TX (default: 1,400,000)

#### `uploadVK(payer, vk): Promise<VKUploadResult>`

Upload a verification key. Do this **once per circuit**.

Returns:
- `vkAccount` - The VK account public key (save this!)
- `numChunks` - Number of chunks uploaded (typically 2)

#### `verify(payer, proof, publicInputs, vkAccount, options?): Promise<VerificationResult>`

Verify a proof on-chain.

- `proof` - 16,224 byte proof buffer
- `publicInputs` - Array of 32-byte public input buffers
- `vkAccount` - VK account from `uploadVK()`
- `options.onProgress` - Optional progress callback

Returns:
- `verified` - Whether verification succeeded
- `stateAccount` - State account (needed for `createReceipt`)
- `proofAccount` - Proof account (needed for `createReceipt`)
- `totalCUs` - Total compute units consumed
- `numTransactions` - Number of transactions

#### `createReceipt(payer, stateAccount, proofAccount, vkAccount, publicInputs)`

Create a permanent receipt PDA after successful verification.

The receipt allows integrators to check if a proof was verified without re-running verification.

#### `getReceipt(vkAccount, publicInputs): Promise<Receipt | null>`

Look up a verification receipt.

Returns receipt info if the proof was verified and a receipt was created, otherwise `null`.

#### `deriveReceiptPda(vkAccount, publicInputs): [PublicKey, number]`

Derive the receipt PDA address for a given VK and public inputs.

## Architecture

UltraHonk verification requires ~5-7M compute units, split across 8+ transactions:

| Phase | Description | Approx CUs |
|-------|-------------|------------|
| 1 | Challenge generation | ~270-550K |
| 2 | Sumcheck (2-3 TXs) | ~3-4M |
| 3+4 | MSM + Pairing (4 TXs) | ~2M |

The SDK handles all phases automatically.

## License

MIT
