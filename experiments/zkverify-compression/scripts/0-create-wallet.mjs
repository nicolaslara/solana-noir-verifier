#!/usr/bin/env node
/**
 * Generate a new Polkadot wallet for zkVerify
 * 
 * This creates a seed phrase and address that you can use with zkVerify.
 * Fund the address with testnet $tVFY from the faucet.
 */

import { Keyring } from '@polkadot/keyring';
import { mnemonicGenerate, cryptoWaitReady } from '@polkadot/util-crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
    console.log("=== Generate Polkadot Wallet for zkVerify ===");
    console.log("");

    // Wait for crypto to be ready
    await cryptoWaitReady();

    // Generate a new mnemonic (seed phrase)
    const mnemonic = mnemonicGenerate(12);
    
    // Create keyring and add account from mnemonic
    const keyring = new Keyring({ type: 'sr25519' });
    const pair = keyring.addFromMnemonic(mnemonic);

    console.log("✅ New wallet generated!");
    console.log("");
    console.log("=== IMPORTANT: Save this information! ===");
    console.log("");
    console.log("Seed Phrase (12 words):");
    console.log(`  ${mnemonic}`);
    console.log("");
    console.log("Address (for faucet):");
    console.log(`  ${pair.address}`);
    console.log("");

    // Save to .env file
    const envPath = path.join(__dirname, '.env');
    const envContent = `# Generated wallet for zkVerify
SEED_PHRASE="${mnemonic}"

# Wallet address (use this for faucet): ${pair.address}
SOLANA_RPC="http://localhost:8899"
`;

    fs.writeFileSync(envPath, envContent);
    console.log(`✅ Saved to ${envPath}`);
    console.log("");

    console.log("=== Next Steps ===");
    console.log("");
    console.log("1. Get testnet tokens from zkVerify faucet:");
    console.log("   https://docs.zkverify.io/overview/getting-started/get_testnet_tokens");
    console.log("");
    console.log(`2. Paste this address in the faucet: ${pair.address}`);
    console.log("");
    console.log("3. Wait for tokens to arrive, then run:");
    console.log("   node 3-submit-zkverify.mjs");
    console.log("");
}

main().catch(console.error);

