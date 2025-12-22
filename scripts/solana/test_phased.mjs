#!/usr/bin/env node
/**
 * End-to-end test for UltraHonk verification using the SDK
 * 
 * This is the single test entrypoint - it dogfoods our own SDK.
 */
import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Import our SDK
import { SolanaNoirVerifier, PROOF_SIZE, VK_SIZE } from '../../sdk/dist/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8899';
const PROGRAM_ID = new PublicKey(process.env.PROGRAM_ID || '7sfMWfVs6P1ACjouyvRwWHjiAj6AsFkYARP2v9RBSSoe');
const CIRCUIT_NAME = process.env.CIRCUIT || 'simple_square';
const DEBUG = process.env.DEBUG === '1';

// Circuit paths
const proofPath = path.join(__dirname, `../../test-circuits/${CIRCUIT_NAME}/target/keccak/proof`);
const piPath = path.join(__dirname, `../../test-circuits/${CIRCUIT_NAME}/target/keccak/public_inputs`);
const vkPath = path.join(__dirname, `../../test-circuits/${CIRCUIT_NAME}/target/keccak/vk`);

async function main() {
    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║         UltraHonk Verification Test (using SDK)              ║');
    console.log('╚══════════════════════════════════════════════════════════════╝\n');
    
    console.log(`Circuit: ${CIRCUIT_NAME}`);
    console.log(`Program: ${PROGRAM_ID.toBase58()}`);
    console.log(`RPC: ${RPC_URL}\n`);
    
    // Load test data
    if (!fs.existsSync(proofPath)) {
        console.error(`❌ Proof not found: ${proofPath}`);
        console.error(`   Run: cd test-circuits/${CIRCUIT_NAME} && ./build.sh`);
        process.exit(1);
    }
    
    const proof = fs.readFileSync(proofPath);
    const publicInputsRaw = fs.readFileSync(piPath);
    const vk = fs.readFileSync(vkPath);
    
    // Convert raw PI bytes to array of 32-byte buffers
    const numPi = publicInputsRaw.length / 32;
    const publicInputs = [];
    for (let i = 0; i < numPi; i++) {
        publicInputs.push(publicInputsRaw.slice(i * 32, (i + 1) * 32));
    }
    
    console.log(`Proof: ${proof.length} bytes (expected: ${PROOF_SIZE})`);
    console.log(`VK: ${vk.length} bytes (expected: ${VK_SIZE})`);
    console.log(`Public inputs: ${numPi} × 32 = ${publicInputsRaw.length} bytes\n`);
    
    // Setup
    const connection = new Connection(RPC_URL, 'confirmed');
    const payer = Keypair.generate();
    
    // Fund payer
    console.log('Funding payer account...');
    const airdropSig = await connection.requestAirdrop(payer.publicKey, 10_000_000_000);
    await connection.confirmTransaction(airdropSig);
    console.log('  ✅ Funded\n');
    
    // Create SDK client
    const verifier = new SolanaNoirVerifier(connection, { programId: PROGRAM_ID });
    
    // =========================================================================
    // STEP 1: Upload VK (one-time per circuit)
    // =========================================================================
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║           CIRCUIT DEPLOYMENT (one-time per circuit)           ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    
    const vkStart = Date.now();
    const vkResult = await verifier.uploadVK(payer, vk);
    const vkTime = Date.now() - vkStart;
    
    console.log(`  VK Account: ${vkResult.vkAccount.toBase58()}`);
    console.log(`  Chunks: ${vkResult.numChunks}`);
    console.log(`  Time: ${(vkTime / 1000).toFixed(2)}s`);
    console.log('  ✅ VK uploaded\n');
    
    // =========================================================================
    // STEP 2: Verify proof
    // =========================================================================
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║              PROOF VERIFICATION (per proof)                   ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    
    const verifyStart = Date.now();
    let lastPhase = '';
    
    const result = await verifier.verify(payer, proof, publicInputs, vkResult.vkAccount, {
        onProgress: (phase, current, total) => {
            if (phase !== lastPhase) {
                if (lastPhase) console.log('  ✅ Done');
                console.log(`  ${phase}...`);
                lastPhase = phase;
            }
        }
    });
    if (lastPhase) console.log('  ✅ Done');
    
    const verifyTime = Date.now() - verifyStart;
    
    console.log(`\n  Verified: ${result.verified ? '✅ YES' : '❌ NO'}`);
    console.log(`  Total CUs: ${result.totalCUs.toLocaleString()}`);
    console.log(`  Transactions: ${result.numTransactions} (${result.numSteps} sequential steps)`);
    console.log(`  Time: ${(verifyTime / 1000).toFixed(2)}s\n`);
    
    if (!result.verified) {
        console.error('❌ Verification failed!');
        process.exit(1);
    }
    
    // =========================================================================
    // STEP 3: Create receipt (for integrators)
    // =========================================================================
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║         RECEIPT CREATION (for integrators)                    ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    
    const [receiptPda] = verifier.deriveReceiptPda(vkResult.vkAccount, publicInputs);
    console.log(`  Receipt PDA: ${receiptPda.toBase58()}`);
    
    await verifier.createReceipt(
        payer,
        result.stateAccount,
        result.proofAccount,
        vkResult.vkAccount,
        publicInputs
    );
    console.log('  ✅ Receipt created\n');
    
    // =========================================================================
    // STEP 4: Validate receipt (simulating integrator lookup)
    // =========================================================================
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║         RECEIPT VALIDATION (integrator check)                 ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    
    const receipt = await verifier.getReceipt(vkResult.vkAccount, publicInputs);
    
    if (receipt) {
        console.log(`  ✅ Receipt found!`);
        console.log(`     Verified at slot: ${receipt.verifiedSlot}`);
        console.log(`     Verified at: ${new Date(Number(receipt.verifiedTimestamp) * 1000).toISOString()}`);
    } else {
        console.log('  ❌ Receipt not found');
        process.exit(1);
    }
    
    // =========================================================================
    // SUMMARY
    // =========================================================================
    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║                         SUMMARY                               ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    
    console.log(`\n  Circuit: ${CIRCUIT_NAME}`);
    console.log(`  VK deployment: ${(vkTime / 1000).toFixed(2)}s (one-time)`);
    console.log(`  Proof verification: ${(verifyTime / 1000).toFixed(2)}s`);
    console.log(`  Total CUs: ${result.totalCUs.toLocaleString()}`);
    console.log(`  Transactions: ${result.numTransactions} (${result.numSteps} sequential steps)`);
    console.log(`\n  VK Account: ${vkResult.vkAccount.toBase58()}`);
    console.log(`  Receipt: ${receiptPda.toBase58()}`);
    
    console.log('\n  🎉 All tests passed!\n');
}

main().catch(err => {
    console.error('\n❌ Test failed:', err.message);
    if (DEBUG) console.error(err.stack);
    process.exit(1);
});
