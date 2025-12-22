#!/usr/bin/env node
/**
 * End-to-end test for UltraHonk verification using the SDK
 * 
 * This is the single test entrypoint - it dogfoods our own SDK.
 * 
 * Usage:
 *   node test_phased.mjs                    # Test single circuit (default: simple_square)
 *   CIRCUIT=merkle_membership node test_phased.mjs  # Test specific circuit
 *   BENCHMARK=1 node test_phased.mjs        # Benchmark all circuits
 *   VERBOSE=1 node test_phased.mjs          # Show CU breakdown
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
const BENCHMARK = process.env.BENCHMARK === '1';
const VERBOSE = process.env.VERBOSE === '1';

// All available circuits for benchmark mode
const ALL_CIRCUITS = ['simple_square', 'hash_batch', 'merkle_membership'];

function getCircuitPaths(circuitName) {
    return {
        proof: path.join(__dirname, `../../test-circuits/${circuitName}/target/keccak/proof`),
        pi: path.join(__dirname, `../../test-circuits/${circuitName}/target/keccak/public_inputs`),
        vk: path.join(__dirname, `../../test-circuits/${circuitName}/target/keccak/vk`),
    };
}

/**
 * Test a single circuit and return results
 */
async function testCircuit(circuitName, verifier, payer, verbose = false) {
    const paths = getCircuitPaths(circuitName);
    
    // Load test data
    if (!fs.existsSync(paths.proof)) {
        throw new Error(`Proof not found: ${paths.proof}\n   Run: cd test-circuits/${circuitName} && ./build.sh`);
    }
    
    const proof = fs.readFileSync(paths.proof);
    const publicInputsRaw = fs.readFileSync(paths.pi);
    const vk = fs.readFileSync(paths.vk);
    
    // Convert raw PI bytes to array of 32-byte buffers
    const numPi = publicInputsRaw.length / 32;
    const publicInputs = [];
    for (let i = 0; i < numPi; i++) {
        publicInputs.push(publicInputsRaw.slice(i * 32, (i + 1) * 32));
    }
    
    // Upload VK
    const vkStart = Date.now();
    const vkResult = await verifier.uploadVK(payer, vk);
    const vkTime = Date.now() - vkStart;
    
    // Verify proof
    const verifyStart = Date.now();
    let lastPhase = '';
    
    const result = await verifier.verify(payer, proof, publicInputs, vkResult.vkAccount, {
        verbose,
        onProgress: (phase, current, total) => {
            if (phase !== lastPhase) {
                if (lastPhase && !BENCHMARK) console.log('  ✅ Done');
                if (!BENCHMARK) console.log(`  ${phase}...`);
                lastPhase = phase;
            }
        }
    });
    if (lastPhase && !BENCHMARK) console.log('  ✅ Done');
    
    const verifyTime = Date.now() - verifyStart;
    
    // Create receipt
    const [receiptPda] = verifier.deriveReceiptPda(vkResult.vkAccount, publicInputs);
    await verifier.createReceipt(
        payer,
        result.stateAccount,
        result.proofAccount,
        vkResult.vkAccount,
        publicInputs
    );
    
    // Validate receipt
    const receipt = await verifier.getReceipt(vkResult.vkAccount, publicInputs);
    if (!receipt) {
        throw new Error('Receipt not found after creation');
    }
    
    // Close accounts
    const closeResult = await verifier.closeAccounts(
        payer,
        result.stateAccount,
        result.proofAccount
    );
    
    return {
        circuit: circuitName,
        numPi,
        verified: result.verified,
        totalCUs: result.totalCUs,
        numTransactions: result.numTransactions,
        numSteps: result.numSteps,
        vkTime,
        verifyTime,
        vkAccount: vkResult.vkAccount,
        receiptPda,
        recoveredLamports: closeResult.recoveredLamports,
        phases: result.phases,
    };
}

/**
 * Run single circuit test with full output
 */
async function runSingleTest(circuitName) {
    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║         UltraHonk Verification Test (using SDK)              ║');
    console.log('╚══════════════════════════════════════════════════════════════╝\n');
    
    console.log(`Circuit: ${circuitName}`);
    console.log(`Program: ${PROGRAM_ID.toBase58()}`);
    console.log(`RPC: ${RPC_URL}`);
    
    const paths = getCircuitPaths(circuitName);
    const proof = fs.readFileSync(paths.proof);
    const vk = fs.readFileSync(paths.vk);
    const pi = fs.readFileSync(paths.pi);
    
    console.log(`\nProof: ${proof.length} bytes (expected: ${PROOF_SIZE})`);
    console.log(`VK: ${vk.length} bytes (expected: ${VK_SIZE})`);
    console.log(`Public inputs: ${pi.length / 32} × 32 = ${pi.length} bytes\n`);
    
    // Setup
    const connection = new Connection(RPC_URL, 'confirmed');
    const payer = Keypair.generate();
    
    console.log('Funding payer account...');
    const airdropSig = await connection.requestAirdrop(payer.publicKey, 10_000_000_000);
    await connection.confirmTransaction(airdropSig);
    console.log('  ✅ Funded\n');
    
    const verifier = new SolanaNoirVerifier(connection, { programId: PROGRAM_ID });
    
    // VK Upload
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
    
    // Verification
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║              PROOF VERIFICATION (per proof)                   ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    
    const publicInputsRaw = pi;
    const numPi = publicInputsRaw.length / 32;
    const publicInputs = [];
    for (let i = 0; i < numPi; i++) {
        publicInputs.push(publicInputsRaw.slice(i * 32, (i + 1) * 32));
    }
    
    const verifyStart = Date.now();
    let lastPhase = '';
    
    const result = await verifier.verify(payer, proof, publicInputs, vkResult.vkAccount, {
        verbose: VERBOSE,
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
    console.log(`  Time: ${(verifyTime / 1000).toFixed(2)}s`);
    
    if (result.phases) {
        console.log('\n  Phase Breakdown:');
        for (const phase of result.phases) {
            console.log(`    ${phase.name.padEnd(25)} ${phase.cus.toLocaleString().padStart(10)} CUs`);
        }
    }
    console.log('');
    
    if (!result.verified) {
        console.error('❌ Verification failed!');
        process.exit(1);
    }
    
    // Receipt
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
    
    // Validate
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
    
    // Close accounts
    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║         ACCOUNT CLEANUP (recover rent)                        ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    
    const closeResult = await verifier.closeAccounts(
        payer,
        result.stateAccount,
        result.proofAccount
    );
    const solRecovered = closeResult.recoveredLamports / 1e9;
    console.log(`  ✅ Accounts closed`);
    console.log(`     Recovered: ${solRecovered.toFixed(4)} SOL (${closeResult.recoveredLamports.toLocaleString()} lamports)`);
    
    // Summary
    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║                         SUMMARY                               ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    
    console.log(`\n  Circuit: ${circuitName}`);
    console.log(`  VK deployment: ${(vkTime / 1000).toFixed(2)}s (one-time)`);
    console.log(`  Proof verification: ${(verifyTime / 1000).toFixed(2)}s`);
    console.log(`  Total CUs: ${result.totalCUs.toLocaleString()}`);
    console.log(`  Transactions: ${result.numTransactions} (${result.numSteps} sequential steps)`);
    console.log(`  Rent recovered: ${solRecovered.toFixed(4)} SOL`);
    console.log(`\n  VK Account: ${vkResult.vkAccount.toBase58()}`);
    console.log(`  Receipt: ${receiptPda.toBase58()}`);
    
    console.log('\n  🎉 All tests passed!\n');
}

/**
 * Run benchmark across all circuits
 */
async function runBenchmark() {
    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║         UltraHonk Verification Benchmark                      ║');
    console.log('╚══════════════════════════════════════════════════════════════╝\n');
    
    console.log(`Program: ${PROGRAM_ID.toBase58()}`);
    console.log(`RPC: ${RPC_URL}`);
    console.log(`Circuits: ${ALL_CIRCUITS.join(', ')}\n`);
    
    // Setup
    const connection = new Connection(RPC_URL, 'confirmed');
    const payer = Keypair.generate();
    
    console.log('Funding payer account...');
    const airdropSig = await connection.requestAirdrop(payer.publicKey, 100_000_000_000); // 100 SOL for all tests
    await connection.confirmTransaction(airdropSig);
    console.log('  ✅ Funded\n');
    
    const verifier = new SolanaNoirVerifier(connection, { programId: PROGRAM_ID });
    const results = [];
    
    for (const circuit of ALL_CIRCUITS) {
        const paths = getCircuitPaths(circuit);
        if (!fs.existsSync(paths.proof)) {
            console.log(`  ⚠️  Skipping ${circuit} (not built)`);
            continue;
        }
        
        console.log(`  Testing ${circuit}...`);
        try {
            const result = await testCircuit(circuit, verifier, payer, false);
            results.push(result);
            console.log(`  ✅ ${circuit}: ${result.numSteps} steps, ${result.totalCUs.toLocaleString()} CUs, ${(result.verifyTime / 1000).toFixed(2)}s`);
        } catch (err) {
            console.log(`  ❌ ${circuit}: ${err.message}`);
        }
    }
    
    // Summary table
    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║                    BENCHMARK RESULTS                          ║');
    console.log('╚══════════════════════════════════════════════════════════════╝\n');
    
    console.log('  ┌─────────────────────┬────────┬────────┬─────────────┬─────────┬───────────────┐');
    console.log('  │ Circuit             │ PIs    │ Steps  │ Total CUs   │ Time    │ Rent Recovered│');
    console.log('  ├─────────────────────┼────────┼────────┼─────────────┼─────────┼───────────────┤');
    
    for (const r of results) {
        const sol = (r.recoveredLamports / 1e9).toFixed(4);
        console.log(`  │ ${r.circuit.padEnd(19)} │ ${String(r.numPi).padStart(6)} │ ${String(r.numSteps).padStart(6)} │ ${r.totalCUs.toLocaleString().padStart(11)} │ ${(r.verifyTime / 1000).toFixed(2).padStart(6)}s │ ${sol.padStart(9)} SOL │`);
    }
    
    console.log('  └─────────────────────┴────────┴────────┴─────────────┴─────────┴───────────────┘');
    
    // Cost estimate
    console.log('\n  Cost Estimate (Mainnet, ~10K microlamports/CU priority fee):');
    for (const r of results) {
        const baseFee = r.numSteps * 0.000005; // 5000 lamports per TX
        const priorityFee = (r.totalCUs / 1_000_000) * 0.01; // ~$0.01 per 1M CU
        const totalCost = baseFee + priorityFee;
        console.log(`    ${r.circuit.padEnd(20)} ~$${totalCost.toFixed(3)}/proof (${r.numSteps} TXs)`);
    }
    
    console.log('\n  🎉 Benchmark complete!\n');
}

// Main entry point
if (BENCHMARK) {
    runBenchmark().catch(err => {
        console.error('\n❌ Benchmark failed:', err.message);
        if (DEBUG) console.error(err.stack);
        process.exit(1);
    });
} else {
    runSingleTest(CIRCUIT_NAME).catch(err => {
        console.error('\n❌ Test failed:', err.message);
        if (DEBUG) console.error(err.stack);
        process.exit(1);
    });
}
