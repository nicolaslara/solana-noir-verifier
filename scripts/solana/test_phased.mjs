#!/usr/bin/env node
/**
 * Test phased verification - measure CUs for each phase
 */
import {
    Connection,
    Keypair,
    PublicKey,
    Transaction,
    TransactionInstruction,
    SystemProgram,
    ComputeBudgetProgram,
    sendAndConfirmTransaction,
} from '@solana/web3.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RPC_URL = 'http://127.0.0.1:8899';
const PROGRAM_ID = new PublicKey('2qH79axdgTbfuutaXvDJQ1e19HqTGzZKDrG73jT4UewK');

// Instruction codes
const IX_INIT_BUFFER = 0;
const IX_UPLOAD_CHUNK = 1;
const IX_SET_PUBLIC_INPUTS = 3;
const IX_PHASED_GENERATE_CHALLENGES = 10;
const IX_PHASED_VERIFY_SUMCHECK = 11;
const IX_PHASED_COMPUTE_MSM = 12;
const IX_PHASED_FINAL_CHECK = 13;
// Sub-phased challenge generation
const IX_PHASE1A = 20;
const IX_PHASE1B = 21;
const IX_PHASE1C = 22;
const IX_PHASE1D = 23;
const IX_PHASE1E1 = 24;
const IX_PHASE1E2 = 25;

// Constants
const PROOF_SIZE = 16224;
const BUFFER_HEADER_SIZE = 5;
const STATE_SIZE = 3304;
const MAX_CHUNK_SIZE = 900;

const proofPath = path.join(__dirname, '../../test-circuits/simple_square/target/keccak/proof');
const piPath = path.join(__dirname, '../../test-circuits/simple_square/target/keccak/public_inputs');

async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function executeWithCU(connection, tx, signers, description) {
    console.log(`\n${description}...`);
    try {
        // First simulate to get CU estimate
        const sim = await connection.simulateTransaction(tx);
        const cus = sim.value.unitsConsumed || 0;
        
        if (sim.value.err) {
            console.log(`  ❌ Simulation Error: ${JSON.stringify(sim.value.err)}`);
            console.log('  Logs:');
            for (const log of (sim.value.logs || [])) {
                console.log(`    ${log}`);
            }
            return { success: false, cus };
        }
        
        // Execute the transaction
        const sig = await connection.sendTransaction(tx, signers, { skipPreflight: true });
        
        // Poll for confirmation
        for (let i = 0; i < 30; i++) {
            await sleep(500);
            const status = await connection.getSignatureStatus(sig);
            if (status.value?.confirmationStatus === 'confirmed' || 
                status.value?.confirmationStatus === 'finalized') {
                if (status.value?.err) {
                    console.log(`  ❌ TX Error: ${JSON.stringify(status.value.err)}`);
                    return { success: false, cus };
                }
                console.log(`  ✅ Success! CUs: ${cus}`);
                return { success: true, cus };
            }
        }
        console.log(`  ⏳ Timeout waiting for confirmation`);
        return { success: false, cus };
    } catch (e) {
        console.log(`  ❌ Exception: ${e.message}`);
        return { success: false, cus: 0 };
    }
}

async function main() {
    console.log('\n=== Phased UltraHonk Verification Test ===\n');
    
    const proof = fs.readFileSync(proofPath);
    const publicInputs = fs.readFileSync(piPath);
    const numPi = publicInputs.length / 32;
    
    console.log(`Proof size: ${proof.length} bytes`);
    console.log(`Public inputs: ${numPi} (${publicInputs.length} bytes)`);
    
    const connection = new Connection(RPC_URL, 'confirmed');
    const payer = Keypair.generate();
    const proofBuffer = Keypair.generate();
    const stateBuffer = Keypair.generate();
    
    // Airdrop
    console.log('\nSetting up accounts...');
    const airdropSig = await connection.requestAirdrop(payer.publicKey, 10_000_000_000);
    await connection.confirmTransaction(airdropSig);
    
    // Create proof buffer
    const proofBufferSize = BUFFER_HEADER_SIZE + publicInputs.length + PROOF_SIZE;
    const proofRent = await connection.getMinimumBalanceForRentExemption(proofBufferSize);
    const createProofTx = new Transaction().add(
        SystemProgram.createAccount({
            fromPubkey: payer.publicKey,
            newAccountPubkey: proofBuffer.publicKey,
            lamports: proofRent,
            space: proofBufferSize,
            programId: PROGRAM_ID,
        })
    );
    await sendAndConfirmTransaction(connection, createProofTx, [payer, proofBuffer]);
    
    // Create state buffer
    const stateRent = await connection.getMinimumBalanceForRentExemption(STATE_SIZE);
    const createStateTx = new Transaction().add(
        SystemProgram.createAccount({
            fromPubkey: payer.publicKey,
            newAccountPubkey: stateBuffer.publicKey,
            lamports: stateRent,
            space: STATE_SIZE,
            programId: PROGRAM_ID,
        })
    );
    await sendAndConfirmTransaction(connection, createStateTx, [payer, stateBuffer]);
    
    // Init proof buffer
    const initData = Buffer.alloc(3);
    initData[0] = IX_INIT_BUFFER;
    initData.writeUInt16LE(numPi, 1);
    const initTx = new Transaction().add(new TransactionInstruction({
        keys: [{ pubkey: proofBuffer.publicKey, isSigner: false, isWritable: true }],
        programId: PROGRAM_ID,
        data: initData,
    }));
    await sendAndConfirmTransaction(connection, initTx, [payer]);
    
    // Set public inputs
    const piData = Buffer.alloc(1 + publicInputs.length);
    piData[0] = IX_SET_PUBLIC_INPUTS;
    publicInputs.copy(piData, 1);
    const piTx = new Transaction().add(new TransactionInstruction({
        keys: [{ pubkey: proofBuffer.publicKey, isSigner: false, isWritable: true }],
        programId: PROGRAM_ID,
        data: piData,
    }));
    await sendAndConfirmTransaction(connection, piTx, [payer]);
    
    // Upload proof in chunks (parallel)
    const uploadPromises = [];
    let offset = 0;
    while (offset < proof.length) {
        const chunkSize = Math.min(MAX_CHUNK_SIZE, proof.length - offset);
        const chunk = proof.slice(offset, offset + chunkSize);
        const uploadData = Buffer.alloc(3 + chunkSize);
        uploadData[0] = IX_UPLOAD_CHUNK;
        uploadData.writeUInt16LE(offset, 1);
        chunk.copy(uploadData, 3);
        const uploadTx = new Transaction().add(new TransactionInstruction({
            keys: [{ pubkey: proofBuffer.publicKey, isSigner: false, isWritable: true }],
            programId: PROGRAM_ID,
            data: uploadData,
        }));
        uploadPromises.push(sendAndConfirmTransaction(connection, uploadTx, [payer]));
        offset += chunkSize;
    }
    await Promise.all(uploadPromises);
    console.log(`Proof uploaded (${uploadPromises.length} chunks in parallel) ✓\n`);
    
    // ===== SUB-PHASED CHALLENGE GENERATION =====
    console.log('=== SUB-PHASED CHALLENGE GENERATION ===');
    
    const results = {};
    
    // Helper to create a phased TX
    async function createPhaseTx(ixCode, description) {
        const computeIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 });
        const ix = new TransactionInstruction({
            keys: [
                { pubkey: stateBuffer.publicKey, isSigner: false, isWritable: true },
                { pubkey: proofBuffer.publicKey, isSigner: false, isWritable: false },
            ],
            programId: PROGRAM_ID,
            data: Buffer.from([ixCode]),
        });
        const tx = new Transaction().add(computeIx).add(ix);
        tx.feePayer = payer.publicKey;
        tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
        return executeWithCU(connection, tx, [payer], description);
    }
    
    // Execute each phase sequentially (state persists between TXs)
    results.phase1a = await createPhaseTx(IX_PHASE1A, 'Phase 1a: eta/beta/gamma');
    if (!results.phase1a.success) console.log('  Stopping - phase failed');
    
    if (results.phase1a.success) {
        results.phase1b = await createPhaseTx(IX_PHASE1B, 'Phase 1b: alphas/gates');
    } else {
        results.phase1b = { success: false, cus: 0 };
    }
    
    if (results.phase1b.success) {
        results.phase1c = await createPhaseTx(IX_PHASE1C, 'Phase 1c: sumcheck 0-13');
    } else {
        results.phase1c = { success: false, cus: 0 };
    }
    
    if (results.phase1c.success) {
        results.phase1d = await createPhaseTx(IX_PHASE1D, 'Phase 1d: sumcheck 14-27 + final');
    } else {
        results.phase1d = { success: false, cus: 0 };
    }
    
    if (results.phase1d.success) {
        results.phase1e1 = await createPhaseTx(IX_PHASE1E1, 'Phase 1e1: delta part1');
    } else {
        results.phase1e1 = { success: false, cus: 0 };
    }
    
    if (results.phase1e1.success) {
        results.phase1e2 = await createPhaseTx(IX_PHASE1E2, 'Phase 1e2: delta part2');
    } else {
        results.phase1e2 = { success: false, cus: 0 };
    }
    
    // Phase 2: Verify Sumcheck
    if (results.phase1e2.success) {
        results.phase2 = await createPhaseTx(IX_PHASED_VERIFY_SUMCHECK, 'Phase 2: Verify Sumcheck');
    } else {
        results.phase2 = { success: false, cus: 0 };
    }
    
    // Phase 3: Compute MSM
    if (results.phase2.success) {
        results.phase3 = await createPhaseTx(IX_PHASED_COMPUTE_MSM, 'Phase 3: Compute MSM (P0/P1)');
    } else {
        results.phase3 = { success: false, cus: 0 };
    }
    
    // Phase 4: Final Pairing Check (no proof_data needed)
    if (results.phase3.success) {
        const computeIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 });
        const ix = new TransactionInstruction({
            keys: [
                { pubkey: stateBuffer.publicKey, isSigner: false, isWritable: true },
            ],
            programId: PROGRAM_ID,
            data: Buffer.from([IX_PHASED_FINAL_CHECK]),
        });
        const tx = new Transaction().add(computeIx).add(ix);
        tx.feePayer = payer.publicKey;
        tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
        results.phase4 = await executeWithCU(connection, tx, [payer], 'Phase 4: Final Pairing Check');
    } else {
        results.phase4 = { success: false, cus: 0 };
    }
    
    // Summary
    console.log('\n=== SUMMARY ===');
    console.log('Challenge Generation Sub-Phases:');
    console.log(`  1a (eta/beta/gamma):  ${results.phase1a.success ? '✅' : '❌'} ${results.phase1a.cus?.toLocaleString()} CUs`);
    console.log(`  1b (alphas/gates):    ${results.phase1b.success ? '✅' : '❌'} ${results.phase1b.cus?.toLocaleString()} CUs`);
    console.log(`  1c (sumcheck 0-13):   ${results.phase1c.success ? '✅' : '❌'} ${results.phase1c.cus?.toLocaleString()} CUs`);
    console.log(`  1d (sumcheck 14-27):  ${results.phase1d.success ? '✅' : '❌'} ${results.phase1d.cus?.toLocaleString()} CUs`);
    console.log(`  1e1 (delta part1):    ${results.phase1e1.success ? '✅' : '❌'} ${results.phase1e1.cus?.toLocaleString()} CUs`);
    console.log(`  1e2 (delta part2):    ${results.phase1e2.success ? '✅' : '❌'} ${results.phase1e2.cus?.toLocaleString()} CUs`);
    console.log('Verification Phases:');
    console.log(`  2 (Sumcheck):         ${results.phase2.success ? '✅' : '❌'} ${results.phase2.cus?.toLocaleString()} CUs`);
    console.log(`  3 (MSM):              ${results.phase3.success ? '✅' : '❌'} ${results.phase3.cus?.toLocaleString()} CUs`);
    console.log(`  4 (Pairing):          ${results.phase4.success ? '✅' : '❌'} ${results.phase4.cus?.toLocaleString()} CUs`);
    
    const challengeCUs = (results.phase1a.cus || 0) + (results.phase1b.cus || 0) + 
                         (results.phase1c.cus || 0) + (results.phase1d.cus || 0) + 
                         (results.phase1e1.cus || 0) + (results.phase1e2.cus || 0);
    const verifyCUs = (results.phase2.cus || 0) + (results.phase3.cus || 0) + (results.phase4.cus || 0);
    const total = challengeCUs + verifyCUs;
    
    console.log(`\nChallenge Generation: ${challengeCUs.toLocaleString()} CUs (6 TXs)`);
    console.log(`Verification: ${verifyCUs.toLocaleString()} CUs (3 TXs)`);
    console.log(`Total: ${total.toLocaleString()} CUs across 9 transactions`);
    
    const allSuccess = results.phase1a.success && results.phase1b.success && 
                       results.phase1c.success && results.phase1d.success && 
                       results.phase1e1.success && results.phase1e2.success &&
                       results.phase2.success && results.phase3.success && results.phase4.success;
    
    if (allSuccess) {
        console.log('\n🎉 All phases passed! Verification complete.');
    } else {
        console.log('\n⚠️  Some phases failed. Need further analysis.');
    }
}

main().catch(console.error);

