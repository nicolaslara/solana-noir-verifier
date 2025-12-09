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
// Sub-phased sumcheck verification
const IX_PHASE2_ROUNDS = 40;  // Takes start_round, end_round in instruction data
const IX_PHASE2D_RELATIONS = 43;

// Constants
const PROOF_SIZE = 16224;
const BUFFER_HEADER_SIZE = 5;
const STATE_SIZE = 3400; // Updated for sumcheck intermediate state
const MAX_CHUNK_SIZE = 900;

const proofPath = path.join(__dirname, '../../test-circuits/simple_square/target/keccak/proof');
const piPath = path.join(__dirname, '../../test-circuits/simple_square/target/keccak/public_inputs');

async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function executeWithCU(connection, tx, signers, description, skipSimulation = false) {
    console.log(`\n${description}...`);
    try {
        let cus = 0;
        
        // Simulate only if not skipping (simulation uses stale state for dependent TXs)
        if (!skipSimulation) {
            const sim = await connection.simulateTransaction(tx);
            cus = sim.value.unitsConsumed || 0;
            
            if (sim.value.err) {
                console.log(`  ❌ Simulation Error: ${JSON.stringify(sim.value.err)}`);
                console.log('  Logs:');
                for (const log of (sim.value.logs || [])) {
                    console.log(`    ${log}`);
                }
                return { success: false, cus };
            }
        }
        
        // Execute the transaction
        const sig = await connection.sendTransaction(tx, signers, { skipPreflight: true });
        
        // Poll for confirmation and get logs
        for (let i = 0; i < 30; i++) {
            await sleep(500);
            const status = await connection.getSignatureStatus(sig);
            if (status.value?.confirmationStatus === 'confirmed' || 
                status.value?.confirmationStatus === 'finalized') {
                if (status.value?.err) {
                    console.log(`  ❌ TX Error: ${JSON.stringify(status.value.err)}`);
                    // Try to get logs
                    const txDetails = await connection.getTransaction(sig, { maxSupportedTransactionVersion: 0 });
                    if (txDetails?.meta?.logMessages) {
                        console.log('  Logs:');
                        for (const log of txDetails.meta.logMessages) {
                            console.log(`    ${log}`);
                        }
                    }
                    return { success: false, cus };
                }
                // Get actual CU from transaction
                const txDetails = await connection.getTransaction(sig, { maxSupportedTransactionVersion: 0 });
                cus = txDetails?.meta?.computeUnitsConsumed || cus;
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
    
    // ===== PHASE 1: Challenge Generation (6 sub-phases, ~296K CUs total) =====
    // Note: Unified Phase 1 hits BPF heap limit (32KB), so we use sub-phases
    console.log('=== PHASE 1: CHALLENGE GENERATION ===');
    
    results.phase1a = await createPhaseTx(IX_PHASE1A, 'Phase 1a: eta/beta/gamma');
    if (results.phase1a.success) {
        results.phase1b = await createPhaseTx(IX_PHASE1B, 'Phase 1b: alphas/gates');
    }
    if (results.phase1b?.success) {
        results.phase1c = await createPhaseTx(IX_PHASE1C, 'Phase 1c: sumcheck 0-13');
    }
    if (results.phase1c?.success) {
        results.phase1d = await createPhaseTx(IX_PHASE1D, 'Phase 1d: sumcheck 14-27 + final');
    }
    if (results.phase1d?.success) {
        results.phase1e1 = await createPhaseTx(IX_PHASE1E1, 'Phase 1e1: delta part1');
    }
    if (results.phase1e1?.success) {
        results.phase1e2 = await createPhaseTx(IX_PHASE1E2, 'Phase 1e2: delta part2');
    }
    
    const phase1Total = (results.phase1a?.cus || 0) + (results.phase1b?.cus || 0) + 
                       (results.phase1c?.cus || 0) + (results.phase1d?.cus || 0) + 
                       (results.phase1e1?.cus || 0) + (results.phase1e2?.cus || 0);
    results.phase1 = { success: results.phase1e2?.success || false, cus: phase1Total };
    
    // Phase 2: Verify Sumcheck (split into many sub-phases: 2 rounds per TX)
    console.log('\n=== PHASE 2: SUMCHECK VERIFICATION ===');
    
    // Helper to create round verification TX with round range in data
    async function createRoundsTx(startRound, endRound, label) {
        const computeIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 });
        const ix = new TransactionInstruction({
            keys: [
                { pubkey: stateBuffer.publicKey, isSigner: false, isWritable: true },
                { pubkey: proofBuffer.publicKey, isSigner: false, isWritable: false },
            ],
            programId: PROGRAM_ID,
            data: Buffer.from([IX_PHASE2_ROUNDS, startRound, endRound]),
        });
        const tx = new Transaction().add(computeIx).add(ix);
        tx.feePayer = payer.publicKey;
        tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
        
        // Skip simulation for dependent TXs (state changes between TXs)
        const skipSim = startRound > 0;
        const result = await executeWithCU(connection, tx, [payer], label, skipSim);
        return result;
    }
    
    // Read log_n from state account to know how many rounds to verify
    let logN = 28; // Default to max
    if (results.phase1.success) {
        const stateData = await connection.getAccountInfo(stateBuffer.publicKey);
        if (stateData) {
            // log_n is at offset 3 in VerificationState (after phase, challenge_sub_phase, sumcheck_sub_phase)
            logN = stateData.data[3];
            console.log(`Circuit log_n: ${logN}`);
        }
    }
    
    // Verify 2 rounds per TX
    const ROUNDS_PER_TX = 2;
    const roundResults = [];
    let allRoundsSuccess = results.phase1.success;
    
    for (let r = 0; r < logN && allRoundsSuccess; r += ROUNDS_PER_TX) {
        const endRound = Math.min(r + ROUNDS_PER_TX, logN);
        const result = await createRoundsTx(r, endRound, `Phase 2: rounds ${r}-${endRound-1}`);
        roundResults.push({ start: r, end: endRound, ...result });
        allRoundsSuccess = result.success;
    }
    
    // Phase 2d: Relations
    if (allRoundsSuccess) {
        results.phase2d = await createPhaseTx(IX_PHASE2D_RELATIONS, 'Phase 2d: relations');
    } else {
        results.phase2d = { success: false, cus: 0 };
    }
    
    // Calculate totals
    const roundsCUs = roundResults.reduce((sum, r) => sum + (r.cus || 0), 0);
    const phase2Total = roundsCUs + (results.phase2d?.cus || 0);
    results.phase2 = { 
        success: results.phase2d?.success || false, 
        cus: phase2Total,
        roundResults 
    };
    
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
                { pubkey: activeStateBuffer.publicKey, isSigner: false, isWritable: true },
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
    
    console.log('Phase 1 - Challenge Generation (6 TXs):');
    console.log(`  1a (eta/beta/gamma):  ${results.phase1a?.success ? '✅' : '❌'} ${(results.phase1a?.cus || 0).toLocaleString()} CUs`);
    console.log(`  1b (alphas/gates):    ${results.phase1b?.success ? '✅' : '❌'} ${(results.phase1b?.cus || 0).toLocaleString()} CUs`);
    console.log(`  1c (sumcheck 0-13):   ${results.phase1c?.success ? '✅' : '❌'} ${(results.phase1c?.cus || 0).toLocaleString()} CUs`);
    console.log(`  1d (sumcheck 14-27):  ${results.phase1d?.success ? '✅' : '❌'} ${(results.phase1d?.cus || 0).toLocaleString()} CUs`);
    console.log(`  1e1 (delta part1):    ${results.phase1e1?.success ? '✅' : '❌'} ${(results.phase1e1?.cus || 0).toLocaleString()} CUs`);
    console.log(`  1e2 (delta part2):    ${results.phase1e2?.success ? '✅' : '❌'} ${(results.phase1e2?.cus || 0).toLocaleString()} CUs`);
    
    const phase2Rounds = results.phase2?.roundResults || [];
    console.log(`Phase 2 - Sumcheck Verification (${phase2Rounds.length + 1} TXs):`);
    for (const r of phase2Rounds) {
        console.log(`  rounds ${r.start}-${r.end-1}:        ${r.success ? '✅' : '❌'} ${(r.cus || 0).toLocaleString()} CUs`);
    }
    console.log(`  relations:            ${results.phase2d?.success ? '✅' : '❌'} ${(results.phase2d?.cus || 0).toLocaleString()} CUs`);
    
    console.log('Phase 3-4 - Final Verification:');
    console.log(`  3 (MSM):              ${results.phase3.success ? '✅' : '❌'} ${results.phase3.cus?.toLocaleString()} CUs`);
    console.log(`  4 (Pairing):          ${results.phase4.success ? '✅' : '❌'} ${results.phase4.cus?.toLocaleString()} CUs`);
    
    const challengeCUs = results.phase1.cus || 0;
    const sumcheckCUs = results.phase2.cus || 0;
    const finalCUs = (results.phase3.cus || 0) + (results.phase4.cus || 0);
    const total = challengeCUs + sumcheckCUs + finalCUs;
    
    const numRoundTXs = phase2Rounds.length;
    const totalTXs = 6 + numRoundTXs + 1 + 2; // Phase 1 + rounds + relations + Phase 3-4
    
    console.log(`\nPhase 1 (Challenges): ${challengeCUs.toLocaleString()} CUs (6 TXs)`);
    console.log(`Phase 2 (Sumcheck):   ${sumcheckCUs.toLocaleString()} CUs (${numRoundTXs + 1} TXs)`);
    console.log(`Phase 3-4 (Final):    ${finalCUs.toLocaleString()} CUs (2 TXs)`);
    console.log(`Total: ${total.toLocaleString()} CUs across ${totalTXs} transactions`);
    
    const allSuccess = results.phase1.success && 
                       results.phase2.success && results.phase3.success && results.phase4.success;
    
    if (allSuccess) {
        console.log('\n🎉 All phases passed! Verification complete.');
    } else {
        console.log('\n⚠️  Some phases failed. Need further analysis.');
    }
}

main().catch(console.error);

