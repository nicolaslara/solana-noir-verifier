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
// Sub-phased challenge generation (legacy, for debugging)
const IX_PHASE1A = 20;
const IX_PHASE1B = 21;
const IX_PHASE1C = 22;
const IX_PHASE1D = 23;
const IX_PHASE1E1 = 24;
const IX_PHASE1E2 = 25;
// Unified Phase 1 (after FrLimbs optimization, ~300K CUs)
const IX_PHASE1_FULL = 30;
// Sub-phased sumcheck verification
const IX_PHASE2_ROUNDS = 40;  // Takes start_round, end_round in instruction data
const IX_PHASE2D_RELATIONS = 43;
// Sub-phased MSM computation
const IX_PHASE3A_WEIGHTS = 50;
const IX_PHASE3B1_FOLDING = 51;
const IX_PHASE3B2_GEMINI = 52;
const IX_PHASE3C_MSM = 53;
const IX_PHASE3C_AND_PAIRING = 54;  // Combined 3c+4 (saves 1 TX)

// Combine Phase 3c (MSM) + Phase 4 (Pairing) into single TX (set COMBINE_PHASE_3C_4=0 to disable)
const COMBINE_PHASE_3C_4 = process.env.COMBINE_PHASE_3C_4 !== '0';

// Constants
const PROOF_SIZE = 16224;
const BUFFER_HEADER_SIZE = 5;
const STATE_SIZE = 6376; // Updated for fold_pos storage
const MAX_CHUNK_SIZE = 900;

// Get circuit name from environment or default to simple_square
const CIRCUIT_NAME = process.env.CIRCUIT || 'simple_square';
const proofPath = path.join(__dirname, `../../test-circuits/${CIRCUIT_NAME}/target/keccak/proof`);
const piPath = path.join(__dirname, `../../test-circuits/${CIRCUIT_NAME}/target/keccak/public_inputs`);

// Debug logging - set DEBUG=1 to enable verbose logs
const DEBUG = process.env.DEBUG === '1';

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
                // Show full logs only when DEBUG=1
                if (DEBUG && txDetails?.meta?.logMessages) {
                    console.log('  Logs:');
                    for (const log of txDetails.meta.logMessages) {
                        console.log(`    ${log}`);
                    }
                }
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
    console.log(`Circuit: ${CIRCUIT_NAME}`);
    if (DEBUG) console.log('Debug logging: ENABLED');
    
    // Check if proof file exists
    if (!fs.existsSync(proofPath)) {
        console.error(`\n❌ Error: Proof file not found: ${proofPath}`);
        console.error(`   Run: cd test-circuits/${CIRCUIT_NAME} && nargo compile && nargo execute && bb prove ...`);
        process.exit(1);
    }
    
    // Note about VK matching - the program must be built with the same CIRCUIT
    console.log(`\n⚠️  IMPORTANT: Program must be deployed with matching VK!`);
    console.log(`   Run: cd programs/ultrahonk-verifier && CIRCUIT=${CIRCUIT_NAME} cargo build-sbf`);
    console.log(`   Then: solana program deploy target/deploy/ultrahonk_verifier.so --url http://127.0.0.1:8899 --use-rpc\n`);
    
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
    
    // ===== PHASE 1: Challenge Generation (unified with zero-copy) =====
    // Zero-copy Proof struct saves ~16KB heap, enabling unified Phase 1
    console.log('=== PHASE 1: CHALLENGE GENERATION ===');
    
    results.phase1 = await createPhaseTx(IX_PHASE1_FULL, 'Phase 1: All challenges (zero-copy)');
    
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

    
    // Configurable rounds per TX (test with 2, 3, 4, 6, etc.)
    // After FrLimbs optimization, 6 rounds fits comfortably under 1.4M CUs
    const ROUNDS_PER_TX = parseInt(process.env.ROUNDS_PER_TX || '6');
    console.log(`Rounds per TX: ${ROUNDS_PER_TX}`);
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
    
    // Phase 3: Compute MSM (split into sub-phases)
    if (results.phase2.success) {
        // Phase 3a: Weights + scalar accumulation
        results.phase3a = await createPhaseTx(IX_PHASE3A_WEIGHTS, 'Phase 3a: Weights + scalar accum');
        
        // Phase 3b1: Folding only
        if (results.phase3a?.success) {
            results.phase3b1 = await createPhaseTx(IX_PHASE3B1_FOLDING, 'Phase 3b1: Folding');
        } else {
            results.phase3b1 = { success: false, cus: 0 };
        }
        
        // Phase 3b2: Gemini + libra
        if (results.phase3b1?.success) {
            results.phase3b2 = await createPhaseTx(IX_PHASE3B2_GEMINI, 'Phase 3b2: Gemini + libra');
        } else {
            results.phase3b2 = { success: false, cus: 0 };
        }
        
        // Phase 3c: MSM computation (or combined with Phase 4)
        if (results.phase3b2?.success) {
            if (COMBINE_PHASE_3C_4) {
                // Combined Phase 3c + 4 (saves 1 TX!)
                results.phase3c = await createPhaseTx(IX_PHASE3C_AND_PAIRING, 'Phase 3c+4: MSM + Pairing (combined)');
                results.phase4 = { success: results.phase3c?.success, cus: 0, combined: true };
            } else {
                results.phase3c = await createPhaseTx(IX_PHASE3C_MSM, 'Phase 3c: MSM');
            }
        } else {
            results.phase3c = { success: false, cus: 0 };
        }
        
        // Aggregate Phase 3 results
        const phase3Total = (results.phase3a?.cus || 0) + (results.phase3b1?.cus || 0) + 
                           (results.phase3b2?.cus || 0) + (results.phase3c?.cus || 0);
        results.phase3 = {
            success: results.phase3c?.success || false,
            cus: phase3Total
        };
    } else {
        results.phase3 = { success: false, cus: 0 };
        results.phase3a = { success: false, cus: 0 };
        results.phase3b1 = { success: false, cus: 0 };
        results.phase3b2 = { success: false, cus: 0 };
        results.phase3c = { success: false, cus: 0 };
    }
    
    // Phase 4: Final Pairing Check (skip if combined)
    if (!COMBINE_PHASE_3C_4 && results.phase3.success) {
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
    } else if (!results.phase4) {
        results.phase4 = { success: false, cus: 0 };
    }
    
    // Summary
    console.log('\n=== SUMMARY ===');
    
    console.log('Phase 1 - Challenge Generation (1 TX, zero-copy):');
    console.log(`  All challenges:       ${results.phase1?.success ? '✅' : '❌'} ${(results.phase1?.cus || 0).toLocaleString()} CUs`);
    
    const phase2Rounds = results.phase2?.roundResults || [];
    console.log(`Phase 2 - Sumcheck Verification (${phase2Rounds.length + 1} TXs):`);
    for (const r of phase2Rounds) {
        console.log(`  rounds ${r.start}-${r.end-1}:        ${r.success ? '✅' : '❌'} ${(r.cus || 0).toLocaleString()} CUs`);
    }
    console.log(`  relations:            ${results.phase2d?.success ? '✅' : '❌'} ${(results.phase2d?.cus || 0).toLocaleString()} CUs`);
    
    const phase3TxCount = COMBINE_PHASE_3C_4 ? 4 : 4;  // 3a, 3b1, 3b2, 3c(+4)
    console.log(`Phase 3 - MSM Computation (${phase3TxCount} TXs${COMBINE_PHASE_3C_4 ? ', incl. pairing' : ''}):`);
    console.log(`  3a (weights):         ${results.phase3a?.success ? '✅' : '❌'} ${(results.phase3a?.cus || 0).toLocaleString()} CUs`);
    console.log(`  3b1 (folding):        ${results.phase3b1?.success ? '✅' : '❌'} ${(results.phase3b1?.cus || 0).toLocaleString()} CUs`);
    console.log(`  3b2 (gemini+libra):   ${results.phase3b2?.success ? '✅' : '❌'} ${(results.phase3b2?.cus || 0).toLocaleString()} CUs`);
    if (COMBINE_PHASE_3C_4) {
        console.log(`  3c+4 (MSM+Pairing):   ${results.phase3c?.success ? '✅' : '❌'} ${(results.phase3c?.cus || 0).toLocaleString()} CUs`);
    } else {
        console.log(`  3c (MSM):             ${results.phase3c?.success ? '✅' : '❌'} ${(results.phase3c?.cus || 0).toLocaleString()} CUs`);
        console.log('Phase 4 - Pairing Check (1 TX):');
        console.log(`  4 (Pairing):          ${results.phase4.success ? '✅' : '❌'} ${results.phase4.cus?.toLocaleString()} CUs`);
    }
    
    const challengeCUs = results.phase1.cus || 0;
    const sumcheckCUs = results.phase2.cus || 0;
    const msmCUs = results.phase3.cus || 0;
    const pairingCUs = COMBINE_PHASE_3C_4 ? 0 : (results.phase4.cus || 0);
    const total = challengeCUs + sumcheckCUs + msmCUs + pairingCUs;
    
    const numRoundTXs = phase2Rounds.length;
    const phase4TXs = COMBINE_PHASE_3C_4 ? 0 : 1;
    const totalTXs = 1 + numRoundTXs + 1 + 4 + phase4TXs;
    
    console.log(`\nPhase 1 (Challenges): ${challengeCUs.toLocaleString()} CUs (1 TX)`);
    console.log(`Phase 2 (Sumcheck):   ${sumcheckCUs.toLocaleString()} CUs (${numRoundTXs + 1} TXs)`);
    if (COMBINE_PHASE_3C_4) {
        console.log(`Phase 3+4 (MSM+Pair): ${msmCUs.toLocaleString()} CUs (4 TXs)`);
    } else {
        console.log(`Phase 3 (MSM):        ${msmCUs.toLocaleString()} CUs (4 TXs)`);
        console.log(`Phase 4 (Pairing):    ${pairingCUs.toLocaleString()} CUs (1 TX)`);
    }
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

