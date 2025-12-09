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

// Constants
const PROOF_SIZE = 16224;
const BUFFER_HEADER_SIZE = 5;
const STATE_SIZE = 3144;
const MAX_CHUNK_SIZE = 900;

const proofPath = path.join(__dirname, '../../test-circuits/simple_square/target/keccak/proof');
const piPath = path.join(__dirname, '../../test-circuits/simple_square/target/keccak/public_inputs');

async function simulateWithCU(connection, tx, description) {
    console.log(`\n${description}...`);
    try {
        const sim = await connection.simulateTransaction(tx);
        if (sim.value.err) {
            console.log(`  ❌ Error: ${JSON.stringify(sim.value.err)}`);
            const cuLog = (sim.value.logs || []).find(l => l.includes('consumed'));
            if (cuLog) console.log(`  CU: ${cuLog}`);
            // Print all logs for debugging
            console.log('  Logs:');
            for (const log of (sim.value.logs || [])) {
                console.log(`    ${log}`);
            }
            return { success: false, cus: sim.value.unitsConsumed };
        } else {
            console.log(`  ✅ Success! CUs: ${sim.value.unitsConsumed}`);
            return { success: true, cus: sim.value.unitsConsumed };
        }
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
    
    // Upload proof in chunks
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
        await sendAndConfirmTransaction(connection, uploadTx, [payer]);
        offset += chunkSize;
    }
    console.log('Proof uploaded ✓\n');
    
    // ===== PHASED VERIFICATION =====
    console.log('=== PHASED VERIFICATION ===');
    
    const results = {};
    
    // Phase 1: Generate Challenges
    {
        const computeIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 });
        const ix = new TransactionInstruction({
            keys: [
                { pubkey: stateBuffer.publicKey, isSigner: false, isWritable: true },
                { pubkey: proofBuffer.publicKey, isSigner: false, isWritable: false },
            ],
            programId: PROGRAM_ID,
            data: Buffer.from([IX_PHASED_GENERATE_CHALLENGES]),
        });
        const tx = new Transaction().add(computeIx).add(ix);
        tx.feePayer = payer.publicKey;
        tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
        results.phase1 = await simulateWithCU(connection, tx, 'Phase 1: Generate Challenges');
    }
    
    // Phase 2: Verify Sumcheck
    {
        const computeIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 });
        const ix = new TransactionInstruction({
            keys: [
                { pubkey: stateBuffer.publicKey, isSigner: false, isWritable: true },
                { pubkey: proofBuffer.publicKey, isSigner: false, isWritable: false },
            ],
            programId: PROGRAM_ID,
            data: Buffer.from([IX_PHASED_VERIFY_SUMCHECK]),
        });
        const tx = new Transaction().add(computeIx).add(ix);
        tx.feePayer = payer.publicKey;
        tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
        results.phase2 = await simulateWithCU(connection, tx, 'Phase 2: Verify Sumcheck');
    }
    
    // Phase 3: Compute MSM
    {
        const computeIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 });
        const ix = new TransactionInstruction({
            keys: [
                { pubkey: stateBuffer.publicKey, isSigner: false, isWritable: true },
                { pubkey: proofBuffer.publicKey, isSigner: false, isWritable: false },
            ],
            programId: PROGRAM_ID,
            data: Buffer.from([IX_PHASED_COMPUTE_MSM]),
        });
        const tx = new Transaction().add(computeIx).add(ix);
        tx.feePayer = payer.publicKey;
        tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
        results.phase3 = await simulateWithCU(connection, tx, 'Phase 3: Compute MSM (P0/P1)');
    }
    
    // Phase 4: Final Pairing Check
    {
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
        results.phase4 = await simulateWithCU(connection, tx, 'Phase 4: Final Pairing Check');
    }
    
    // Summary
    console.log('\n=== SUMMARY ===');
    console.log(`Phase 1 (Challenges):  ${results.phase1.success ? '✅' : '❌'} ${results.phase1.cus?.toLocaleString()} CUs`);
    console.log(`Phase 2 (Sumcheck):    ${results.phase2.success ? '✅' : '❌'} ${results.phase2.cus?.toLocaleString()} CUs`);
    console.log(`Phase 3 (MSM):         ${results.phase3.success ? '✅' : '❌'} ${results.phase3.cus?.toLocaleString()} CUs`);
    console.log(`Phase 4 (Pairing):     ${results.phase4.success ? '✅' : '❌'} ${results.phase4.cus?.toLocaleString()} CUs`);
    
    const total = (results.phase1.cus || 0) + (results.phase2.cus || 0) + 
                  (results.phase3.cus || 0) + (results.phase4.cus || 0);
    console.log(`\nTotal: ${total.toLocaleString()} CUs across 4 transactions`);
    
    if (results.phase1.success && results.phase2.success && 
        results.phase3.success && results.phase4.success) {
        console.log('\n🎉 All phases passed! Verification complete.');
    } else {
        console.log('\n⚠️  Some phases failed. Need further splitting.');
    }
}

main().catch(console.error);

