#!/usr/bin/env node
/**
 * Measure actual CU consumption by simulating with progressively higher limits
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
const PROOF_SIZE = 16224;
const BUFFER_HEADER_SIZE = 5;
const MAX_CHUNK_SIZE = 1020;
const IX_INIT_BUFFER = 0;
const IX_UPLOAD_CHUNK = 1;
const IX_VERIFY = 2;
const IX_SET_PUBLIC_INPUTS = 3;

const proofPath = path.join(__dirname, '../../test-circuits/simple_square/target/keccak/proof');
const piPath = path.join(__dirname, '../../test-circuits/simple_square/target/keccak/public_inputs');

async function main() {
    console.log('\n=== Measuring UltraHonk CU Requirements ===\n');
    
    const proof = fs.readFileSync(proofPath);
    const publicInputs = fs.readFileSync(piPath);
    const numPi = publicInputs.length / 32;
    
    const connection = new Connection(RPC_URL, 'confirmed');
    const payer = Keypair.generate();
    const bufferKeypair = Keypair.generate();
    const bufferSize = BUFFER_HEADER_SIZE + publicInputs.length + PROOF_SIZE;
    
    // Airdrop
    console.log('Setting up...');
    const airdropSig = await connection.requestAirdrop(payer.publicKey, 10_000_000_000);
    await connection.confirmTransaction(airdropSig);
    
    // Create buffer
    const rent = await connection.getMinimumBalanceForRentExemption(bufferSize);
    const createTx = new Transaction().add(
        SystemProgram.createAccount({
            fromPubkey: payer.publicKey,
            newAccountPubkey: bufferKeypair.publicKey,
            lamports: rent,
            space: bufferSize,
            programId: PROGRAM_ID,
        })
    );
    await sendAndConfirmTransaction(connection, createTx, [payer, bufferKeypair]);
    
    // Init buffer
    const initData = Buffer.alloc(3);
    initData[0] = IX_INIT_BUFFER;
    initData.writeUInt16LE(numPi, 1);
    const initTx = new Transaction().add(new TransactionInstruction({
        keys: [{ pubkey: bufferKeypair.publicKey, isSigner: false, isWritable: true }],
        programId: PROGRAM_ID,
        data: initData,
    }));
    await sendAndConfirmTransaction(connection, initTx, [payer]);
    
    // Set public inputs
    const piData = Buffer.alloc(1 + publicInputs.length);
    piData[0] = IX_SET_PUBLIC_INPUTS;
    publicInputs.copy(piData, 1);
    const piTx = new Transaction().add(new TransactionInstruction({
        keys: [{ pubkey: bufferKeypair.publicKey, isSigner: false, isWritable: true }],
        programId: PROGRAM_ID,
        data: piData,
    }));
    await sendAndConfirmTransaction(connection, piTx, [payer]);
    
    // Upload proof
    let offset = 0;
    while (offset < proof.length) {
        const chunkSize = Math.min(MAX_CHUNK_SIZE, proof.length - offset);
        const chunk = proof.slice(offset, offset + chunkSize);
        const uploadData = Buffer.alloc(3 + chunkSize);
        uploadData[0] = IX_UPLOAD_CHUNK;
        uploadData.writeUInt16LE(offset, 1);
        chunk.copy(uploadData, 3);
        const uploadTx = new Transaction().add(new TransactionInstruction({
            keys: [{ pubkey: bufferKeypair.publicKey, isSigner: false, isWritable: true }],
            programId: PROGRAM_ID,
            data: uploadData,
        }));
        await sendAndConfirmTransaction(connection, uploadTx, [payer]);
        offset += chunkSize;
    }
    console.log('Proof uploaded\n');
    
    // Try simulate with progressively higher CU limits
    const cuLimits = [1_400_000, 2_000_000, 5_000_000, 10_000_000, 50_000_000, 100_000_000];
    
    for (const limit of cuLimits) {
        const limitStr = (limit / 1_000_000).toFixed(1) + 'M';
        console.log('Testing with ' + limitStr + ' CU limit...');
        
        const computeBudgetIx = ComputeBudgetProgram.setComputeUnitLimit({ units: limit });
        const verifyData = Buffer.from([IX_VERIFY]);
        const verifyIx = new TransactionInstruction({
            keys: [{ pubkey: bufferKeypair.publicKey, isSigner: false, isWritable: false }],
            programId: PROGRAM_ID,
            data: verifyData,
        });
        const verifyTx = new Transaction().add(computeBudgetIx).add(verifyIx);
        verifyTx.feePayer = payer.publicKey;
        verifyTx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
        
        try {
            const sim = await connection.simulateTransaction(verifyTx);
            if (sim.value.err) {
                const logs = sim.value.logs || [];
                const cuLog = logs.find(l => l.includes('consumed'));
                console.log('  ❌ Failed: ' + JSON.stringify(sim.value.err));
                if (cuLog) console.log('  CU: ' + cuLog);
            } else {
                console.log('  ✅ SUCCESS with ' + limitStr + '!');
                console.log('  Units consumed: ' + sim.value.unitsConsumed);
                return;
            }
        } catch (e) {
            console.log('  ❌ Error: ' + e.message);
        }
    }
    
    console.log('\n⚠️  Verification exceeds 100M CUs - this is not feasible on Solana');
}

main().catch(console.error);
