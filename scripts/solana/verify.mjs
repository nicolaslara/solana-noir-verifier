#!/usr/bin/env node
/**
 * UltraHonk Verification Script for Surfpool
 * 
 * This script:
 * 1. Creates a proof buffer account
 * 2. Uploads proof in chunks
 * 3. Calls verify instruction
 * 4. Measures compute units
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

// Configuration
const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8899';
// Program ID from deployment (check with: surfpool run deployment --env localnet --unsupervised)
const PROGRAM_ID = new PublicKey(process.env.PROGRAM_ID || '2qH79axdgTbfuutaXvDJQ1e19HqTGzZKDrG73jT4UewK');

// Instruction codes (must match program)
const IX_INIT_BUFFER = 0;
const IX_UPLOAD_CHUNK = 1;
const IX_VERIFY = 2;
const IX_SET_PUBLIC_INPUTS = 3;

// Constants matching the program
const PROOF_SIZE = 16224;
const BUFFER_HEADER_SIZE = 5;
const MAX_CHUNK_SIZE = 900;

// Load test artifacts
const proofPath = path.join(__dirname, '../../test-circuits/simple_square/target/keccak/proof');
const piPath = path.join(__dirname, '../../test-circuits/simple_square/target/keccak/public_inputs');

// Note: paths are relative to scripts/solana/

async function main() {
    console.log('\n=== UltraHonk Verification on Solana (Surfpool) ===\n');
    
    // Load proof and public inputs
    const proof = fs.readFileSync(proofPath);
    const publicInputs = fs.readFileSync(piPath);
    const numPi = publicInputs.length / 32;
    
    console.log(`RPC URL: ${RPC_URL}`);
    console.log(`Program ID: ${PROGRAM_ID.toBase58()}`);
    console.log(`Proof size: ${proof.length} bytes`);
    console.log(`Public inputs: ${numPi} (${publicInputs.length} bytes)`);
    
    // Connect to Surfpool
    const connection = new Connection(RPC_URL, 'confirmed');
    
    // Check connection
    try {
        const version = await connection.getVersion();
        console.log(`Solana version: ${version['solana-core']}`);
    } catch (e) {
        console.error('\n❌ Cannot connect to Solana. Is Surfpool running?');
        console.error('   Start with: surfpool start');
        process.exit(1);
    }
    
    // Generate keypairs
    const payer = Keypair.generate();
    const bufferKeypair = Keypair.generate();
    
    // Calculate buffer size
    const bufferSize = BUFFER_HEADER_SIZE + publicInputs.length + PROOF_SIZE;
    console.log(`\nBuffer size required: ${bufferSize} bytes`);
    
    // Airdrop to payer
    console.log('\nRequesting airdrop...');
    const airdropSig = await connection.requestAirdrop(payer.publicKey, 10_000_000_000);
    await connection.confirmTransaction(airdropSig);
    console.log('  Airdrop received ✓');
    
    // Calculate rent
    const rent = await connection.getMinimumBalanceForRentExemption(bufferSize);
    console.log(`  Rent-exempt minimum: ${rent / 1e9} SOL`);
    
    // Step 1: Create buffer account
    console.log('\nStep 1: Create buffer account...');
    const createAccountIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        newAccountPubkey: bufferKeypair.publicKey,
        lamports: rent,
        space: bufferSize,
        programId: PROGRAM_ID,
    });
    
    const createTx = new Transaction().add(createAccountIx);
    await sendAndConfirmTransaction(connection, createTx, [payer, bufferKeypair]);
    console.log(`  Buffer account: ${bufferKeypair.publicKey.toBase58()}`);
    
    // Step 2: Initialize buffer
    console.log('\nStep 2: Initialize buffer...');
    const initData = Buffer.alloc(3);
    initData[0] = IX_INIT_BUFFER;
    initData.writeUInt16LE(numPi, 1);
    
    const initIx = new TransactionInstruction({
        keys: [{ pubkey: bufferKeypair.publicKey, isSigner: false, isWritable: true }],
        programId: PROGRAM_ID,
        data: initData,
    });
    
    const initTx = new Transaction().add(initIx);
    await sendAndConfirmTransaction(connection, initTx, [payer]);
    console.log('  Buffer initialized ✓');
    
    // Step 3: Set public inputs
    console.log('\nStep 3: Set public inputs...');
    const piData = Buffer.alloc(1 + publicInputs.length);
    piData[0] = IX_SET_PUBLIC_INPUTS;
    publicInputs.copy(piData, 1);
    
    const piIx = new TransactionInstruction({
        keys: [{ pubkey: bufferKeypair.publicKey, isSigner: false, isWritable: true }],
        programId: PROGRAM_ID,
        data: piData,
    });
    
    const piTx = new Transaction().add(piIx);
    await sendAndConfirmTransaction(connection, piTx, [payer]);
    console.log('  Public inputs set ✓');
    
    // Step 4: Upload proof in chunks
    console.log('\nStep 4: Upload proof in chunks...');
    let offset = 0;
    let chunkCount = 0;
    const startUpload = Date.now();
    
    // First upload public inputs
    const piChunkData = Buffer.alloc(3 + publicInputs.length);
    piChunkData[0] = 1; // Instruction: UploadChunk
    piChunkData.writeUInt16LE(0, 1); // offset = 0 (but PI goes after header in our layout)
    // Actually, our upload writes to proof area, not PI area
    // Let's modify: upload PI as first chunk at negative offset... 
    // Simpler: just upload everything including header override
    
    // For this script, let's take a simpler approach:
    // Upload proof data directly, PI needs separate handling
    // Or we can write the full buffer in chunks including PI
    
    while (offset < proof.length) {
        const chunkSize = Math.min(MAX_CHUNK_SIZE, proof.length - offset);
        const chunk = proof.slice(offset, offset + chunkSize);
        
        const uploadData = Buffer.alloc(3 + chunkSize);
        uploadData[0] = IX_UPLOAD_CHUNK;
        uploadData.writeUInt16LE(offset, 1);
        chunk.copy(uploadData, 3);
        
        const uploadIx = new TransactionInstruction({
            keys: [{ pubkey: bufferKeypair.publicKey, isSigner: false, isWritable: true }],
            programId: PROGRAM_ID,
            data: uploadData,
        });
        
        const uploadTx = new Transaction().add(uploadIx);
        await sendAndConfirmTransaction(connection, uploadTx, [payer]);
        
        offset += chunkSize;
        chunkCount++;
        process.stdout.write(`  Uploaded chunk ${chunkCount} (${offset}/${proof.length} bytes)\r`);
    }
    
    const uploadTime = Date.now() - startUpload;
    console.log(`\n  Uploaded ${chunkCount} chunks in ${uploadTime}ms ✓`);
    
    // Step 5: Verify
    console.log('\nStep 5: Verify proof...');
    
    // Request 1.4M compute units (max per transaction)
    const computeBudgetIx = ComputeBudgetProgram.setComputeUnitLimit({
        units: 1_400_000,
    });
    
    const verifyData = Buffer.from([IX_VERIFY]);
    
    const verifyIx = new TransactionInstruction({
        keys: [{ pubkey: bufferKeypair.publicKey, isSigner: false, isWritable: false }],
        programId: PROGRAM_ID,
        data: verifyData,
    });
    
    const verifyTx = new Transaction().add(computeBudgetIx).add(verifyIx);
    
    try {
        const startVerify = Date.now();
        const sig = await sendAndConfirmTransaction(connection, verifyTx, [payer], {
            commitment: 'confirmed',
        });
        const verifyTime = Date.now() - startVerify;
        
        console.log(`\n✅ UltraHonk proof verified successfully!`);
        console.log(`   Signature: ${sig}`);
        console.log(`   Time: ${verifyTime}ms`);
        
        // Get transaction details for CU
        const txDetails = await connection.getTransaction(sig, {
            maxSupportedTransactionVersion: 0,
        });
        if (txDetails?.meta?.computeUnitsConsumed) {
            console.log(`   Compute Units: ${txDetails.meta.computeUnitsConsumed}`);
        }
    } catch (e) {
        console.log(`\n❌ Verification failed: ${e.message}`);
        if (e.logs) {
            console.log('\nProgram logs:');
            e.logs.forEach(log => console.log(`  ${log}`));
        }
    }
}

main().catch(console.error);

