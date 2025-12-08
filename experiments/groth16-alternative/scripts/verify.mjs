#!/usr/bin/env node
/**
 * Manual Groth16 verification on Solana/Surfpool
 * 
 * Usage: node verify.mjs [program_id]
 */

import { Connection, Keypair, Transaction, TransactionInstruction, PublicKey, sendAndConfirmTransaction } from '@solana/web3.js';
import { readFileSync, existsSync } from 'fs';
import { homedir } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const EXPERIMENT_DIR = join(__dirname, '..');

// Configuration
const RPC_URL = process.env.RPC_URL || 'http://127.0.0.1:8899';
const PROGRAM_ID = process.argv[2] || '4ac1awNJe1AyXQnmZN9yyMKAmNo45fknjtyD4FDEmGez';

// File paths
const PROOF_FILE = join(EXPERIMENT_DIR, 'gnark/output/proof.bin');
const PUBLIC_FILE = join(EXPERIMENT_DIR, 'gnark/output/public.bin');
const KEYPAIR_FILE = join(homedir(), '.config/solana/id.json');

async function main() {
    console.log('=== Groth16 Manual Verification on Solana ===\n');
    
    // Check files exist
    if (!existsSync(PROOF_FILE)) {
        console.error(`Error: Proof file not found at ${PROOF_FILE}`);
        console.error('Run "cd gnark && go run ." first');
        process.exit(1);
    }
    
    if (!existsSync(PUBLIC_FILE)) {
        console.error(`Error: Public input file not found at ${PUBLIC_FILE}`);
        process.exit(1);
    }
    
    // Load proof and public input
    const proof = readFileSync(PROOF_FILE);
    const publicInput = readFileSync(PUBLIC_FILE);
    
    console.log(`RPC URL: ${RPC_URL}`);
    console.log(`Program ID: ${PROGRAM_ID}`);
    console.log(`Proof size: ${proof.length} bytes`);
    console.log(`Public input size: ${publicInput.length} bytes`);
    console.log(`Public input (y=9): 0x${publicInput.toString('hex')}`);
    console.log('');
    
    // Concatenate proof + public input
    const instructionData = Buffer.concat([proof, publicInput]);
    console.log(`Total instruction data: ${instructionData.length} bytes`);
    console.log('');
    
    // Load keypair
    let payer;
    try {
        const keypairData = JSON.parse(readFileSync(KEYPAIR_FILE, 'utf-8'));
        payer = Keypair.fromSecretKey(Uint8Array.from(keypairData));
        console.log(`Payer: ${payer.publicKey.toBase58()}`);
    } catch (e) {
        console.error(`Error loading keypair from ${KEYPAIR_FILE}: ${e.message}`);
        process.exit(1);
    }
    
    // Connect to cluster
    const connection = new Connection(RPC_URL, 'confirmed');
    
    try {
        const version = await connection.getVersion();
        console.log(`Connected to Solana ${version['solana-core']}`);
    } catch (e) {
        console.error(`Error connecting to ${RPC_URL}: ${e.message}`);
        console.error('Make sure Surfpool is running: surfpool start');
        process.exit(1);
    }
    
    // Check balance
    const balance = await connection.getBalance(payer.publicKey);
    console.log(`Balance: ${balance / 1e9} SOL`);
    console.log('');
    
    // Create instruction
    const programId = new PublicKey(PROGRAM_ID);
    const instruction = new TransactionInstruction({
        keys: [], // No accounts needed for this verifier
        programId,
        data: instructionData,
    });
    
    // Create and send transaction
    console.log('Sending verification transaction...');
    console.log('');
    
    const transaction = new Transaction().add(instruction);
    
    // Get fresh blockhash to avoid "already processed" errors
    const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
    transaction.recentBlockhash = blockhash;
    transaction.lastValidBlockHeight = lastValidBlockHeight;
    transaction.feePayer = payer.publicKey;
    
    try {
        const startTime = Date.now();
        const signature = await sendAndConfirmTransaction(
            connection,
            transaction,
            [payer],
            { commitment: 'confirmed' }
        );
        const elapsed = Date.now() - startTime;
        
        console.log('✅ Groth16 proof verified successfully!');
        console.log('');
        console.log(`Signature: ${signature}`);
        console.log(`Time: ${elapsed}ms`);
        
        // Get transaction details for CU measurement
        const txDetails = await connection.getTransaction(signature, {
            commitment: 'confirmed',
            maxSupportedTransactionVersion: 0,
        });
        
        if (txDetails?.meta?.computeUnitsConsumed) {
            console.log(`Compute Units: ${txDetails.meta.computeUnitsConsumed}`);
        }
        
    } catch (e) {
        console.error('❌ Verification failed!');
        console.error('');
        console.error(`Error: ${e.message}`);
        
        // Try to get logs
        if (e.logs) {
            console.error('');
            console.error('Program logs:');
            e.logs.forEach(log => console.error(`  ${log}`));
        }
        
        process.exit(1);
    }
}

main().catch(console.error);

