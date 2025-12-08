#!/usr/bin/env node
/**
 * Verify zkVerify's Groth16 receipt on Solana
 * 
 * This script:
 * 1. Reads the Groth16 proof from zkVerify's attestation
 * 2. Sends it to our Solana Groth16 verifier program
 * 3. Verifies the proof on-chain using alt_bn128 syscalls
 * 
 * Requires:
 * - groth16_receipt.json from step 3
 * - Solana verifier program deployed (from ../groth16-alternative/)
 * - Surfpool running locally
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import {
    Connection,
    PublicKey,
    Keypair,
    Transaction,
    TransactionInstruction,
    sendAndConfirmTransaction,
} from "@solana/web3.js";
import dotenv from "dotenv";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, ".env") });

const OUTPUT_DIR = path.join(__dirname, "../output");

// Default Surfpool endpoint
const SOLANA_RPC = process.env.SOLANA_RPC || "http://localhost:8899";

// Our Groth16 verifier program ID (from groth16-alternative experiment)
// This should be the deployed program ID
const VERIFIER_PROGRAM_ID = process.env.VERIFIER_PROGRAM_ID || "Verify1111111111111111111111111111111111111";

async function main() {
    console.log("=== Step 4: Verify Groth16 on Solana ===");
    console.log("");

    // Read the Groth16 receipt
    const receiptPath = path.join(OUTPUT_DIR, "groth16_receipt.json");
    
    if (!fs.existsSync(receiptPath)) {
        console.error("Error: groth16_receipt.json not found.");
        console.error("Run step 3 first to get the zkVerify attestation.");
        console.error("");
        console.error("For testing without zkVerify, you can use the proof");
        console.error("from our groth16-alternative experiment.");
        process.exit(1);
    }

    console.log("Reading Groth16 receipt...");
    const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
    
    // Extract Groth16 proof components from receipt
    // The exact structure depends on zkVerify's output format
    let proof, publicInputs;
    
    if (receipt.proof) {
        // Direct proof object
        proof = receipt.proof;
        publicInputs = receipt.publicInputs || [];
    } else if (receipt.attestation) {
        // Nested attestation structure
        proof = receipt.attestation.proof;
        publicInputs = receipt.attestation.publicInputs || [];
    } else {
        console.error("Error: Could not find proof in receipt.");
        console.error("Receipt structure:", Object.keys(receipt));
        process.exit(1);
    }

    console.log("  ✓ Receipt loaded");
    console.log("");

    // Connect to Solana
    console.log(`Connecting to Solana at ${SOLANA_RPC}...`);
    const connection = new Connection(SOLANA_RPC, "confirmed");
    
    try {
        const version = await connection.getVersion();
        console.log(`  ✓ Connected (${version["solana-core"]})`);
    } catch (e) {
        console.error("Error connecting to Solana. Is Surfpool running?");
        console.error("Run: surfpool");
        process.exit(1);
    }

    console.log("");

    // Load or create payer keypair
    let payer;
    const keyPath = path.join(__dirname, "payer.json");
    
    if (fs.existsSync(keyPath)) {
        const keyData = JSON.parse(fs.readFileSync(keyPath, "utf8"));
        payer = Keypair.fromSecretKey(Uint8Array.from(keyData));
        console.log(`Using existing payer: ${payer.publicKey.toBase58()}`);
    } else {
        payer = Keypair.generate();
        fs.writeFileSync(keyPath, JSON.stringify(Array.from(payer.secretKey)));
        console.log(`Generated new payer: ${payer.publicKey.toBase58()}`);
        
        // Request airdrop for new account
        console.log("Requesting airdrop...");
        const sig = await connection.requestAirdrop(payer.publicKey, 1e9);
        await connection.confirmTransaction(sig);
        console.log("  ✓ Airdrop received");
    }

    console.log("");

    // Build the verification instruction
    console.log("Building verification instruction...");
    
    // Convert proof to bytes
    // Format: [proof_a (64 bytes), proof_b (128 bytes), proof_c (64 bytes), public_inputs...]
    const proofBytes = buildProofBytes(proof, publicInputs);
    
    console.log(`  Instruction data: ${proofBytes.length} bytes`);
    console.log("");

    // Create instruction
    const programId = new PublicKey(VERIFIER_PROGRAM_ID);
    const instruction = new TransactionInstruction({
        keys: [],  // No accounts needed for verification
        programId,
        data: proofBytes,
    });

    // Send transaction
    console.log("Sending verification transaction...");
    
    const transaction = new Transaction();
    transaction.add(instruction);
    
    try {
        const startTime = Date.now();
        const signature = await sendAndConfirmTransaction(
            connection,
            transaction,
            [payer],
            {
                commitment: "confirmed",
                preflightCommitment: "confirmed",
            }
        );
        const elapsed = Date.now() - startTime;
        
        console.log("");
        console.log("🎉 Verification successful!");
        console.log(`  Signature: ${signature}`);
        console.log(`  Time: ${elapsed}ms`);
        
        // Get transaction details for CU usage
        const txDetails = await connection.getTransaction(signature, {
            commitment: "confirmed",
        });
        
        if (txDetails?.meta?.computeUnitsConsumed) {
            console.log(`  Compute Units: ${txDetails.meta.computeUnitsConsumed}`);
        }
        
        console.log("");
        console.log("✅ End-to-end pipeline complete!");
        console.log("   Noir → UltraHonk → zkVerify → Groth16 → Solana ✓");
        
    } catch (e) {
        console.error("");
        console.error("❌ Verification failed!");
        console.error(e.message);
        
        if (e.logs) {
            console.error("");
            console.error("Program logs:");
            e.logs.forEach(log => console.error("  ", log));
        }
        
        process.exit(1);
    }
}

/**
 * Build proof bytes in the format expected by groth16-solana
 */
function buildProofBytes(proof, publicInputs) {
    // The exact format depends on how zkVerify encodes the Groth16 proof
    // Typical format: [proof_a_x, proof_a_y, proof_b_x1, proof_b_x2, proof_b_y1, proof_b_y2, proof_c_x, proof_c_y]
    // Plus public inputs
    
    const components = [];
    
    // Helper to convert hex string to bytes
    const hexToBytes = (hex) => {
        if (hex.startsWith("0x")) hex = hex.slice(2);
        const bytes = [];
        for (let i = 0; i < hex.length; i += 2) {
            bytes.push(parseInt(hex.substr(i, 2), 16));
        }
        return bytes;
    };
    
    // Handle different proof formats
    if (typeof proof === "string") {
        // Proof is a single hex string
        return Buffer.from(hexToBytes(proof));
    } else if (proof.a && proof.b && proof.c) {
        // Proof is {a, b, c} structure
        components.push(...hexToBytes(proof.a));
        components.push(...hexToBytes(proof.b));
        components.push(...hexToBytes(proof.c));
    } else if (proof.pi_a && proof.pi_b && proof.pi_c) {
        // Proof is {pi_a, pi_b, pi_c} structure (snarkjs-style)
        // Need to flatten the arrays and convert
        const pi_a = proof.pi_a.slice(0, 2).flatMap(x => hexToBytes(x));
        const pi_b = proof.pi_b.slice(0, 2).flatMap(pair => pair.flatMap(x => hexToBytes(x)));
        const pi_c = proof.pi_c.slice(0, 2).flatMap(x => hexToBytes(x));
        
        components.push(...pi_a);
        components.push(...pi_b);
        components.push(...pi_c);
    } else {
        console.error("Unknown proof format:", Object.keys(proof));
        console.error("Proof:", JSON.stringify(proof, null, 2).slice(0, 500));
        process.exit(1);
    }
    
    // Add public inputs
    for (const input of publicInputs) {
        if (typeof input === "string") {
            components.push(...hexToBytes(input));
        } else {
            // Assume it's already bytes or a number
            const bytes = new Array(32).fill(0);
            const hex = BigInt(input).toString(16).padStart(64, "0");
            components.push(...hexToBytes(hex));
        }
    }
    
    return Buffer.from(components);
}

main().catch(console.error);

