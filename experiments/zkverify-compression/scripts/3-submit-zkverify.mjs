#!/usr/bin/env node
/**
 * Submit UltraHonk proof to zkVerify and get attestation
 * 
 * Requires:
 * - .env file with SEED_PHRASE (zkVerify testnet account with tokens)
 * - Output files from 2-convert-hex.sh
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, ".env") });

// Import zkverifyjs v2
let zkVerifySession, Library, CurveType, ZkVerifyEvents, UltrahonkVariant, ProofType;
try {
    const zkverify = await import("zkverifyjs");
    zkVerifySession = zkverify.zkVerifySession;
    Library = zkverify.Library;
    CurveType = zkverify.CurveType;
    ZkVerifyEvents = zkverify.ZkVerifyEvents;
    UltrahonkVariant = zkverify.UltrahonkVariant;
    ProofType = zkverify.ProofType;
    console.log("✓ zkverifyjs v2 loaded");
} catch (e) {
    console.error("Error loading zkverifyjs:", e.message);
    console.error("");
    console.error("Try: npm install zkverifyjs@latest");
    process.exit(1);
}

const OUTPUT_DIR = path.join(__dirname, "../output");

async function main() {
    console.log("=== Step 3: Submit to zkVerify ===");
    console.log("");

    // Check seed phrase
    if (!process.env.SEED_PHRASE) {
        console.error("Error: SEED_PHRASE not found in .env");
        console.error("Create scripts/.env with:");
        console.error('  SEED_PHRASE="your twelve word seed phrase here"');
        process.exit(1);
    }

    // Read hex-encoded artifacts
    console.log("Reading proof artifacts...");
    
    let proofHex, vkHex, pubsHex;
    try {
        proofHex = fs.readFileSync(path.join(OUTPUT_DIR, "zkv_proof.hex"), "utf8").trim();
        vkHex = fs.readFileSync(path.join(OUTPUT_DIR, "zkv_vk.hex"), "utf8").trim();
        pubsHex = fs.readFileSync(path.join(OUTPUT_DIR, "zkv_pubs.hex"), "utf8").trim();
    } catch (e) {
        console.error("Error reading hex files. Did you run 2-convert-hex.sh?");
        console.error(e.message);
        process.exit(1);
    }

    console.log("  ✓ Proof loaded");
    console.log("  ✓ VK loaded");
    console.log("  ✓ Public inputs loaded");
    console.log("");

    // Parse the proof JSON to get the actual hex string and determine variant
    const proofJson = JSON.parse(proofHex);
    const variant = proofJson.ZK ? UltrahonkVariant.ZK : UltrahonkVariant.Plain;
    const proofData = proofJson.ZK || proofJson.Plain;
    
    // Parse VK (it's just a quoted hex string)
    const vkData = JSON.parse(vkHex);
    
    // Parse public inputs array
    const pubsData = JSON.parse(pubsHex);

    console.log("Connecting to zkVerify Volta...");
    
    // Connect to zkVerify Volta testnet
    const session = await zkVerifySession
        .start()
        .Volta()
        .withAccount(process.env.SEED_PHRASE);
    
    console.log("  ✓ Connected to zkVerify testnet");
    console.log("");
    
    console.log("Submitting UltraHonk proof...");
    console.log(`  Variant: ${variant}`);
    console.log(`  Proof size: ${proofData.length} chars`);
    console.log(`  Public inputs: ${pubsData.length}`);
    console.log("");

    try {
        // Submit proof for verification (v2 API)
        // API: session.verify().ultrahonk({ variant }).execute({ proofData })
        const { events, transactionResult } = await session.verify()
            .ultrahonk({
                variant: variant
            })
            .execute({
                proofData: {
                    proof: proofData,
                    publicSignals: pubsData,
                    vk: vkData,
                }
            });

        console.log("  ✅ Proof submitted!");
        console.log("");

        // Wait for verification result
        console.log("Waiting for verification...");
        console.log("Transaction result:", JSON.stringify(transactionResult, null, 2));
        console.log("");

        // Save the attestation info
        const attestation = {
            timestamp: new Date().toISOString(),
            transactionResult,
            eventsType: typeof events
        };

        const attestationPath = path.join(OUTPUT_DIR, "attestation.json");
        fs.writeFileSync(attestationPath, JSON.stringify(attestation, null, 2));
        console.log(`✅ Attestation saved to ${attestationPath}`);

        // Listen for aggregation receipt (if using domain with aggregation)
        console.log("");
        console.log("Waiting for aggregation receipt (this may take a few minutes)...");
        console.log("Press Ctrl+C to exit if you don't want to wait.");
        console.log("");
        
        // Subscribe to aggregation events using correct v2 API
        session.subscribe([
            {
                event: ZkVerifyEvents.NewAggregationReceipt,
                callback: async (eventData) => {
                    console.log("");
                    console.log("🎉 Aggregation Receipt Received!");
                    console.log(JSON.stringify(eventData, null, 2));
                    
                    // Save the full receipt
                    const receiptPath = path.join(OUTPUT_DIR, "groth16_receipt.json");
                    fs.writeFileSync(receiptPath, JSON.stringify(eventData, null, 2));
                    console.log(`✅ Groth16 receipt saved to ${receiptPath}`);
                    
                    console.log("");
                    console.log("Next: Run 'node scripts/4-verify-solana.mjs'");
                    process.exit(0);
                },
                options: { domainId: 0 },
            },
        ]);
        
        // Set a timeout for aggregation
        setTimeout(() => {
            console.log("");
            console.log("⚠️  Aggregation timeout reached (5 minutes)");
            console.log("The proof was verified! Aggregation may still be in progress.");
            console.log("Check zkVerify explorer for the final receipt.");
            console.log("");
            console.log("✅ Proof submission complete!");
            process.exit(0);
        }, 5 * 60 * 1000);

    } catch (error) {
        console.error("Error submitting proof:");
        console.error(error);
        process.exit(1);
    }
}

main().catch(console.error);

