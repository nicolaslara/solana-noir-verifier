#!/usr/bin/env node
/**
 * Submit UltraHonk proof via zkVerify Relayer REST API
 * 
 * Based on: https://github.com/Rumeyst/zkverify-groth16-guide
 * 
 * Uses the public default API key from zkVerify docs.
 * No wallet setup required!
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import axios from "axios";
import dotenv from "dotenv";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, ".env") });

const OUTPUT_DIR = path.join(__dirname, "../output");

// zkVerify Relayer API - production endpoint
const API_URL = "https://relayer-api.horizenlabs.io/api/v1";

// Default public API key from zkVerify docs
const DEFAULT_API_KEY = "598f259f5f5d7476622ae52677395932fa98901f";

async function main() {
    console.log("=== Step 3: Submit via Relayer API ===");
    console.log("");

    // Use provided API key or default
    const API_KEY = process.env.API_KEY || DEFAULT_API_KEY;
    console.log(`Using API key: ${API_KEY.slice(0, 8)}...`);
    console.log("");

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

    // Parse JSON - the proof is wrapped in {"ZK": "0x..."} format
    const proofJson = JSON.parse(proofHex);
    const proofData = proofJson.ZK || proofJson.Plain || proofJson;
    const vkData = JSON.parse(vkHex);
    const pubsData = JSON.parse(pubsHex);

    console.log("  ✓ Proof loaded (ZK mode)");
    console.log("  ✓ VK loaded");
    console.log(`  ✓ Public inputs: ${pubsData.length} elements`);
    console.log("");

    // Submit proof directly (VK included inline)
    console.log("Submitting UltraHonk proof to zkVerify...");
    console.log(`  Endpoint: ${API_URL}/submit-proof/${API_KEY.slice(0, 8)}...`);
    
    // Format for zkVerify Relayer API
    // variant: "ZK" for zero-knowledge proofs, "Plain" for non-ZK
    const submitParams = {
        proofType: "ultrahonk",
        vkRegistered: false,  // Include VK inline
        proofOptions: {
            library: "barretenberg",
            curve: "bn254",
            variant: "ZK"  // We generated with ZK mode
        },
        proofData: {
            proof: proofData,
            publicSignals: pubsData,
            vk: vkData
        }
    };

    console.log("");
    console.log("Request payload:");
    console.log(`  proofType: ${submitParams.proofType}`);
    console.log(`  library: ${submitParams.proofOptions.library}`);
    console.log(`  curve: ${submitParams.proofOptions.curve}`);
    console.log(`  proof size: ${proofData.length} chars`);
    console.log("");

    let jobId;
    try {
        const response = await axios.post(
            `${API_URL}/submit-proof/${API_KEY}`,
            submitParams
        );
        console.log("  ✅ Proof submitted!");
        console.log("  Response:", JSON.stringify(response.data, null, 2));
        
        jobId = response.data.jobId;
        if (!jobId) {
            console.error("  ❌ No jobId returned");
            process.exit(1);
        }
        console.log(`  Job ID: ${jobId}`);
    } catch (e) {
        console.error("Error submitting proof:");
        console.error("  Status:", e.response?.status);
        console.error("  Data:", JSON.stringify(e.response?.data, null, 2) || e.message);
        process.exit(1);
    }

    console.log("");

    // Poll for result
    console.log("Waiting for verification result...");
    console.log("(This may take a minute)");
    console.log("");
    
    let attempts = 0;
    const maxAttempts = 60;  // 5 minutes with 5s intervals

    while (attempts < maxAttempts) {
        try {
            const statusResp = await axios.get(
                `${API_URL}/job-status/${API_KEY}/${jobId}`
            );
            
            const status = statusResp.data;
            console.log(`  Status: ${status.status}`);
            
            if (status.status === "Finalized") {
                console.log("");
                console.log("🎉 Verification finalized!");
                console.log("");
                console.log("Full result:", JSON.stringify(status, null, 2));
                
                // Save result
                const resultPath = path.join(OUTPUT_DIR, "relayer_result.json");
                fs.writeFileSync(resultPath, JSON.stringify(status, null, 2));
                console.log(`\n✅ Result saved to ${resultPath}`);
                
                // Extract attestation info if available
                if (status.attestationId || status.root || status.proof) {
                    const attestation = {
                        jobId,
                        attestationId: status.attestationId,
                        root: status.root,
                        proof: status.proof,
                        leafIndex: status.leafIndex,
                        blockNumber: status.blockNumber
                    };
                    const attestPath = path.join(OUTPUT_DIR, "attestation.json");
                    fs.writeFileSync(attestPath, JSON.stringify(attestation, null, 2));
                    console.log(`✅ Attestation saved to ${attestPath}`);
                }
                
                return;
            } else if (status.status === "Failed" || status.status === "Rejected") {
                console.error("");
                console.error("❌ Verification failed!");
                console.error("Details:", JSON.stringify(status, null, 2));
                process.exit(1);
            }
            
            await new Promise(r => setTimeout(r, 5000));
            attempts++;
            
        } catch (e) {
            if (e.response?.status === 404) {
                // Job might not be ready yet
                process.stdout.write(".");
            } else {
                console.error("Error checking status:", e.response?.data || e.message);
            }
            await new Promise(r => setTimeout(r, 5000));
            attempts++;
        }
    }

    console.log("");
    console.log("⚠️  Timeout waiting for verification result.");
    console.log("Check zkVerify explorer for job ID:", jobId);
}

main().catch(console.error);

