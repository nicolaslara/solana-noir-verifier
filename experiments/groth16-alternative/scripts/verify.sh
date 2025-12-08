#!/bin/bash
# Manual Groth16 verification on Surfpool
# Usage: ./verify.sh [program_id]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXPERIMENT_DIR="$(dirname "$SCRIPT_DIR")"

# Program ID (use provided or default)
PROGRAM_ID="${1:-4ac1awNJe1AyXQnmZN9yyMKAmNo45fknjtyD4FDEmGez}"

# Paths to proof and public input
PROOF_FILE="$EXPERIMENT_DIR/gnark/output/proof.bin"
PUBLIC_FILE="$EXPERIMENT_DIR/gnark/output/public.bin"

echo "=== Groth16 Manual Verification ==="
echo "Program ID: $PROGRAM_ID"
echo "Proof file: $PROOF_FILE"
echo "Public input file: $PUBLIC_FILE"
echo ""

# Check files exist
if [[ ! -f "$PROOF_FILE" ]]; then
    echo "Error: Proof file not found at $PROOF_FILE"
    echo "Run 'cd gnark && go run .' first"
    exit 1
fi

if [[ ! -f "$PUBLIC_FILE" ]]; then
    echo "Error: Public input file not found at $PUBLIC_FILE"
    exit 1
fi

# Show file sizes
PROOF_SIZE=$(wc -c < "$PROOF_FILE" | tr -d ' ')
PUBLIC_SIZE=$(wc -c < "$PUBLIC_FILE" | tr -d ' ')
echo "Proof size: $PROOF_SIZE bytes"
echo "Public input size: $PUBLIC_SIZE bytes"

# Concatenate proof + public input into hex
INSTRUCTION_DATA=$(cat "$PROOF_FILE" "$PUBLIC_FILE" | xxd -p | tr -d '\n')

echo "Instruction data: ${#INSTRUCTION_DATA} hex chars ($(( ${#INSTRUCTION_DATA} / 2 )) bytes)"
echo ""

# Check Solana connection
echo "Checking Solana connection..."
if ! solana cluster-version 2>/dev/null; then
    echo "Error: Cannot connect to Solana cluster"
    echo "Make sure Surfpool is running: surfpool start"
    exit 1
fi

echo ""
echo "Sending verification transaction..."
echo ""

# Create and send transaction
# Using solana program invoke with base64-encoded data
INSTRUCTION_DATA_BASE64=$(cat "$PROOF_FILE" "$PUBLIC_FILE" | base64)

# Use a temporary keypair for the transaction
solana transfer $(solana-keygen pubkey) 0.001 --allow-unfunded-recipient 2>/dev/null || true

# Call the program with instruction data
echo "Instruction data (first 64 bytes hex): ${INSTRUCTION_DATA:0:128}..."
echo ""

# Create transaction using Solana CLI
# The program expects: proof (256 bytes) + public_input (32 bytes)
TX_RESULT=$(solana program call \
    "$PROGRAM_ID" \
    --data-file <(cat "$PROOF_FILE" "$PUBLIC_FILE") \
    2>&1) || true

echo "$TX_RESULT"

# Check for success
if echo "$TX_RESULT" | grep -q "Success"; then
    echo ""
    echo "✅ Groth16 proof verified successfully on Solana!"
elif echo "$TX_RESULT" | grep -q "Error"; then
    echo ""
    echo "❌ Verification failed"
    exit 1
else
    echo ""
    echo "Transaction sent. Check logs above for result."
fi

