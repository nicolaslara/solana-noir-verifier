#!/bin/bash
# Convert UltraHonk proof artifacts to zkVerify hex format
# Based on zkVerify documentation
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/../output"

echo "=== Step 2: Convert to zkVerify Hex Format ==="
echo ""

PROOF_TYPE="Plain"  # "Plain" for non-ZK, "ZK" for zero-knowledge
PROOF_FILE_PATH="$OUTPUT_DIR/ultrahonk_proof.bin"
VK_FILE_PATH="$OUTPUT_DIR/ultrahonk_vk.bin"
PUBS_FILE_PATH="$OUTPUT_DIR/public_inputs.bin"

ZKV_PROOF_HEX_FILE_PATH="$OUTPUT_DIR/zkv_proof.hex"
ZKV_VK_HEX_FILE_PATH="$OUTPUT_DIR/zkv_vk.hex"
ZKV_PUBS_HEX_FILE_PATH="$OUTPUT_DIR/zkv_pubs.hex"

# Convert proof to hex JSON
if [ -f "$PROOF_FILE_PATH" ]; then
    PROOF_BYTES=$(xxd -p -c 256 "$PROOF_FILE_PATH" | tr -d '\n')
    printf '{\n  "%s": "0x%s"\n}\n' "$PROOF_TYPE" "$PROOF_BYTES" > "$ZKV_PROOF_HEX_FILE_PATH"
    echo "✅ proof -> ${ZKV_PROOF_HEX_FILE_PATH}"
    echo "   Size: $(wc -c < "$ZKV_PROOF_HEX_FILE_PATH") bytes (hex)"
else
    echo "❌ Proof file not found: $PROOF_FILE_PATH"
    exit 1
fi

# Convert VK to hex
if [ -f "$VK_FILE_PATH" ]; then
    printf '"0x%s"\n' "$(xxd -p -c 0 "$VK_FILE_PATH")" > "$ZKV_VK_HEX_FILE_PATH"
    echo "✅ vk -> ${ZKV_VK_HEX_FILE_PATH}"
    echo "   Size: $(wc -c < "$ZKV_VK_HEX_FILE_PATH") bytes (hex)"
else
    echo "❌ VK file not found: $VK_FILE_PATH"
    exit 1
fi

# Convert public inputs to hex array
if [ -f "$PUBS_FILE_PATH" ]; then
    xxd -p -c 32 "$PUBS_FILE_PATH" | sed 's/.*/"0x&"/' | paste -sd, - | sed 's/.*/[&]/' > "$ZKV_PUBS_HEX_FILE_PATH"
    echo "✅ pubs -> ${ZKV_PUBS_HEX_FILE_PATH}"
    echo "   Size: $(wc -c < "$ZKV_PUBS_HEX_FILE_PATH") bytes (hex)"
else
    # If no public inputs file, create empty array
    echo "[]" > "$ZKV_PUBS_HEX_FILE_PATH"
    echo "⚠️  No public inputs file, created empty array"
fi

echo ""
echo "=== Output Files ==="
ls -la "$OUTPUT_DIR"/*.hex

echo ""
echo "=== Preview ==="
echo ""
echo "Proof (first 200 chars):"
head -c 200 "$ZKV_PROOF_HEX_FILE_PATH"
echo "..."
echo ""
echo "VK (first 200 chars):"
head -c 200 "$ZKV_VK_HEX_FILE_PATH"
echo "..."
echo ""
echo "Public inputs:"
cat "$ZKV_PUBS_HEX_FILE_PATH"
echo ""

echo ""
echo "Next: Run 'node scripts/3-submit-zkverify.mjs'"

