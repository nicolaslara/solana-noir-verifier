#!/bin/bash
# Generate UltraHonk proof from Noir circuit for zkVerify
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CIRCUIT_DIR="$SCRIPT_DIR/../circuits/hello_world"
OUTPUT_DIR="$SCRIPT_DIR/../output"

echo "=== Step 1: Generate UltraHonk Proof ==="
echo ""

# Check tools
echo "Checking tools..."
command -v nargo >/dev/null 2>&1 || { echo "Error: nargo not found. Run: noirup"; exit 1; }
command -v bb >/dev/null 2>&1 || { echo "Error: bb not found. Run: bbup -v 0.84.0"; exit 1; }

echo "  nargo: $(nargo --version)"
echo "  bb: $(bb --version)"
echo ""

# Compile circuit
echo "Compiling Noir circuit..."
cd "$CIRCUIT_DIR"
nargo compile
echo "  ✓ Circuit compiled"

# Execute to generate witness
echo "Generating witness..."
nargo execute
echo "  ✓ Witness generated"

# Generate UltraHonk proof (ZK mode is default, keccak oracle for zkVerify compatibility)
echo "Generating UltraHonk proof..."
bb prove \
    -s ultra_honk \
    -b ./target/hello_world.json \
    -w ./target/hello_world.gz \
    -o ./target \
    --oracle_hash keccak \
    --write_vk

echo "  ✓ Proof generated"
echo "  ✓ VK generated (via --write_vk)"

# Copy outputs
mkdir -p "$OUTPUT_DIR"
cp ./target/proof "$OUTPUT_DIR/ultrahonk_proof.bin"
cp ./target/vk "$OUTPUT_DIR/ultrahonk_vk.bin"
cp ./target/public_inputs "$OUTPUT_DIR/public_inputs.bin" 2>/dev/null || echo "  (no public_inputs file)"

echo ""
echo "=== Output Files ==="
ls -la "$OUTPUT_DIR"/*.bin 2>/dev/null || echo "No .bin files found"

echo ""
echo "=== Summary ==="
echo "  Proof:  $(wc -c < "$OUTPUT_DIR/ultrahonk_proof.bin" 2>/dev/null || echo 'N/A') bytes"
echo "  VK:     $(wc -c < "$OUTPUT_DIR/ultrahonk_vk.bin" 2>/dev/null || echo 'N/A') bytes"
echo ""
echo "Next: Run ./scripts/2-convert-hex.sh"

