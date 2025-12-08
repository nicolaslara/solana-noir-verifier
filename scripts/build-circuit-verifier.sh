#!/bin/bash
# Build a circuit-specific Solana verifier
#
# Usage: ./scripts/build-circuit-verifier.sh <circuit_dir> [output_dir]
#
# Example:
#   ./scripts/build-circuit-verifier.sh test-circuits/simple_square programs/simple_square_verifier

set -e

CIRCUIT_DIR="${1:?Usage: $0 <circuit_dir> [output_dir]}"
OUTPUT_DIR="${2:-programs/$(basename $CIRCUIT_DIR)_verifier}"
CIRCUIT_NAME=$(basename "$CIRCUIT_DIR")

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Building Solana Verifier for: ${CIRCUIT_NAME} ===${NC}"
echo ""

# Step 1: Compile circuit
echo -e "${BLUE}[1/5] Compiling circuit...${NC}"
cd "$CIRCUIT_DIR"
nargo compile
echo -e "${GREEN}✓ Circuit compiled${NC}"

# Step 2: Generate witness
echo -e "${BLUE}[2/5] Generating witness...${NC}"
nargo execute
echo -e "${GREEN}✓ Witness generated${NC}"

# Step 3: Generate proof with Keccak oracle (for Solana)
echo -e "${BLUE}[3/5] Generating proof (Keccak oracle)...${NC}"
mkdir -p target/keccak
~/.bb/bb prove \
    -b "./target/${CIRCUIT_NAME}.json" \
    -w "./target/${CIRCUIT_NAME}.gz" \
    --oracle_hash keccak \
    --write_vk \
    -o ./target/keccak
echo -e "${GREEN}✓ Proof generated${NC}"
echo "   Proof size: $(wc -c < ./target/keccak/proof | tr -d ' ') bytes"
echo "   VK size: $(wc -c < ./target/keccak/vk | tr -d ' ') bytes"

# Step 4: Verify externally (sanity check)
echo -e "${BLUE}[4/5] Verifying proof externally...${NC}"
~/.bb/bb verify \
    -p ./target/keccak/proof \
    -k ./target/keccak/vk \
    --oracle_hash keccak
echo -e "${GREEN}✓ Proof verified${NC}"

# Go back to root
cd - > /dev/null

# Step 5: Generate Rust VK constants
echo -e "${BLUE}[5/5] Generating Rust VK constants...${NC}"
mkdir -p "$OUTPUT_DIR/src"

cargo run -p plonk-solana-vk-codegen -- \
    --vk "${CIRCUIT_DIR}/target/keccak/vk" \
    --proof "${CIRCUIT_DIR}/target/keccak/proof" \
    --public-inputs "${CIRCUIT_DIR}/target/keccak/public_inputs" \
    --output "${OUTPUT_DIR}/src/vk.rs" \
    --name "${CIRCUIT_NAME}"

echo -e "${GREEN}✓ VK constants generated at ${OUTPUT_DIR}/src/vk.rs${NC}"

echo ""
echo -e "${GREEN}=== Build complete! ===${NC}"
echo ""
echo "Generated files:"
echo "  - ${CIRCUIT_DIR}/target/keccak/proof"
echo "  - ${CIRCUIT_DIR}/target/keccak/vk"
echo "  - ${OUTPUT_DIR}/src/vk.rs"
echo ""
echo "Next steps:"
echo "  1. Copy ${OUTPUT_DIR}/src/vk.rs to your Solana program"
echo "  2. Use VK_BYTES in your verifier"
echo "  3. Run: cargo test -p ${CIRCUIT_NAME}-verifier"

