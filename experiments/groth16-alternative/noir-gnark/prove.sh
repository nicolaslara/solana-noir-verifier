#!/bin/bash
# Prove a Noir circuit using the gnark Groth16 backend
# Run from the noir-gnark/ directory

set -e

CIRCUIT_DIR="${1:-../../../test-circuits/simple_square}"
BACKEND_DIR="noir_backend_using_gnark"

echo "=== Noir → gnark Groth16 Proving ==="
echo ""
echo "Circuit: $CIRCUIT_DIR"
echo ""

# Check if backend is built
if [ ! -f "$BACKEND_DIR/target/release/noir_backend_using_gnark" ] && [ ! -f "$BACKEND_DIR/target/release/libnoir_backend_using_gnark.a" ]; then
    echo "❌ Backend not built. Run setup.sh first."
    exit 1
fi

# Check if circuit exists
if [ ! -d "$CIRCUIT_DIR" ]; then
    echo "❌ Circuit directory not found: $CIRCUIT_DIR"
    exit 1
fi

cd "$CIRCUIT_DIR"

# Step 1: Compile the circuit
echo "Step 1: Compiling Noir circuit..."
nargo compile

# The compiled circuit is at target/<circuit_name>.json
CIRCUIT_JSON=$(find target -name "*.json" -type f | head -1)
echo "  Compiled circuit: $CIRCUIT_JSON"

# Step 2: Execute to generate witness
echo ""
echo "Step 2: Generating witness..."
nargo execute

# The witness is at target/<circuit_name>.gz
WITNESS_GZ=$(find target -name "*.gz" -type f | head -1)
echo "  Witness: $WITNESS_GZ"

# Step 3: Use gnark backend to generate proof
echo ""
echo "Step 3: Generating Groth16 proof with gnark backend..."

# Note: The noir_backend_using_gnark expects to be called as a nargo backend
# For now, we'll document the API it exposes

echo ""
echo "=== Backend API ==="
echo ""
echo "The noir_backend_using_gnark implements the Noir Backend trait:"
echo ""
echo "  1. get_exact_circuit_size(circuit) - Returns circuit size"
echo "  2. get_vk(circuit) - Returns verification key"  
echo "  3. prove(circuit, witness) - Generates Groth16 proof"
echo "  4. verify(circuit, proof, public_inputs) - Verifies proof"
echo ""
echo "To use it as a custom nargo backend, you need to:"
echo "  1. Build as a binary"
echo "  2. Configure nargo to use it via NARGO_BACKEND_PATH"
echo ""
echo "See: https://github.com/lambdaclass/noir_backend_using_gnark"

cd - > /dev/null

echo ""
echo "=== Manual Testing ==="
echo ""
echo "You can also test the gnark backend directly via its Rust API."
echo "See the tests/ directory in noir_backend_using_gnark for examples."

