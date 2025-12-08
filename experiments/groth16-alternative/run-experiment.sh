#!/bin/bash
# Master script to run the Groth16 experiment
# Run from the groth16-alternative/ directory

set -e

echo "=============================================="
echo "  Groth16 Alternative Experiment"
echo "=============================================="
echo ""

# Check prerequisites
echo "Checking prerequisites..."

check_command() {
    if ! command -v $1 &> /dev/null; then
        echo "❌ $1 not found. Please install it first."
        return 1
    else
        echo "✅ $1 found"
        return 0
    fi
}

MISSING=0
check_command go || MISSING=1
check_command cargo || MISSING=1

if [ $MISSING -eq 1 ]; then
    echo ""
    echo "Some prerequisites are missing. Please install them and try again."
    exit 1
fi

echo ""
echo "=============================================="
echo "  gnark Groth16 (Go)"
echo "=============================================="
echo ""

cd gnark

# Initialize Go modules if needed
if [ ! -f "go.sum" ]; then
    echo "Initializing Go modules..."
    go mod tidy
fi

echo "Building gnark experiment..."
go build -o groth16-experiment .

echo ""
echo "Running simple square circuit..."
./groth16-experiment

echo ""
echo "Output files:"
ls -la output/ 2>/dev/null || echo "No output directory yet"

cd ..

echo ""
echo "=============================================="
echo "  Solana Verifier"
echo "=============================================="
echo ""

cd solana-verifier

echo "Building Solana verifier..."
cargo build 2>/dev/null || echo "Note: Full build requires proof/VK data to be filled in"

cd ..

echo ""
echo "=============================================="
echo "  Experiment Complete!"
echo "=============================================="
echo ""
echo "Results:"
echo "  - gnark output: gnark/output/"
echo "  - benchmarks: benchmarks/results.md"
echo ""
echo "Next steps:"
echo "  1. Fill in benchmarks/results.md with timing data"
echo "  2. Update solana-verifier/src/lib.rs with actual VK from gnark/output/"
echo "  3. Run Solana integration tests"
