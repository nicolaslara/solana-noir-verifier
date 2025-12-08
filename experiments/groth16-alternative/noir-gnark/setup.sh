#!/bin/bash
# Setup script for Noir → gnark Groth16 backend
# This clones and builds the lambdaclass/noir_backend_using_gnark project

set -e

echo "=== Setting up Noir → gnark Groth16 Backend ==="
echo ""

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v go &> /dev/null; then
    echo "❌ Go not found. Please install Go 1.21+"
    exit 1
fi
echo "✅ Go $(go version | cut -d' ' -f3)"

if ! command -v cargo &> /dev/null; then
    echo "❌ Rust/Cargo not found. Please install Rust"
    exit 1
fi
echo "✅ Rust $(cargo --version)"

if ! command -v nargo &> /dev/null; then
    echo "❌ nargo not found. Please install Noir toolchain"
    echo "   Run: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash"
    echo "   Then: noirup"
    exit 1
fi
echo "✅ nargo $(nargo --version)"

echo ""

# Clone the noir_backend_using_gnark repo
BACKEND_DIR="noir_backend_using_gnark"

if [ -d "$BACKEND_DIR" ]; then
    echo "Directory $BACKEND_DIR already exists. Updating..."
    cd $BACKEND_DIR
    git pull
    cd ..
else
    echo "Cloning lambdaclass/noir_backend_using_gnark..."
    git clone https://github.com/lambdaclass/noir_backend_using_gnark.git
fi

echo ""
echo "Building the gnark backend..."
cd $BACKEND_DIR

# Build the Go library
echo "Building Go library..."
cd gnark_backend_ffi
go build -buildmode=c-archive -o libgnark_backend.a .
cd ..

# Build the Rust wrapper
echo "Building Rust wrapper..."
cargo build --release

echo ""
echo "=== Setup Complete ==="
echo ""
echo "The gnark backend is built at: $PWD/target/release/"
echo ""
echo "Next steps:"
echo "  1. Compile your Noir circuit: nargo compile"
echo "  2. Use the gnark backend to prove (see prove.sh)"

