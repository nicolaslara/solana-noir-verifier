#!/usr/bin/env bash
set -euo pipefail

# Build all test circuits and generate proofs
# Usage: ./build_all.sh [circuit_name]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Check for nargo and bb
if ! command -v nargo &> /dev/null; then
    echo "Error: nargo not found. Install Noir toolchain first."
    exit 1
fi

if ! command -v bb &> /dev/null && ! command -v ~/.bb/bb &> /dev/null; then
    echo "Error: bb not found. Install Barretenberg CLI."
    exit 1
fi

BB=${BB:-$(command -v bb || echo ~/.bb/bb)}

echo "Using nargo: $(nargo --version | head -1)"
echo "Using bb: $BB"
echo ""

build_circuit() {
    local dir="$1"
    local name=$(basename "$dir")
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Building: $name"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    cd "$dir"
    
    # 1. Compile
    echo "  [1/4] Compiling..."
    nargo compile 2>&1 | grep -v "^$" || true
    
    # 2. Execute (generate witness)
    echo "  [2/4] Executing..."
    nargo execute 2>&1 | grep -v "^$" || true
    
    # 3. Generate proof with keccak
    echo "  [3/4] Proving (keccak)..."
    mkdir -p target/keccak
    
    local json_file="target/${name}.json"
    local witness_file="target/${name}.gz"
    
    if [[ ! -f "$json_file" ]]; then
        echo "    Error: $json_file not found"
        return 1
    fi
    
    $BB prove -b "$json_file" -w "$witness_file" -o target/keccak \
        --scheme ultra_honk --oracle_hash keccak --output_format bytes_and_fields --zk
    
    # 4. Generate VK
    echo "  [4/4] Writing VK..."
    $BB write_vk -b "$json_file" -o target/keccak \
        --scheme ultra_honk --oracle_hash keccak --output_format bytes_and_fields
    
    # Report sizes
    local proof_size=$(stat -f%z target/keccak/proof 2>/dev/null || stat -c%s target/keccak/proof)
    local vk_size=$(stat -f%z target/keccak/vk 2>/dev/null || stat -c%s target/keccak/vk)
    local log_n=$(xxd -p -l 1 -s 31 target/keccak/vk 2>/dev/null | xargs printf "%d" || echo "?")
    
    echo ""
    echo "  ✓ Done: $name"
    echo "    - log_n:      $log_n"
    echo "    - Proof size: $proof_size bytes"
    echo "    - VK size:    $vk_size bytes"
    echo ""
    
    cd "$SCRIPT_DIR"
}

# Build specific circuit or all
if [[ $# -gt 0 ]]; then
    # Build specific circuit
    circuit_dir="$SCRIPT_DIR/$1"
    if [[ -d "$circuit_dir" && -f "$circuit_dir/Nargo.toml" ]]; then
        build_circuit "$circuit_dir"
    else
        echo "Error: Circuit '$1' not found"
        exit 1
    fi
else
    # Build all circuits
    echo "Building all test circuits..."
    echo ""
    
    for dir in "$SCRIPT_DIR"/*/; do
        if [[ -f "${dir}Nargo.toml" ]]; then
            build_circuit "$dir" || echo "  ⚠ Failed to build $(basename "$dir")"
        fi
    done
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Build complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

