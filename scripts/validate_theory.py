#!/usr/bin/env python3
"""
Validation script for UltraHonk proof theory.

This script parses our test proof and VK to validate our theoretical understanding.
Run from the repository root:
    python3 scripts/validate_theory.py

Requirements:
    pip install pycryptodome
"""

import os
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple, Optional

# BN254 scalar field modulus
BN254_R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001

def fr_from_bytes(b: bytes) -> int:
    """Convert 32 big-endian bytes to field element."""
    return int.from_bytes(b, 'big') % BN254_R

def fr_to_bytes(x: int) -> bytes:
    """Convert field element to 32 big-endian bytes."""
    return (x % BN254_R).to_bytes(32, 'big')

def fr_add(a: int, b: int) -> int:
    return (a + b) % BN254_R

def fr_sub(a: int, b: int) -> int:
    return (a - b) % BN254_R

def fr_mul(a: int, b: int) -> int:
    return (a * b) % BN254_R

def fr_inv(a: int) -> int:
    """Modular inverse using extended Euclidean algorithm."""
    return pow(a, BN254_R - 2, BN254_R)

def fr_div(a: int, b: int) -> int:
    return fr_mul(a, fr_inv(b))

@dataclass
class VerificationKey:
    """Parsed verification key."""
    log2_circuit_size: int
    log2_domain_size: int
    num_public_inputs: int
    commitments: List[bytes]  # 28 G1 points, 64 bytes each

    @classmethod
    def from_bytes(cls, data: bytes) -> 'VerificationKey':
        assert len(data) == 1888, f"Expected 1888 bytes, got {len(data)}"
        
        # Parse headers (3 x 32-byte big-endian u256)
        log2_circuit_size = int.from_bytes(data[0:32], 'big')
        log2_domain_size = int.from_bytes(data[32:64], 'big')
        num_public_inputs = int.from_bytes(data[64:96], 'big')
        
        # Parse commitments (28 x 64 bytes)
        commitments = []
        for i in range(28):
            offset = 96 + i * 64
            commitments.append(data[offset:offset+64])
        
        return cls(
            log2_circuit_size=log2_circuit_size,
            log2_domain_size=log2_domain_size,
            num_public_inputs=num_public_inputs,
            commitments=commitments,
        )
    
    def circuit_size(self) -> int:
        return 2 ** self.log2_circuit_size

@dataclass
class Proof:
    """Parsed UltraHonk proof."""
    data: List[bytes]  # Fr elements (32 bytes each)
    log_n: int
    is_zk: bool
    
    @classmethod
    def expected_fr_count(cls, log_n: int, is_zk: bool) -> int:
        """Calculate expected number of Fr elements in proof."""
        size = 0
        
        # Pairing point object
        size += 16
        
        # Wire commitments (8 G1 = 16 Fr)
        size += 16
        
        if is_zk:
            # Libra concat (2 Fr) + sum (1 Fr)
            size += 3
        
        # Sumcheck univariates
        univariate_len = 9 if is_zk else 8
        size += log_n * univariate_len
        
        # Sumcheck evaluations
        size += 41 if is_zk else 40
        
        if is_zk:
            # Libra post-sumcheck data
            size += 8  # libra_eval(1) + grand_sum(2) + quotient(2) + masking(2) + masking_eval(1)
        
        # Gemini fold commitments
        size += (log_n - 1) * 2
        
        # Gemini A evaluations
        size += log_n
        
        if is_zk:
            # Small IPA
            size += 2
        
        # Shplonk Q + KZG W
        size += 4
        
        # Extra protocol data
        size += 2 if is_zk else 1
        
        return size
    
    @classmethod
    def from_bytes(cls, data: bytes, log_n: int, is_zk: bool = True) -> 'Proof':
        assert len(data) % 32 == 0, "Proof must be multiple of 32 bytes"
        
        expected = cls.expected_fr_count(log_n, is_zk)
        actual = len(data) // 32
        
        assert actual == expected, f"Expected {expected} Fr elements, got {actual}"
        
        elements = []
        for i in range(actual):
            elements.append(data[i*32:(i+1)*32])
        
        return cls(data=elements, log_n=log_n, is_zk=is_zk)
    
    def pairing_point_object(self) -> List[bytes]:
        """Get the 16 pairing point object Fr values."""
        return self.data[0:16]
    
    def wire_commitment(self, idx: int) -> bytes:
        """Get G1 commitment at index (64 bytes)."""
        offset = 16 + idx * 2
        return self.data[offset] + self.data[offset + 1]
    
    def libra_sum(self) -> Optional[bytes]:
        """Get libra sum for ZK proofs."""
        if not self.is_zk:
            return None
        offset = 16 + 16 + 2  # ppo + wires + libra_concat
        return self.data[offset]
    
    def sumcheck_univariate(self, round: int) -> List[bytes]:
        """Get univariate coefficients for a sumcheck round."""
        base = 16 + 16  # ppo + wires
        if self.is_zk:
            base += 3  # libra data
        
        univariate_len = 9 if self.is_zk else 8
        offset = base + round * univariate_len
        return self.data[offset:offset + univariate_len]
    
    def sumcheck_evaluations(self) -> List[bytes]:
        """Get all sumcheck evaluations."""
        base = 16 + 16  # ppo + wires
        if self.is_zk:
            base += 3  # libra data
        
        univariate_len = 9 if self.is_zk else 8
        base += self.log_n * univariate_len
        
        num_evals = 41 if self.is_zk else 40
        return self.data[base:base + num_evals]


def keccak256(data: bytes) -> bytes:
    """Compute Keccak256 hash."""
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except ImportError:
        # Fallback using hashlib (Python 3.6+)
        import hashlib
        return hashlib.sha3_256(data).digest()


def compute_vk_hash(vk: VerificationKey) -> bytes:
    """Compute VK hash as done by bb."""
    # Hash: log2_circuit_size || log2_domain_size || num_public_inputs || all commitments
    data = b''
    data += vk.log2_circuit_size.to_bytes(32, 'big')
    data += vk.log2_domain_size.to_bytes(32, 'big')
    data += vk.num_public_inputs.to_bytes(32, 'big')
    for commitment in vk.commitments:
        data += commitment
    
    hash_result = keccak256(data)
    return reduce_to_fr(hash_result)


def reduce_to_fr(h: bytes) -> bytes:
    """Reduce 32-byte hash to Fr (mod r)."""
    value = int.from_bytes(h, 'big')
    reduced = value % BN254_R
    return reduced.to_bytes(32, 'big')


def split_challenge(challenge: bytes) -> Tuple[bytes, bytes]:
    """Split 254-bit challenge into two 127-bit values."""
    value = int.from_bytes(challenge, 'big')
    
    # Lower 127 bits
    lo = value & ((1 << 127) - 1)
    # Upper 127 bits  
    hi = (value >> 127) & ((1 << 127) - 1)
    
    return (lo.to_bytes(32, 'big'), hi.to_bytes(32, 'big'))


def print_hex(name: str, data: bytes, max_len: int = 32):
    """Print bytes as hex with a name."""
    hex_str = data.hex()
    if len(hex_str) > max_len * 2:
        hex_str = hex_str[:max_len*2] + "..."
    print(f"  {name}: 0x{hex_str}")


def validate_vk_structure(vk_path: Path) -> VerificationKey:
    """Validate VK structure and print details."""
    print("\n" + "="*60)
    print("VERIFICATION KEY ANALYSIS")
    print("="*60)
    
    data = vk_path.read_bytes()
    print(f"\nFile: {vk_path}")
    print(f"Size: {len(data)} bytes (expected: 1888)")
    
    vk = VerificationKey.from_bytes(data)
    
    print(f"\nHeader Fields:")
    print(f"  log2_circuit_size: {vk.log2_circuit_size} (circuit size = {vk.circuit_size()})")
    print(f"  log2_domain_size: {vk.log2_domain_size}")
    print(f"  num_public_inputs: {vk.num_public_inputs}")
    
    print(f"\nCommitments ({len(vk.commitments)} G1 points):")
    commitment_names = [
        "Q_m", "Q_c", "Q_l", "Q_r", "Q_o", "Q_4", 
        "Q_lookup", "Q_arith", "Q_range", "Q_elliptic", "Q_aux",
        "Q_poseidon2_ext", "Q_poseidon2_int",
        "σ₁", "σ₂", "σ₃", "σ₄",
        "ID₁", "ID₂", "ID₃", "ID₄",
        "Table₁", "Table₂", "Table₃", "Table₄",
        "L_first", "L_last", "???"
    ]
    for i, (name, comm) in enumerate(zip(commitment_names, vk.commitments)):
        x = comm[:32].hex()[:16] + "..."
        y = comm[32:].hex()[:16] + "..."
        print(f"  [{i:2d}] {name:18s}: x=0x{x}, y=0x{y}")
    
    # Compute and show VK hash
    vk_hash = compute_vk_hash(vk)
    print(f"\nComputed VK Hash: 0x{vk_hash.hex()}")
    
    return vk


def validate_proof_structure(proof_path: Path, log_n: int, is_zk: bool = True) -> Proof:
    """Validate proof structure and print details."""
    print("\n" + "="*60)
    print("PROOF ANALYSIS")
    print("="*60)
    
    data = proof_path.read_bytes()
    expected_fr = Proof.expected_fr_count(log_n, is_zk)
    expected_bytes = expected_fr * 32
    
    print(f"\nFile: {proof_path}")
    print(f"Size: {len(data)} bytes")
    print(f"Expected: {expected_bytes} bytes ({expected_fr} Fr elements)")
    print(f"Config: log_n={log_n}, is_zk={is_zk}")
    
    if len(data) != expected_bytes:
        print(f"\n⚠️  SIZE MISMATCH!")
        print(f"  Actual Fr count: {len(data) // 32}")
        print(f"  Expected Fr count: {expected_fr}")
        
        # Try to figure out correct config
        for try_zk in [True, False]:
            for try_log in range(4, 30):
                if Proof.expected_fr_count(try_log, try_zk) * 32 == len(data):
                    print(f"\n  Detected config: log_n={try_log}, is_zk={try_zk}")
                    log_n = try_log
                    is_zk = try_zk
                    break
    
    proof = Proof.from_bytes(data, log_n, is_zk)
    
    print(f"\nPairing Point Object (16 Fr values):")
    for i, fr in enumerate(proof.pairing_point_object()[:4]):
        print_hex(f"ppo[{i}]", fr)
    print("  ...")
    
    print(f"\nWitness Commitments (8 G1 points):")
    wire_names = ["W₁", "W₂", "W₃", "lookup_counts", "lookup_tags", "W₄", "lookup_inv", "z_perm"]
    for i, name in enumerate(wire_names[:3]):
        comm = proof.wire_commitment(i)
        print_hex(f"{name} x", comm[:32])
        print_hex(f"{name} y", comm[32:])
    print("  ...")
    
    if is_zk:
        print(f"\nLibra Data (ZK mode):")
        libra_sum = proof.libra_sum()
        if libra_sum:
            print_hex("libra_sum", libra_sum)
    
    print(f"\nSumcheck Univariates (round 0):")
    uni0 = proof.sumcheck_univariate(0)
    for i, coeff in enumerate(uni0[:3]):
        print_hex(f"u[0][{i}]", coeff)
    print(f"  ... ({len(uni0)} coefficients total)")
    
    print(f"\nSumcheck Evaluations:")
    evals = proof.sumcheck_evaluations()
    print(f"  Count: {len(evals)}")
    for i, ev in enumerate(evals[:3]):
        print_hex(f"eval[{i}]", ev)
    print("  ...")
    
    return proof


def validate_sumcheck_round_zero(proof: Proof, is_zk: bool):
    """Validate the first sumcheck round."""
    print("\n" + "="*60)
    print("SUMCHECK VALIDATION (Round 0)")
    print("="*60)
    
    univariate = proof.sumcheck_univariate(0)
    u0 = fr_from_bytes(univariate[0])
    u1 = fr_from_bytes(univariate[1])
    
    sum_u = fr_add(u0, u1)
    
    print(f"\n  u[0][0] = 0x{u0:064x}")
    print(f"  u[0][1] = 0x{u1:064x}")
    print(f"  u[0][0] + u[0][1] = 0x{sum_u:064x}")
    
    if is_zk:
        libra_sum = proof.libra_sum()
        if libra_sum:
            ls = fr_from_bytes(libra_sum)
            print(f"\n  libra_sum = 0x{ls:064x}")
            print(f"\n  For ZK: initial_target = libra_sum × libra_challenge")
            print(f"  We need: u[0][0] + u[0][1] == initial_target")
            
            # Check if sum_u == libra_sum (initial case without challenge)
            if sum_u == ls:
                print(f"\n  ✅ Sum equals libra_sum directly (libra_challenge = 1?)")
            else:
                # Try to compute implied libra_challenge
                if ls != 0:
                    implied_challenge = fr_div(sum_u, ls)
                    print(f"\n  Implied libra_challenge = sum / libra_sum")
                    print(f"                          = 0x{implied_challenge:064x}")
    else:
        if sum_u == 0:
            print(f"\n  ✅ Sum equals 0 (correct for non-ZK)")
        else:
            print(f"\n  ⚠️  Sum is non-zero for non-ZK proof!")


def validate_public_inputs(pi_path: Path, vk: VerificationKey):
    """Validate public inputs file."""
    print("\n" + "="*60)
    print("PUBLIC INPUTS ANALYSIS")
    print("="*60)
    
    data = pi_path.read_bytes()
    print(f"\nFile: {pi_path}")
    print(f"Size: {len(data)} bytes")
    print(f"Expected: {vk.num_public_inputs * 32} bytes ({vk.num_public_inputs} inputs)")
    
    num_inputs = len(data) // 32
    print(f"\nPublic Inputs ({num_inputs}):")
    for i in range(num_inputs):
        pi = data[i*32:(i+1)*32]
        value = int.from_bytes(pi, 'big')
        print(f"  [{i}] = {value} (0x{pi.hex()})")


def main():
    # Find test circuit data
    repo_root = Path(__file__).parent.parent
    
    # Try different possible paths for the test data
    possible_dirs = [
        repo_root / "test-circuits" / "simple_square" / "target" / "keccak" / "proof",
        repo_root / "test-circuits" / "simple_square" / "target" / "keccak",
        repo_root / "test-circuits" / "simple_square" / "target",
    ]
    
    test_dir = None
    for d in possible_dirs:
        if (d / "vk").exists() or (d / "proof").exists():
            test_dir = d
            break
    
    if test_dir is None:
        print(f"Test directory not found. Tried:")
        for d in possible_dirs:
            print(f"  {d}")
        print("\nPlease generate test data first:")
        print("  cd test-circuits/simple_square")
        print("  nargo compile && nargo execute")
        print("  bb prove -b ./target/simple_square.json -w ./target/simple_square.gz --oracle_hash keccak --write_vk -o ./target/keccak")
        sys.exit(1)
    
    vk_path = test_dir / "vk"
    proof_path = test_dir / "proof"
    pi_path = test_dir / "public_inputs"
    
    print(f"\nUsing data from: {test_dir}")
    
    print("="*60)
    print("ULTRAHONK PROOF VALIDATION")
    print("="*60)
    print(f"\nTest Circuit: simple_square (x² = y)")
    print(f"Expected: x=3, y=9")
    
    # Validate VK
    vk = validate_vk_structure(vk_path)
    
    # Validate proof
    proof = validate_proof_structure(proof_path, vk.log2_circuit_size, is_zk=True)
    
    # Validate public inputs
    if pi_path.exists():
        validate_public_inputs(pi_path, vk)
    
    # Validate sumcheck
    validate_sumcheck_round_zero(proof, is_zk=True)
    
    print("\n" + "="*60)
    print("VALIDATION COMPLETE")
    print("="*60)
    print("\nSee docs/theory.md for full theoretical explanation.")


if __name__ == "__main__":
    main()

