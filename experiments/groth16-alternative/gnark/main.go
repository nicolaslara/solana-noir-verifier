package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	// Check command line args
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "benchmark":
			mainBenchmark()
			return
		case "circuits":
			runBenchmarks()
			return
		case "help":
			fmt.Println("Usage: go run . [command]")
			fmt.Println("")
			fmt.Println("Commands:")
			fmt.Println("  (none)     Generate proof for SimpleSquare circuit")
			fmt.Println("  benchmark  Run scalability benchmark (100 to 100K constraints)")
			fmt.Println("  circuits   Run circuit benchmarks (MiMC, Range, Merkle, etc.)")
			fmt.Println("  help       Show this help")
			return
		}
	}

	fmt.Println("=== gnark Groth16 Experiment ===")
	fmt.Println()

	// Step 1: Compile the circuit
	fmt.Println("Step 1: Compiling circuit...")
	var circuit SimpleSquareCircuit

	startCompile := time.Now()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	compileTime := time.Since(startCompile)

	fmt.Printf("  Circuit compiled in %v\n", compileTime)
	fmt.Printf("  Number of constraints: %d\n", cs.GetNbConstraints())
	fmt.Printf("  Number of public inputs: %d\n", cs.GetNbPublicVariables()-1) // -1 for constant 1
	fmt.Println()

	// Step 2: Trusted Setup
	fmt.Println("Step 2: Running trusted setup...")
	startSetup := time.Now()
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}
	setupTime := time.Since(startSetup)
	fmt.Printf("  Setup completed in %v\n", setupTime)
	fmt.Println()

	// Step 3: Create witness (x=3, y=9)
	fmt.Println("Step 3: Creating witness...")
	assignment := SimpleSquareCircuit{
		X: 3,
		Y: 9,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	fmt.Println("  Witness created (x=3, y=9)")
	fmt.Println()

	// Step 4: Generate proof
	fmt.Println("Step 4: Generating proof...")
	startProve := time.Now()
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		panic(err)
	}
	proveTime := time.Since(startProve)
	fmt.Printf("  Proof generated in %v\n", proveTime)
	fmt.Println()

	// Step 5: Verify proof
	fmt.Println("Step 5: Verifying proof...")
	startVerify := time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
	verifyTime := time.Since(startVerify)
	fmt.Printf("  Proof verified in %v\n", verifyTime)
	fmt.Println()

	// Step 6: Export for Solana
	fmt.Println("Step 6: Exporting for Solana...")

	// Create output directory
	os.MkdirAll("output", 0755)

	// Cast to concrete BN254 types
	proofBn254 := proof.(*groth16_bn254.Proof)
	vkBn254 := vk.(*groth16_bn254.VerifyingKey)

	// Export proof in format for groth16-solana
	// groth16-solana expects: proof_a (negated) || proof_b || proof_c
	// All in big-endian format
	proofBytes := exportProofForGroth16Solana(proofBn254)
	fmt.Printf("  Proof size: %d bytes\n", len(proofBytes))

	// Write proof
	err = os.WriteFile("output/proof.bin", proofBytes, 0644)
	if err != nil {
		panic(err)
	}
	fmt.Println("  Proof written to output/proof.bin")

	// Write hex-encoded proof for debugging
	proofHex := hex.EncodeToString(proofBytes)
	err = os.WriteFile("output/proof.hex", []byte(proofHex), 0644)
	if err != nil {
		panic(err)
	}

	// Export VK using WriteTo (binary format)
	var vkBuf bytes.Buffer
	_, err = vkBn254.WriteTo(&vkBuf)
	if err != nil {
		panic(err)
	}
	vkBytes := vkBuf.Bytes()
	err = os.WriteFile("output/vk.bin", vkBytes, 0644)
	if err != nil {
		panic(err)
	}
	fmt.Printf("  VK size: %d bytes\n", len(vkBytes))
	fmt.Println("  VK written to output/vk.bin")

	// Export VK components for groth16-solana
	exportVKForSolana(vkBn254)

	// Export public inputs
	// For BN254, field elements are 32 bytes (big-endian)
	publicInputBytes := make([]byte, 32)
	y := big.NewInt(9)
	y.FillBytes(publicInputBytes)
	err = os.WriteFile("output/public.bin", publicInputBytes, 0644)
	if err != nil {
		panic(err)
	}
	fmt.Println("  Public inputs written to output/public.bin")
	fmt.Println()

	// Summary
	fmt.Println("=== Summary ===")
	fmt.Printf("Compile time:    %v\n", compileTime)
	fmt.Printf("Setup time:      %v\n", setupTime)
	fmt.Printf("Proving time:    %v\n", proveTime)
	fmt.Printf("Verification:    %v\n", verifyTime)
	fmt.Printf("Constraints:     %d\n", cs.GetNbConstraints())
	fmt.Printf("Proof size:      %d bytes\n", len(proofBytes))
	fmt.Printf("VK size:         %d bytes\n", len(vkBytes))
}

// exportProofForGroth16Solana exports proof in the exact format groth16-solana expects
// Format: proof_a (64 bytes, G1 negated) || proof_b (128 bytes, G2) || proof_c (64 bytes, G1)
func exportProofForGroth16Solana(proof *groth16_bn254.Proof) []byte {
	result := make([]byte, 256)

	// Negate Ar for the pairing equation: e(-A, B) * e(alpha, beta) * e(vk, gamma) * e(C, delta) = 1
	var arNeg bn254.G1Affine
	arNeg.Neg(&proof.Ar)

	// Write negated Ar (proof_a)
	arBytes := arNeg.RawBytes()
	copy(result[0:64], arBytes[:])

	// Write Bs (proof_b) - G2 point
	bsBytes := proof.Bs.RawBytes()
	copy(result[64:192], bsBytes[:])

	// Write Krs (proof_c) - G1 point
	krsBytes := proof.Krs.RawBytes()
	copy(result[192:256], krsBytes[:])

	fmt.Println()
	fmt.Println("=== Proof Components ===")
	fmt.Printf("Ar (negated, G1): %s\n", hex.EncodeToString(arBytes[:]))
	fmt.Printf("Bs (G2):          %s\n", hex.EncodeToString(bsBytes[:]))
	fmt.Printf("Krs (G1):         %s\n", hex.EncodeToString(krsBytes[:]))

	return result
}

// exportVKForSolana exports VK components in the format needed by groth16-solana
func exportVKForSolana(vk *groth16_bn254.VerifyingKey) {
	fmt.Println()
	fmt.Println("=== VK Components for groth16-solana ===")

	// Export each G1/G2 point as hex
	// Alpha (G1)
	alphaBytes := vk.G1.Alpha.RawBytes()
	fmt.Printf("Alpha G1 (%d bytes): %s\n", len(alphaBytes), hex.EncodeToString(alphaBytes[:]))

	// Beta (G2)
	betaBytes := vk.G2.Beta.RawBytes()
	fmt.Printf("Beta G2 (%d bytes): %s\n", len(betaBytes), hex.EncodeToString(betaBytes[:]))

	// Gamma (G2)
	gammaBytes := vk.G2.Gamma.RawBytes()
	fmt.Printf("Gamma G2 (%d bytes): %s\n", len(gammaBytes), hex.EncodeToString(gammaBytes[:]))

	// Delta (G2)
	deltaBytes := vk.G2.Delta.RawBytes()
	fmt.Printf("Delta G2 (%d bytes): %s\n", len(deltaBytes), hex.EncodeToString(deltaBytes[:]))

	// IC (array of G1 points)
	fmt.Printf("IC (G1 array, %d points):\n", len(vk.G1.K))
	for i, ic := range vk.G1.K {
		icBytes := ic.RawBytes()
		fmt.Printf("  IC[%d] (%d bytes): %s\n", i, len(icBytes), hex.EncodeToString(icBytes[:]))
	}

	// Write binary VK for easy Rust parsing
	writeBinaryVK(vk)

	// Write Rust code for VK (for reference)
	writeRustVK(vk)
}

// writeBinaryVK writes the VK in a binary format for easy parsing in Rust
// Layout: Alpha(64) + Beta(128) + Gamma(128) + Delta(128) + IC[0](64) + IC[1](64) = 576 bytes
func writeBinaryVK(vk *groth16_bn254.VerifyingKey) {
	var buf bytes.Buffer

	// Alpha G1 (64 bytes)
	alphaBytes := vk.G1.Alpha.RawBytes()
	buf.Write(alphaBytes[:])

	// Beta G2 (128 bytes)
	betaBytes := vk.G2.Beta.RawBytes()
	buf.Write(betaBytes[:])

	// Gamma G2 (128 bytes)
	gammaBytes := vk.G2.Gamma.RawBytes()
	buf.Write(gammaBytes[:])

	// Delta G2 (128 bytes)
	deltaBytes := vk.G2.Delta.RawBytes()
	buf.Write(deltaBytes[:])

	// IC points (64 bytes each)
	for _, ic := range vk.G1.K {
		icBytes := ic.RawBytes()
		buf.Write(icBytes[:])
	}

	err := os.WriteFile("output/vk_solana.bin", buf.Bytes(), 0644)
	if err != nil {
		fmt.Printf("Warning: Could not write binary VK: %v\n", err)
		return
	}
	fmt.Printf("  Binary VK written to output/vk_solana.bin (%d bytes)\n", buf.Len())
}

// writeRustVK generates Rust code for the VK that can be used with groth16-solana
func writeRustVK(vk *groth16_bn254.VerifyingKey) {
	f, err := os.Create("output/vk_rust.rs")
	if err != nil {
		fmt.Printf("Warning: Could not write Rust VK: %v\n", err)
		return
	}
	defer f.Close()

	fmt.Fprintln(f, "// Generated verification key for groth16-solana")
	fmt.Fprintln(f, "// Circuit: SimpleSquare (x * x == y)")
	fmt.Fprintln(f, "")
	fmt.Fprintf(f, "pub const VERIFYING_KEY: Groth16Verifyingkey<%d> = Groth16Verifyingkey {\n", len(vk.G1.K)-1)
	fmt.Fprintf(f, "    nr_pubinputs: %d,\n", len(vk.G1.K)-1)
	fmt.Fprintln(f, "")

	// Alpha G1
	alphaBytes := vk.G1.Alpha.RawBytes()
	fmt.Fprintln(f, "    // α ∈ G1")
	fmt.Fprintln(f, "    vk_alpha_g1: [")
	writeByteArray(f, alphaBytes[:], "        ")
	fmt.Fprintln(f, "    ],")
	fmt.Fprintln(f, "")

	// Beta G2
	betaBytes := vk.G2.Beta.RawBytes()
	fmt.Fprintln(f, "    // β ∈ G2")
	fmt.Fprintln(f, "    vk_beta_g2: [")
	writeByteArray(f, betaBytes[:], "        ")
	fmt.Fprintln(f, "    ],")
	fmt.Fprintln(f, "")

	// Gamma G2 (note the typo in groth16-solana)
	gammaBytes := vk.G2.Gamma.RawBytes()
	fmt.Fprintln(f, "    // γ ∈ G2 (note: groth16-solana has typo 'gamme')")
	fmt.Fprintln(f, "    vk_gamme_g2: [")
	writeByteArray(f, gammaBytes[:], "        ")
	fmt.Fprintln(f, "    ],")
	fmt.Fprintln(f, "")

	// Delta G2
	deltaBytes := vk.G2.Delta.RawBytes()
	fmt.Fprintln(f, "    // δ ∈ G2")
	fmt.Fprintln(f, "    vk_delta_g2: [")
	writeByteArray(f, deltaBytes[:], "        ")
	fmt.Fprintln(f, "    ],")
	fmt.Fprintln(f, "")

	// IC
	fmt.Fprintln(f, "    // IC ∈ G1[]")
	fmt.Fprintln(f, "    vk_ic: [")
	for i, ic := range vk.G1.K {
		icBytes := ic.RawBytes()
		fmt.Fprintf(f, "        // IC[%d]\n", i)
		fmt.Fprintln(f, "        [")
		writeByteArray(f, icBytes[:], "            ")
		fmt.Fprintln(f, "        ],")
	}
	fmt.Fprintln(f, "    ],")
	fmt.Fprintln(f, "};")

	fmt.Println("  Rust VK written to output/vk_rust.rs")
}

func writeByteArray(f *os.File, data []byte, indent string) {
	for i := 0; i < len(data); i += 8 {
		end := i + 8
		if end > len(data) {
			end = len(data)
		}
		fmt.Fprint(f, indent)
		for j := i; j < end; j++ {
			fmt.Fprintf(f, "0x%02x, ", data[j])
		}
		fmt.Fprintln(f)
	}
}
