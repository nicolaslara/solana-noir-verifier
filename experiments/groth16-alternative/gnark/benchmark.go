package main

import (
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// ScalableHashChainCircuit creates a circuit with approximately N constraints
// by chaining multiplications (simulating hash-like operations)
type ScalableHashChainCircuit struct {
	// Private input (starting value)
	Start frontend.Variable

	// Public output (final value after N iterations)
	End frontend.Variable `gnark:",public"`

	// Number of iterations (set at compile time)
	Iterations int `gnark:"-"`
}

// Define declares the circuit constraints
func (circuit *ScalableHashChainCircuit) Define(api frontend.API) error {
	// Chain of multiplications: each iteration adds ~1 constraint
	// x_{i+1} = x_i * x_i + x_i (2 constraints per iteration)
	current := circuit.Start

	for i := 0; i < circuit.Iterations; i++ {
		squared := api.Mul(current, current)
		current = api.Add(squared, circuit.Start) // Mix in original value
	}

	// Final constraint: result must equal public output
	api.AssertIsEqual(current, circuit.End)

	return nil
}

// computeExpectedOutput computes the expected output using proper field arithmetic
func computeExpectedOutput(start int64, iterations int) *big.Int {
	// Use gnark's field element type for proper modular arithmetic
	var current, startFr, squared fr.Element
	startFr.SetInt64(start)
	current.Set(&startFr)

	for i := 0; i < iterations; i++ {
		squared.Square(&current)        // squared = current^2
		current.Add(&squared, &startFr) // current = squared + start
	}

	var result big.Int
	current.BigInt(&result)
	return &result
}

func runBenchmark(iterations int) {
	fmt.Printf("\n=== Benchmark: %d iterations ===\n", iterations)

	// Compile circuit
	circuit := ScalableHashChainCircuit{Iterations: iterations}

	startCompile := time.Now()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	compileTime := time.Since(startCompile)

	constraints := cs.GetNbConstraints()
	fmt.Printf("Constraints: %d\n", constraints)
	fmt.Printf("Compile:     %v\n", compileTime)

	// Setup
	startSetup := time.Now()
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}
	setupTime := time.Since(startSetup)
	fmt.Printf("Setup:       %v\n", setupTime)

	// Compute expected output using proper field arithmetic
	startVal := int64(3)
	expectedOutput := computeExpectedOutput(startVal, iterations)

	// Create witness
	assignment := ScalableHashChainCircuit{
		Start:      startVal,
		End:        expectedOutput,
		Iterations: iterations,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	// Prove
	startProve := time.Now()
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		panic(err)
	}
	proveTime := time.Since(startProve)
	fmt.Printf("Prove:       %v\n", proveTime)

	// Verify
	startVerify := time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
	verifyTime := time.Since(startVerify)
	fmt.Printf("Verify:      %v\n", verifyTime)

	// Proof size (cast to BN254 type for MarshalSolidity)
	proofBn254 := proof.(*groth16_bn254.Proof)
	proofBytes := proofBn254.MarshalSolidity()
	fmt.Printf("Proof size:  %d bytes\n", len(proofBytes))

	// Constraints per second
	if proveTime.Seconds() > 0 {
		cps := float64(constraints) / proveTime.Seconds()
		fmt.Printf("Throughput:  %.0f constraints/sec\n", cps)
	}
}

func mainBenchmark() {
	fmt.Println("=== gnark Groth16 Scalability Benchmark ===")
	fmt.Println("Testing different circuit sizes to measure proving time scaling")

	// Default sizes to test
	sizes := []int{100, 1000, 10000, 100000}

	// Check if custom size provided
	if len(os.Args) > 2 {
		customSize, err := strconv.Atoi(os.Args[2])
		if err == nil {
			sizes = []int{customSize}
		}
	}

	for _, size := range sizes {
		runBenchmark(size)
	}

	fmt.Println("\n=== Benchmark Complete ===")
	fmt.Println("Note: Groth16 verification time and proof size remain CONSTANT")
	fmt.Println("regardless of circuit size. Only proving time scales with constraints.")
}
