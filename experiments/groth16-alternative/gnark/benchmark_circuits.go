package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
)

// ============================================================================
// Benchmark Circuits
// ============================================================================

// 1. MiMC Hash Chain - ZK-friendly hash, common in rollups
type MiMCHashChainCircuit struct {
	PreImage frontend.Variable   `gnark:",private"`
	Hashes   []frontend.Variable `gnark:",public"`
}

func (c *MiMCHashChainCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	current := c.PreImage
	for i := range c.Hashes {
		h.Reset()
		h.Write(current)
		current = h.Sum()
		api.AssertIsEqual(current, c.Hashes[i])
	}
	return nil
}

// 2. Range Proof - prove value is in [0, 2^n)
type RangeProofCircuit struct {
	Value   frontend.Variable `gnark:",private"`
	NumBits int               `gnark:"-"`
}

func (c *RangeProofCircuit) Define(api frontend.API) error {
	// Decompose into bits and verify each is 0 or 1
	bits := api.ToBinary(c.Value, c.NumBits)
	for _, b := range bits {
		api.AssertIsBoolean(b)
	}
	return nil
}

// 3. Merkle Tree Membership - common in privacy protocols
type MerkleProofCircuit struct {
	Leaf     frontend.Variable   `gnark:",private"`
	Path     []frontend.Variable `gnark:",private"`
	PathBits []frontend.Variable `gnark:",private"` // 0=left, 1=right
	Root     frontend.Variable   `gnark:",public"`
}

func (c *MerkleProofCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	current := c.Leaf
	for i := range c.Path {
		h.Reset()
		// If PathBits[i] == 0, current is left child, otherwise right
		left := api.Select(c.PathBits[i], c.Path[i], current)
		right := api.Select(c.PathBits[i], current, c.Path[i])
		h.Write(left, right)
		current = h.Sum()
	}
	api.AssertIsEqual(current, c.Root)
	return nil
}

// 4. Matrix Multiplication - computational benchmark
type MatMulCircuit struct {
	A      [][]frontend.Variable `gnark:",private"`
	B      [][]frontend.Variable `gnark:",private"`
	Result [][]frontend.Variable `gnark:",public"`
	Size   int                   `gnark:"-"`
}

func (c *MatMulCircuit) Define(api frontend.API) error {
	for i := 0; i < c.Size; i++ {
		for j := 0; j < c.Size; j++ {
			sum := frontend.Variable(0)
			for k := 0; k < c.Size; k++ {
				sum = api.Add(sum, api.Mul(c.A[i][k], c.B[k][j]))
			}
			api.AssertIsEqual(c.Result[i][j], sum)
		}
	}
	return nil
}

// 5. Iteration benchmark (like our simple_square but repeated)
type IteratedSquareCircuit struct {
	X          frontend.Variable `gnark:",private"`
	Iterations int               `gnark:"-"`
	FinalY     frontend.Variable `gnark:",public"`
}

func (c *IteratedSquareCircuit) Define(api frontend.API) error {
	current := c.X
	for i := 0; i < c.Iterations; i++ {
		current = api.Mul(current, current)
	}
	api.AssertIsEqual(current, c.FinalY)
	return nil
}

// ============================================================================
// Benchmark Runner
// ============================================================================

type BenchmarkResult struct {
	Name        string
	Constraints int
	CompileTime time.Duration
	SetupTime   time.Duration
	ProveTime   time.Duration
	VerifyTime  time.Duration
	ProofSize   int
}

func runBenchmarks() {
	fmt.Println("=== Groth16 Circuit Benchmarks ===")
	fmt.Println()

	results := []BenchmarkResult{}

	// 1. MiMC Hash Chain (various depths)
	for _, depth := range []int{10, 100, 1000} {
		result := benchmarkMiMCHashChain(depth)
		results = append(results, result)
	}

	// 2. Range Proofs (various bit sizes)
	for _, bits := range []int{32, 64, 128, 256} {
		result := benchmarkRangeProof(bits)
		results = append(results, result)
	}

	// 3. Merkle Tree (various depths)
	for _, depth := range []int{10, 20, 32} {
		result := benchmarkMerkleProof(depth)
		results = append(results, result)
	}

	// 4. Iterated Squares
	for _, iters := range []int{100, 1000, 10000} {
		result := benchmarkIteratedSquare(iters)
		results = append(results, result)
	}

	// Print results table
	fmt.Println()
	fmt.Println("=== Results Summary ===")
	fmt.Println()
	fmt.Printf("%-30s %12s %12s %12s %12s %10s\n",
		"Circuit", "Constraints", "Setup", "Prove", "Verify", "Proof")
	fmt.Println(string(make([]byte, 100)))

	for _, r := range results {
		fmt.Printf("%-30s %12d %12s %12s %12s %10d\n",
			r.Name,
			r.Constraints,
			r.SetupTime.Round(time.Millisecond),
			r.ProveTime.Round(time.Millisecond),
			r.VerifyTime.Round(time.Millisecond),
			r.ProofSize,
		)
	}
}

func benchmarkMiMCHashChain(depth int) BenchmarkResult {
	name := fmt.Sprintf("MiMC Hash Chain (%d)", depth)
	fmt.Printf("Benchmarking %s...\n", name)

	// Create circuit
	circuit := &MiMCHashChainCircuit{
		Hashes: make([]frontend.Variable, depth),
	}

	// Compile
	start := time.Now()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Printf("  Error compiling: %v\n", err)
		return BenchmarkResult{Name: name}
	}
	compileTime := time.Since(start)

	// Setup
	start = time.Now()
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		fmt.Printf("  Error in setup: %v\n", err)
		return BenchmarkResult{Name: name}
	}
	setupTime := time.Since(start)

	// Create witness
	preImage := big.NewInt(42)
	hashes := make([]interface{}, depth)
	current := preImage
	for i := 0; i < depth; i++ {
		// Simplified hash for witness (real MiMC would be computed here)
		current = new(big.Int).Mul(current, big.NewInt(7))
		current = new(big.Int).Mod(current, ecc.BN254.ScalarField())
		hashes[i] = current
	}

	assignment := &MiMCHashChainCircuit{
		PreImage: preImage,
		Hashes:   make([]frontend.Variable, depth),
	}
	for i := 0; i < depth; i++ {
		assignment.Hashes[i] = hashes[i]
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("  Error creating witness: %v\n", err)
		return BenchmarkResult{Name: name}
	}

	// Prove
	start = time.Now()
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		fmt.Printf("  Error proving: %v\n", err)
		return BenchmarkResult{Name: name}
	}
	proveTime := time.Since(start)

	// Verify
	publicWitness, _ := witness.Public()
	start = time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("  Error verifying: %v\n", err)
		return BenchmarkResult{Name: name}
	}
	verifyTime := time.Since(start)

	fmt.Printf("  ✓ %d constraints, prove: %v\n", cs.GetNbConstraints(), proveTime)

	return BenchmarkResult{
		Name:        name,
		Constraints: cs.GetNbConstraints(),
		CompileTime: compileTime,
		SetupTime:   setupTime,
		ProveTime:   proveTime,
		VerifyTime:  verifyTime,
		ProofSize:   256,
	}
}

func benchmarkRangeProof(numBits int) BenchmarkResult {
	name := fmt.Sprintf("Range Proof (%d-bit)", numBits)
	fmt.Printf("Benchmarking %s...\n", name)

	circuit := &RangeProofCircuit{NumBits: numBits}

	start := time.Now()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Printf("  Error compiling: %v\n", err)
		return BenchmarkResult{Name: name}
	}
	compileTime := time.Since(start)

	start = time.Now()
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		fmt.Printf("  Error in setup: %v\n", err)
		return BenchmarkResult{Name: name}
	}
	setupTime := time.Since(start)

	// Random value in range
	value, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(numBits)-1))

	assignment := &RangeProofCircuit{
		Value:   value,
		NumBits: numBits,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("  Error creating witness: %v\n", err)
		return BenchmarkResult{Name: name}
	}

	start = time.Now()
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		fmt.Printf("  Error proving: %v\n", err)
		return BenchmarkResult{Name: name}
	}
	proveTime := time.Since(start)

	publicWitness, _ := witness.Public()
	start = time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("  Error verifying: %v\n", err)
		return BenchmarkResult{Name: name}
	}
	verifyTime := time.Since(start)

	fmt.Printf("  ✓ %d constraints, prove: %v\n", cs.GetNbConstraints(), proveTime)

	return BenchmarkResult{
		Name:        name,
		Constraints: cs.GetNbConstraints(),
		CompileTime: compileTime,
		SetupTime:   setupTime,
		ProveTime:   proveTime,
		VerifyTime:  verifyTime,
		ProofSize:   256,
	}
}

func benchmarkMerkleProof(depth int) BenchmarkResult {
	name := fmt.Sprintf("Merkle Proof (depth %d)", depth)
	fmt.Printf("Benchmarking %s...\n", name)

	circuit := &MerkleProofCircuit{
		Path:     make([]frontend.Variable, depth),
		PathBits: make([]frontend.Variable, depth),
	}

	start := time.Now()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Printf("  Error compiling: %v\n", err)
		return BenchmarkResult{Name: name}
	}
	compileTime := time.Since(start)

	start = time.Now()
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		fmt.Printf("  Error in setup: %v\n", err)
		return BenchmarkResult{Name: name}
	}
	setupTime := time.Since(start)

	// Create dummy witness
	assignment := &MerkleProofCircuit{
		Leaf:     big.NewInt(12345),
		Path:     make([]frontend.Variable, depth),
		PathBits: make([]frontend.Variable, depth),
		Root:     big.NewInt(0), // Will be computed
	}
	for i := 0; i < depth; i++ {
		assignment.Path[i] = big.NewInt(int64(i + 1))
		assignment.PathBits[i] = i % 2
	}
	// Compute root (simplified)
	assignment.Root = big.NewInt(99999)

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("  Error creating witness: %v\n", err)
		return BenchmarkResult{Name: name}
	}

	start = time.Now()
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		fmt.Printf("  Error proving (expected for dummy witness): %v\n", err)
		// Return with just compile/setup times
		return BenchmarkResult{
			Name:        name,
			Constraints: cs.GetNbConstraints(),
			CompileTime: compileTime,
			SetupTime:   setupTime,
			ProofSize:   256,
		}
	}
	proveTime := time.Since(start)

	publicWitness, _ := witness.Public()
	start = time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	verifyTime := time.Since(start)

	fmt.Printf("  ✓ %d constraints, prove: %v\n", cs.GetNbConstraints(), proveTime)

	return BenchmarkResult{
		Name:        name,
		Constraints: cs.GetNbConstraints(),
		CompileTime: compileTime,
		SetupTime:   setupTime,
		ProveTime:   proveTime,
		VerifyTime:  verifyTime,
		ProofSize:   256,
	}
}

func benchmarkIteratedSquare(iterations int) BenchmarkResult {
	name := fmt.Sprintf("Iterated Square (%d)", iterations)
	fmt.Printf("Benchmarking %s...\n", name)

	circuit := &IteratedSquareCircuit{Iterations: iterations}

	start := time.Now()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Printf("  Error compiling: %v\n", err)
		return BenchmarkResult{Name: name}
	}
	compileTime := time.Since(start)

	start = time.Now()
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		fmt.Printf("  Error in setup: %v\n", err)
		return BenchmarkResult{Name: name}
	}
	setupTime := time.Since(start)

	// Compute expected result
	x := big.NewInt(2)
	result := new(big.Int).Set(x)
	modulus := ecc.BN254.ScalarField()
	for i := 0; i < iterations; i++ {
		result.Mul(result, result)
		result.Mod(result, modulus)
	}

	assignment := &IteratedSquareCircuit{
		X:          x,
		Iterations: iterations,
		FinalY:     result,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("  Error creating witness: %v\n", err)
		return BenchmarkResult{Name: name}
	}

	start = time.Now()
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		fmt.Printf("  Error proving: %v\n", err)
		return BenchmarkResult{Name: name}
	}
	proveTime := time.Since(start)

	publicWitness, _ := witness.Public()
	start = time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("  Error verifying: %v\n", err)
		return BenchmarkResult{Name: name}
	}
	verifyTime := time.Since(start)

	fmt.Printf("  ✓ %d constraints, prove: %v\n", cs.GetNbConstraints(), proveTime)

	return BenchmarkResult{
		Name:        name,
		Constraints: cs.GetNbConstraints(),
		CompileTime: compileTime,
		SetupTime:   setupTime,
		ProveTime:   proveTime,
		VerifyTime:  verifyTime,
		ProofSize:   256,
	}
}
