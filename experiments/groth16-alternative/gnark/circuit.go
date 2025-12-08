package main

import (
	"github.com/consensys/gnark/frontend"
)

// SimpleSquareCircuit proves knowledge of x such that x * x == y
// This is equivalent to the Noir circuit in test-circuits/simple_square
type SimpleSquareCircuit struct {
	// Private input (witness)
	X frontend.Variable

	// Public input
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
func (circuit *SimpleSquareCircuit) Define(api frontend.API) error {
	// Compute x * x
	xSquared := api.Mul(circuit.X, circuit.X)

	// Assert x * x == y
	api.AssertIsEqual(xSquared, circuit.Y)

	return nil
}
