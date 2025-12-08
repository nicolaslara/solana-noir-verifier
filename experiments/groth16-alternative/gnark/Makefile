.PHONY: all build run benchmark clean deps

all: build

deps:
	go mod tidy

build: deps
	go build -o groth16-experiment .

run: build
	./groth16-experiment

# Run benchmark with default sizes (100, 1000, 10000 constraints)
benchmark: build
	./groth16-experiment benchmark

# Run benchmark with custom size: make benchmark-N where N is constraint count
benchmark-%: build
	./groth16-experiment benchmark $*

clean:
	rm -rf groth16-experiment output/

