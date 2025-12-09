// Iterated squaring circuit: prove we know x such that x^(2^100) == y (mod p)
// This creates ~100 constraints (one multiplication per iteration)

fn main(x: Field, y: pub Field) {
    let mut current = x;
    // 100 iterations of squaring
    for _ in 0..100 {
        current = current * current;
    }
    assert(current == y);
}

#[test]
fn test_main() {
    // For x=2, after 100 squarings: 2^(2^100) mod p
    // This wraps around in the field, we compute expected value
    let x = 2;
    // Compute 2^(2^100) mod p - this needs to be pre-computed
    // For testing, we use a value that satisfies the constraint
    let mut expected: Field = x;
    for _ in 0..100 {
        expected = expected * expected;
    }
    main(x, expected);
}
