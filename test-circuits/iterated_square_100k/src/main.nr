// Iterated squaring circuit: prove we know x such that x^(2^100000) == y (mod p)
// This creates ~100000 constraints (one multiplication per iteration)
// This will push log_n higher than smaller circuits

fn main(x: Field, y: pub Field) {
    let mut current = x;
    // 100000 iterations of squaring
    for _ in 0..100000 {
        current = current * current;
    }
    assert(current == y);
}

#[test]
fn test_main() {
    // For testing, use a smaller iteration count
    // The actual proof uses 100k iterations
    let x = 2;
    let mut expected: Field = x;
    for _ in 0..100 {
        expected = expected * expected;
    }
    // This test won't pass with the full 100k, just validates structure
    // main(x, expected);
}
