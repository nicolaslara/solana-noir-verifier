// Iterated squaring circuit: prove we know x such that x^(2^10000) == y (mod p)
// This creates ~10000 constraints (one multiplication per iteration)
// This is a middle ground between 1k and 100k

fn main(x: Field, y: pub Field) {
    let mut current = x;
    // 10000 iterations of squaring
    for _ in 0..10000 {
        current = current * current;
    }
    assert(current == y);
}

#[test]
fn test_main() {
    let x = 2;
    let mut expected: Field = x;
    for _ in 0..100 {
        expected = expected * expected;
    }
    // This is a shorter test; full proof uses 10k iterations
}
