// Iterated squaring circuit: prove we know x such that x^(2^1000) == y (mod p)
// This creates ~1000 constraints (one multiplication per iteration)

fn main(x: Field, y: pub Field) {
    let mut current = x;
    // 1000 iterations of squaring
    for _ in 0..1000 {
        current = current * current;
    }
    assert(current == y);
}

#[test]
fn test_main() {
    let x = 2;
    let mut expected: Field = x;
    for _ in 0..1000 {
        expected = expected * expected;
    }
    main(x, expected);
}
