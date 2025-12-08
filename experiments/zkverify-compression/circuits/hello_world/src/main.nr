// Simple circuit: prove knowledge of x such that x * x == y
// This matches our gnark SimpleSquare for easy comparison

fn main(x: Field, y: pub Field) {
    assert(x * x == y);
}

#[test]
fn test_main() {
    main(3, 9);
}
