// Simple circuit: prove we know x such that x * x == y (public)
fn main(x: Field, y: pub Field) {
    assert(x * x == y);
}

#[test]
fn test_main() {
    // 3 * 3 = 9
    main(3, 9);
}
