// Fibonacci chain: prove we know initial values (a0, a1) such that
// after 100 iterations, the result equals the public output
// This creates ~200 constraints (2 operations per iteration)

fn main(a0: Field, a1: Field, out: pub Field) {
    let mut prev = a0;
    let mut curr = a1;

    // 100 Fibonacci iterations
    for _ in 0..100 {
        let next = prev + curr;
        prev = curr;
        curr = next;
    }

    assert(curr == out);
}

#[test]
fn test_main() {
    // Standard Fibonacci: 0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, ...
    // After 100 iterations starting from (0, 1), we get fib(101)
    let a0 = 0;
    let a1 = 1;

    // Compute expected output
    let mut prev: Field = a0;
    let mut curr: Field = a1;
    for _ in 0..100 {
        let next = prev + curr;
        prev = curr;
        curr = next;
    }

    main(a0, a1, curr);
}
