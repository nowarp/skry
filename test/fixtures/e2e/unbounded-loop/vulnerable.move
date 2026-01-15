/// Test cases for unbounded-loop rule.
/// Loop bound controlled by user input - potential DoS via gas exhaustion
module test::unbounded_loop {
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::vec_map::{Self, VecMap};

    public struct State has key {
        id: UID,
        data: VecMap<u64, u64>,
    }

    /// VULNERABLE: Loop bound from user input
    // @expect: unbounded-loop
    public entry fun process_items(count: u64, ctx: &mut TxContext) {
        let mut i = 0;
        while (i < count) {  // count is tainted - attacker can exhaust gas
            i = i + 1;
        };
    }

    /// VULNERABLE: For loop with tainted bound
    // @expect: unbounded-loop
    public entry fun process_batch(iterations: u64, state: &mut State) {
        let mut i = 0;
        while (i < iterations) {  // iterations from user
            vec_map::insert(&mut state.data, i, i * 2);
            i = i + 1;
        };
    }

    /// VULNERABLE: Nested loops with tainted outer bound
    // @expect: unbounded-loop
    public entry fun process_nested(outer: u64, ctx: &mut TxContext) {
        let mut i = 0;
        while (i < outer) {  // outer is tainted
            let mut j = 0;
            while (j < 100) {  // inner is bounded, but outer multiplies it
                j = j + 1;
            };
            i = i + 1;
        };
    }

    /// SAFE: Loop bound is constant
    public entry fun process_fixed(ctx: &mut TxContext) {
        let mut i = 0;
        while (i < 100) {
            i = i + 1;
        };
    }

    /// SAFE: Loop bound is validated
    public entry fun process_validated(count: u64, ctx: &mut TxContext) {
        assert!(count <= 1000, 0);  // Validation sanitizes
        let mut i = 0;
        while (i < count) {
            i = i + 1;
        };
    }

    /// SAFE: Loop bound from struct field (not user input)
    public entry fun process_from_state(state: &State) {
        let size = vec_map::size(&state.data);
        let mut i = 0;
        while (i < size) {
            i = i + 1;
        };
    }
}
