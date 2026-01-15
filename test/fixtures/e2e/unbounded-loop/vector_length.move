/// Test: vector::length as loop bound
module test::unbounded_loop_vector {
    use std::vector;
    use sui::tx_context::TxContext;

    /// VULNERABLE: Loop bound from vector::length of tainted vector
    // @expect: unbounded-loop
    public entry fun process_vector(items: vector<u64>, ctx: &mut TxContext) {
        let mut i = 0;
        let len = vector::length(&items);
        while (i < len) {
            i = i + 1;
        };
    }

    /// VULNERABLE: Direct vector::length in condition
    // @expect: unbounded-loop
    public entry fun process_vector_direct(items: vector<u64>, ctx: &mut TxContext) {
        let mut i = 0;
        while (i < vector::length(&items)) {
            i = i + 1;
        };
    }

    /// SAFE: Vector from on-chain state, not user input
    public entry fun process_state_vector(state: &State, ctx: &mut TxContext) {
        let mut i = 0;
        while (i < vector::length(&state.items)) {
            i = i + 1;
        };
    }

    public struct State has key {
        id: UID,
        items: vector<u64>,
    }
}
