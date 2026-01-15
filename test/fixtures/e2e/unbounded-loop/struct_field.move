/// Test: struct field as loop bound
module test::unbounded_loop_struct {
    use sui::tx_context::TxContext;
    use sui::object::UID;

    public struct Request has drop {
        count: u64,
        data: u64,
    }

    /// VULNERABLE: Loop bound from field of tainted struct
    // @expect: unbounded-loop
    public entry fun process_struct_field(count: u64, data: u64, ctx: &mut TxContext) {
        let req = Request { count, data };
        let mut i = 0;
        while (i < req.count) {
            i = i + 1;
        };
    }

    /// VULNERABLE: Extracted field still tainted
    // @expect: unbounded-loop
    public entry fun process_extracted_field(count: u64, data: u64, ctx: &mut TxContext) {
        let req = Request { count, data };
        let bound = req.count;
        let mut i = 0;
        while (i < bound) {
            i = i + 1;
        };
    }

    /// SAFE: Field from on-chain state
    public entry fun process_state_field(state: &Config, ctx: &mut TxContext) {
        let mut i = 0;
        while (i < state.max_iterations) {
            i = i + 1;
        };
    }

    public struct Config has key {
        id: UID,
        max_iterations: u64,
    }
}
