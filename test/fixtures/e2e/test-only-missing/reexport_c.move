/// Re-export test - Module C (defines ReexportCap)
module test::reexport_c {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    public struct ReexportCap has key, store {
        id: UID,
    }

    // @expect: test-only-missing
    public fun create(ctx: &mut TxContext): ReexportCap {
        ReexportCap { id: object::new(ctx) }
    }
}
