/// BUG TEST: Type resolution - Module C (defines PrivCap)
module test::priv_reexport_c {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    public struct PrivCap has key, store {
        id: UID,
    }

    // @expect: privilege-escalation
    public fun create(ctx: &mut TxContext): PrivCap {
        PrivCap { id: object::new(ctx) }
    }
}
