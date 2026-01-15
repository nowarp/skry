/// FQN conflict test: module_b with transferred AdminCap (safe)
module test::module_b {
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    /// AdminCap (same simple name as module_a::AdminCap)
    public struct AdminCap has key {
        id: UID,
    }

    /// SAFE: Properly transfers AdminCap to sender
    fun init(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));  // Correct
    }
}
