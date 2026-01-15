module test::hop_c {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// AdminCap defined here to avoid circular dependency
    public struct AdminCap has key, store { id: UID }

    fun init(ctx: &mut TxContext) {
        transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
    }

    /// Final sink - does the actual transfer
    // @expect: single-step-ownership
    public fun sink(cap: AdminCap, addr: address) {
        transfer::transfer(cap, addr);
    }
}
