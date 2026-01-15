// Cross-module test: operations on types from another module
module test::cross_ops {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;
    use test::cross_types::{GlobalConfig, OperatorCap};

    fun init(ctx: &mut TxContext) {
        let cap = OperatorCap { id: object::new(ctx) };
        sui::transfer::transfer(cap, sui::tx_context::sender(ctx));
    }

    // @expect: mutable-protocol-invariant
    public fun set_protocol_fee(_: &OperatorCap, config: &mut GlobalConfig, fee: u64) {
        config.protocol_fee_bps = fee;  // Cross-module write to invariant!
    }

    // Safe: min_amount is not protocol invariant
    public fun set_min_amount(_: &OperatorCap, config: &mut GlobalConfig, amt: u64) {
        config.min_amount = amt;
    }
}
