// Test case: Multiple protocol invariant violations in one module
module test::multi_violation {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    public struct Exchange has key {
        id: UID,
        base_decimals: u8,   // Protocol invariant
        quote_decimals: u8,  // Protocol invariant
        fee_rate: u64,       // NOT invariant - can be changed
    }

    public struct AdminCap has key, store { id: UID }

    fun init(ctx: &mut TxContext) {
        let exchange = Exchange {
            id: object::new(ctx),
            base_decimals: 9,
            quote_decimals: 6,
            fee_rate: 30,
        };
        sui::transfer::share_object(exchange);

        let admin = AdminCap { id: object::new(ctx) };
        sui::transfer::transfer(admin, sui::tx_context::sender(ctx));
    }

    // @expect: mutable-protocol-invariant
    public fun set_base_decimals(_: &AdminCap, ex: &mut Exchange, d: u8) {
        ex.base_decimals = d;
    }

    // @expect: mutable-protocol-invariant
    public fun set_quote_decimals(_: &AdminCap, ex: &mut Exchange, d: u8) {
        ex.quote_decimals = d;
    }

    // Safe: fee_rate is not protocol invariant
    public fun set_fee_rate(_: &AdminCap, ex: &mut Exchange, rate: u64) {
        ex.fee_rate = rate;
    }
}
