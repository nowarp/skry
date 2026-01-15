/// Safe test cases - no double init
module test::double_init_safe {
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};

    public struct AdminCap has key {
        id: UID,
    }

    fun init(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// Safe: Normal entry functions don't call init
    public entry fun do_action(ctx: &mut TxContext) {
        // Normal operation
    }

    public entry fun another_action(ctx: &mut TxContext) {
        // Another operation
    }

    fun helper(ctx: &mut TxContext) {
        // Helper function
    }
}
