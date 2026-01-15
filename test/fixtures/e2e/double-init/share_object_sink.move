/// SharesObject sink test
/// Tests that init helpers using share_object are detected
module test::share_sink {
    use sui::tx_context::TxContext;
    use sui::transfer;
    use sui::object::{Self, UID};

    public struct GlobalState has key {
        id: UID,
        value: u64,
    }

    fun init(ctx: &mut TxContext) {
        setup_global(ctx);
    }

    fun setup_global(ctx: &mut TxContext) {
        let state = GlobalState {
            id: object::new(ctx),
            value: 0
        };
        transfer::share_object(state);  // SharesObject sink
    }

    /// VULNERABLE: Creates duplicate shared object
    // @expect: double-init
    public entry fun reset_global(ctx: &mut TxContext) {
        setup_global(ctx);
    }

    /// SAFE: Doesn't call setup_global
    public entry fun update_state(_ctx: &mut TxContext) {
        // Would modify existing state, not create new
    }
}
