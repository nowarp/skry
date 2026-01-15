/// Storage module with TxContext method
/// Pattern from suilend: storage.join_stake(ctx) called via field access
module test::field_method_storage {
    use sui::tx_context::TxContext;

    public struct Storage has store {
        value: u64,
    }

    public fun new(): Storage {
        Storage { value: 0 }
    }

    // Safe: orphan-txcontext - called via self.storage.process_with_ctx() in field_method_caller
    public(package) fun process_with_ctx(_self: &mut Storage, ctx: &mut TxContext): u64 {
        sui::tx_context::epoch(ctx)
    }
}
