/// Caller module that invokes storage method via field access
/// Pattern: self.storage.process_with_ctx(ctx) - parser misses this call
module test::field_method_caller {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;
    use test::field_method_storage::{Self, Storage};

    public struct Container has key {
        id: UID,
        storage: Storage,
    }

    fun init(ctx: &mut TxContext) {
        let container = Container {
            id: object::new(ctx),
            storage: field_method_storage::new(),
        };
        sui::transfer::share_object(container);
    }

    /// Calls storage.process_with_ctx(ctx) via field access
    /// Parser should detect this as a call to field_method_storage::process_with_ctx
    public entry fun do_process(self: &mut Container, ctx: &mut TxContext) {
        let _epoch = self.storage.process_with_ctx(ctx);
    }
}
