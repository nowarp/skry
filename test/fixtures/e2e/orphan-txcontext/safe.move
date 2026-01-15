/// Safe test cases - all public(package) functions are called
module test::orphan_txcontext_safe {
    use sui::tx_context::TxContext;

    public(package) fun helper_one(ctx: &mut TxContext): address {
        sui::tx_context::sender(ctx)
    }

    public entry fun action_one(ctx: &mut TxContext) {
        let _addr = helper_one(ctx);
    }

    /// Uses ctx via method call syntax (ctx.epoch())
    public(package) fun uses_method_call(ctx: &mut TxContext): u64 {
        ctx.epoch()
    }

    /// Uses ctx in struct field initialization
    public(package) fun uses_in_struct_init(ctx: &mut TxContext): u64 {
        let epoch = ctx.epoch();
        epoch
    }

    /// Passes ctx to another function (bag::new pattern)
    public(package) fun passes_ctx_to_other(ctx: &mut TxContext) {
        let _addr = sui::tx_context::sender(ctx);
    }

    public entry fun call_method_user(ctx: &mut TxContext) {
        let _epoch = uses_method_call(ctx);
    }

    public entry fun call_struct_init_user(ctx: &mut TxContext) {
        let _epoch = uses_in_struct_init(ctx);
    }

    public entry fun call_passes_ctx(ctx: &mut TxContext) {
        passes_ctx_to_other(ctx);
    }

    /// Passes ctx as argument to method call on self (self.method(..., ctx))
    public(package) fun passes_ctx_to_method_call(
        self: &mut Storage,
        amount: u64,
        ctx: &mut TxContext
    ): u64 {
        // ctx is passed to helper - should NOT be orphan
        self.helper_with_ctx(amount, ctx)
    }

    /// Helper that uses ctx
    public(package) fun helper_with_ctx(self: &mut Storage, amount: u64, ctx: &mut TxContext): u64 {
        let _sender = sui::tx_context::sender(ctx);
        amount
    }

    public entry fun call_passes_ctx_method(ctx: &mut TxContext) {
        let mut storage = Storage { value: 0 };
        let _result = storage.passes_ctx_to_method_call(100, ctx);
    }

    /// Dummy storage struct for testing
    public struct Storage has drop {
        value: u64,
    }

    /// Object with UID for testing object::new pattern
    public struct MyObject has key {
        id: UID,
    }

    /// Uses ctx via object::new in struct literal - should NOT be orphan
    /// This is a common Sui pattern for creating objects
    public(package) fun creates_object(ctx: &mut TxContext): MyObject {
        MyObject {
            id: sui::object::new(ctx),
        }
    }

    public entry fun call_creates_object(ctx: &mut TxContext) {
        let obj = creates_object(ctx);
        sui::transfer::transfer(obj, sui::tx_context::sender(ctx));
    }
}
