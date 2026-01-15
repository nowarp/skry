/// Transitive exposure test: public -> private wrapper -> init helper
/// Tests that exposure through non-public wrappers is detected
///
/// KNOWN ISSUE: Rule only detects direct callers of InitImpl.
/// Private wrappers get flagged, but public entry points calling them don't.
module test::transitive_pub {
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};

    public struct Cap has key {
        id: UID,
    }

    fun init(ctx: &mut TxContext) {
        do_init(ctx);
    }

    fun do_init(ctx: &mut TxContext) {
        let cap = Cap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// Internal wrapper - not directly entry
    /// SAFE: Private function (not externally callable)
    fun internal_wrapper(ctx: &mut TxContext) {
        do_init(ctx);
    }

    /// VULNERABLE: Exposes init through internal_wrapper
    // @expect: double-init
    public entry fun exposed(ctx: &mut TxContext) {
        internal_wrapper(ctx);
    }

    /// Another wrapper layer
    fun deep_wrapper(ctx: &mut TxContext) {
        internal_wrapper(ctx);
    }

    /// VULNERABLE: Even deeper exposure
    // @expect: double-init
    public entry fun deep_exposed(ctx: &mut TxContext) {
        deep_wrapper(ctx);
    }

    /// SAFE: Private function calling init (not entry point)
    fun hidden(ctx: &mut TxContext) {
        internal_wrapper(ctx);
    }

    /// SAFE: Doesn't call init chain
    public entry fun safe_action(_ctx: &mut TxContext) {
        // Normal
    }
}
