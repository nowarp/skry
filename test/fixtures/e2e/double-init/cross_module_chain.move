/// Cross-module IPA chain test: A -> B -> C
/// Tests that transitive calls across module boundaries are detected
///
/// KNOWN ISSUE (PARSER BUG): Multi-module files assign all functions to the
/// last module. This breaks cross-module call graph resolution.
/// backdoor -> passthrough -> do_init chain is not detected because:
/// - backdoor is parsed as test::chain_target::backdoor (wrong!)
/// - The call to test::chain_middle::passthrough doesn't match
module test::chain_entry {
    use sui::tx_context::TxContext;

    /// VULNERABLE: Calls chain_middle which calls chain_target::do_init
    /// BUG: Not detected due to parser multi-module bug
    // @false-negative: double-init
    public entry fun backdoor(ctx: &mut TxContext) {
        test::chain_middle::passthrough(ctx);
    }

    /// SAFE: Doesn't call init chain
    public entry fun safe_action(_ctx: &mut TxContext) {
        // Normal operation
    }
}

module test::chain_middle {
    use sui::tx_context::TxContext;

    /// Intermediate hop - passes through to target
    /// VULNERABLE: Public function callable from other modules
    // @expect: double-init
    public fun passthrough(ctx: &mut TxContext) {
        test::chain_target::do_init(ctx);
    }

    /// Another passthrough - also vulnerable via transitive call
    // @expect: double-init
    public fun another_passthrough(ctx: &mut TxContext) {
        passthrough(ctx);
    }
}

module test::chain_target {
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};

    public struct TargetCap has key {
        id: UID,
    }

    fun init(ctx: &mut TxContext) {
        do_init(ctx);
    }

    /// The actual init implementation - called by init
    public fun do_init(ctx: &mut TxContext) {
        let cap = TargetCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
