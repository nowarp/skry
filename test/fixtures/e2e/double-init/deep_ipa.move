/// Deep IPA test: init -> level1 -> level2 -> level3 (actual sink)
/// Tests that multi-hop transitive calls are detected
///
/// KNOWN ISSUE: Only level3 is marked as InitImpl (has sink).
/// level1 and level2 are NOT InitImpl, so callers of them are not detected.
/// Also, level2 (private) gets falsely flagged.
module test::deep_ipa {
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};

    public struct DeepCap has key {
        id: UID,
    }

    fun init(ctx: &mut TxContext) {
        level1(ctx);
    }

    fun level1(ctx: &mut TxContext) {
        level2(ctx);
    }

    /// SAFE: Private function (not externally callable)
    fun level2(ctx: &mut TxContext) {
        level3(ctx);
    }

    fun level3(ctx: &mut TxContext) {
        // The actual sink - creates and transfers cap
        let cap = DeepCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// VULNERABLE: Calls level1 which transitively reaches level3
    // @expect: double-init
    public entry fun exploit_level1(ctx: &mut TxContext) {
        level1(ctx);
    }

    /// VULNERABLE: Calls level2 which transitively reaches level3
    // @expect: double-init
    public entry fun exploit_level2(ctx: &mut TxContext) {
        level2(ctx);
    }

    /// VULNERABLE: Calls level3 directly - THIS ONE WORKS
    // @expect: double-init
    public entry fun exploit_level3(ctx: &mut TxContext) {
        level3(ctx);
    }

    /// SAFE: Doesn't call any init chain function
    public entry fun safe_action(_ctx: &mut TxContext) {
        // Normal operation
    }
}
