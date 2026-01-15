/// Cross-module test: wrapper that returns cap from another module
module test::wrapper_module {
    use sui::tx_context::TxContext;
    use test::cap_module::{Self, AdminCap};

    /// VULNERABLE: Returns privileged type from another module
    // @expect: test-only-missing
    public fun get_admin_cap(ctx: &mut TxContext): AdminCap {
        cap_module::create(ctx)
    }
}
