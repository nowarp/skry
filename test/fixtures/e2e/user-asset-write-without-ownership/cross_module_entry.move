/// Cross-module entry point for user asset write tests.
module test::cross_module_entry {
    use sui::tx_context::TxContext;
    use test::cross_module_helper;

    /// VULNERABLE: Cross-module write without ownership check
    // @expect: user-asset-write-without-ownership
    public entry fun modify_cross_module(
        vault: &mut cross_module_helper::UserVault,
        new_data: u64,
        ctx: &mut TxContext
    ) {
        cross_module_helper::update(vault, new_data);
    }

    /// SAFE: Cross-module with ownership check in helper
    public entry fun modify_cross_module_safe(
        vault: &mut cross_module_helper::UserVault,
        new_data: u64,
        ctx: &mut TxContext
    ) {
        cross_module_helper::update_safe(vault, new_data, ctx);
    }
}
