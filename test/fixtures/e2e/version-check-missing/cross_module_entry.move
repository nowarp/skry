/// Cross-module test - entry module
module test::version_check_entry {
    use sui::tx_context::TxContext;
    use test::version_check_helper;

    const CURRENT_VERSION: u64 = 2;

    /// Has version check
    public entry fun process_with_check(
        pool: &mut version_check_helper::Pool,
        ctx: &mut TxContext
    ) {
        version_check_helper::verify_version(pool, CURRENT_VERSION);
        version_check_helper::process(pool);
    }

    /// VULNERABLE: Missing version check
    // @expect: version-check-missing
    public entry fun process_without_check(
        pool: &mut version_check_helper::Pool,
        ctx: &mut TxContext
    ) {
        version_check_helper::process(pool);  // No version check
    }
}
