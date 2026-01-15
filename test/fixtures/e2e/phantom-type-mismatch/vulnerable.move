/// Test cases for phantom-type-mismatch rule.
/// Tests detection of capability guards with mismatched phantom types.
module test::phantom_type_mismatch {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    /// Admin capability with phantom type T - binds to specific pool type
    public struct AdminCap<phantom T> has key {
        id: UID,
    }

    /// Pool with phantom type T - identifies the token type
    public struct Pool<phantom T> has key {
        id: UID,
        balance: u64,
    }

    /// Treasury with phantom type T
    public struct Treasury<phantom T> has key {
        id: UID,
        total: u64,
    }

    // =========================================================================
    // VULNERABLE: Phantom type mismatch - guard T, target U
    // =========================================================================

    /// VULNERABLE: Cap<T> guards Pool<U> where T != U
    // @expect: phantom-type-mismatch
    public entry fun admin_action_mismatch<T, U>(
        _cap: &AdminCap<T>,
        pool: &mut Pool<U>,
        amount: u64,
    ) {
        // Attacker with AdminCap<FakeToken> can drain Pool<RealToken>
        pool.balance = pool.balance - amount;
    }

    /// VULNERABLE: Cap<T> guards Treasury<U> where T != U
    // @expect: phantom-type-mismatch
    public entry fun treasury_mismatch<T, U>(
        _cap: &AdminCap<T>,
        treasury: &mut Treasury<U>,
        amount: u64,
    ) {
        treasury.total = treasury.total - amount;
    }

    /// VULNERABLE: Multiple mismatches - T guards U and V
    // @expect: phantom-type-mismatch
    public entry fun multi_mismatch<T, U, V>(
        _cap: &AdminCap<T>,
        pool: &mut Pool<U>,
        treasury: &mut Treasury<V>,
    ) {
        pool.balance = 0;
        treasury.total = 0;
    }

    // =========================================================================
    // SAFE: Same phantom type for guard and target
    // =========================================================================

    /// SAFE: Cap<T> guards Pool<T> - same phantom type
    // @safe: phantom-type-mismatch
    public entry fun admin_action_correct<T>(
        _cap: &AdminCap<T>,
        pool: &mut Pool<T>,
        amount: u64,
    ) {
        // Cap<T> properly guards Pool<T>
        pool.balance = pool.balance - amount;
    }

    /// SAFE: Cap<T> guards both Pool<T> and Treasury<T>
    // @safe: phantom-type-mismatch
    public entry fun multi_correct<T>(
        _cap: &AdminCap<T>,
        pool: &mut Pool<T>,
        treasury: &mut Treasury<T>,
    ) {
        pool.balance = 0;
        treasury.total = 0;
    }

    /// SAFE: No phantom type (non-generic capability)
    // @safe: phantom-type-mismatch
    public entry fun non_generic_cap(
        pool: &mut Pool<u64>,
        amount: u64,
    ) {
        pool.balance = pool.balance - amount;
    }

    /// SAFE: Internal function (not entry)
    fun internal_mismatch<T, U>(
        _cap: &AdminCap<T>,
        pool: &mut Pool<U>,
        amount: u64,
    ) {
        pool.balance = pool.balance - amount;
    }
}
