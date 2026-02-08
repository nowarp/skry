/// False positive test: Admin gating via separate assert_admin callee
///
/// Pattern: assert_admin(global, ctx) is a private helper that checks
/// sender == global.admin. The caller delegates auth to this helper
/// but does the state write directly.
///
/// This differs from do_set_value_checked (line 120 in vulnerable.move)
/// where auth AND state write are in the SAME callee.
module test::fp_assert_admin {
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::dynamic_field;
    use sui::transfer;

    /// Shared protocol storage with admin field
    public struct Global has key {
        id: UID,
        admin: address,
        value: u64,
    }

    /// Private auth helper: checks sender == admin field.
    /// This function has HasSenderEqualityCheck but NO state write sinks.
    fun assert_admin(g: &Global, ctx: &TxContext) {
        assert!(tx_context::sender(ctx) == g.admin, 0);
    }

    /// SAFE: Admin-gated via assert_admin callee, writes to dynamic field.
    /// Auth is in callee, state write is directly in this function.
    /// The "sender" guard should propagate from assert_admin, but currently doesn't.
    /// This function should NOT trigger tainted-state-modification.
    public entry fun set_dynamic_field_admin(
        g: &mut Global,
        key: vector<u8>,
        value: u64,
        ctx: &mut TxContext
    ) {
        assert_admin(g, ctx);
        dynamic_field::add(&mut g.id, key, value);
    }

    /// VULNERABLE: No auth check at all (control case — must fire)
    // @expect: tainted-state-modification
    public entry fun set_dynamic_field_no_auth(
        g: &mut Global,
        key: vector<u8>,
        value: u64,
        _ctx: &mut TxContext
    ) {
        dynamic_field::add(&mut g.id, key, value);
    }

    fun init(ctx: &mut TxContext) {
        let g = Global {
            id: object::new(ctx),
            admin: tx_context::sender(ctx),
            value: 0,
        };
        transfer::share_object(g);
    }
}
