/// Test cases for unauth-sensitive-setter rule.
/// Detects modification of shared protocol state without authorization.
/// Different from missing-authorization: catches setters without transfer sinks.
module test::sensitive_setter {
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};

    /// Protocol settings (shared object)
    public struct Settings has key {
        id: UID,
        fee_rate: u64,
        oracle: address,
        max_limit: u64,
    }

    /// Admin capability
    public struct AdminCap has key, store {
        id: UID,
    }

    /// VULNERABLE: Modifies shared object without auth
    // @expect: unauth-sensitive-setter
    public fun set_fee(
        settings: &mut Settings,
        fee_rate: u64,
    ) {
        settings.fee_rate = fee_rate;
    }

    /// VULNERABLE: Modifies address field without auth
    // @expect: unauth-sensitive-setter
    public fun set_oracle(
        settings: &mut Settings,
        oracle: address,
    ) {
        settings.oracle = oracle;
    }

    /// VULNERABLE: IPA - entry calls helper that modifies shared object
    // @expect: unauth-sensitive-setter
    public entry fun update_limit(
        settings: &mut Settings,
        limit: u64,
        _ctx: &mut TxContext
    ) {
        do_set_limit(settings, limit);
    }

    /// Helper that modifies shared object
    fun do_set_limit(settings: &mut Settings, limit: u64) {
        settings.max_limit = limit;
    }

    /// SAFE: Has role check
    public fun set_fee_admin(
        settings: &mut Settings,
        fee_rate: u64,
        _cap: &AdminCap,
    ) {
        settings.fee_rate = fee_rate;
    }

    /// SAFE: Has sender check
    public fun set_fee_with_sender(
        settings: &mut Settings,
        fee_rate: u64,
        ctx: &mut TxContext
    ) {
        assert!(tx_context::sender(ctx) == @0x1, 0);
        settings.fee_rate = fee_rate;
    }

    /// SAFE: public(package) is internal
    public(package) fun set_fee_internal(
        settings: &mut Settings,
        fee_rate: u64,
    ) {
        settings.fee_rate = fee_rate;
    }

    fun init(ctx: &mut TxContext) {
        let settings = Settings {
            id: object::new(ctx),
            fee_rate: 100,
            oracle: @0x0,
            max_limit: 1000000,
        };
        transfer::share_object(settings);

        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
