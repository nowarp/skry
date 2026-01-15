/// Test cases for config-write-without-admin rule.
/// Detects modification of protocol config without admin authorization.
module test::config_write {
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};

    /// Protocol configuration (has "Config" in name for detection)
    public struct ProtocolConfig has key {
        id: UID,
        fee_rate: u64,
        oracle: address,
        max_limit: u64,
    }

    /// Admin capability
    public struct AdminCap has key, store {
        id: UID,
    }

    /// Compound capability name (should also be detected as role)
    public struct WeightHookAdminCap<phantom P> has key, store {
        id: UID,
    }

    /// VULNERABLE: Modifies config without admin check
    // @expect: config-write-without-privileged
    public fun set_fee(
        config: &mut ProtocolConfig,
        fee_rate: u64,
    ) {
        config.fee_rate = fee_rate;
    }

    /// VULNERABLE: Modifies config address without auth
    // @expect: config-write-without-privileged
    public fun set_oracle(
        config: &mut ProtocolConfig,
        oracle: address,
    ) {
        config.oracle = oracle;
    }

    /// VULNERABLE: IPA - entry calls helper that modifies config
    // @expect: config-write-without-privileged
    public entry fun update_fee(
        config: &mut ProtocolConfig,
        fee_rate: u64,
        _ctx: &mut TxContext
    ) {
        do_set_fee(config, fee_rate);
    }

    /// Helper that modifies config
    fun do_set_fee(config: &mut ProtocolConfig, fee_rate: u64) {
        config.fee_rate = fee_rate;
    }

    /// SAFE: Has role check
    public fun set_fee_admin(
        config: &mut ProtocolConfig,
        fee_rate: u64,
        _cap: &AdminCap,
    ) {
        config.fee_rate = fee_rate;
    }

    /// SAFE: Has compound cap name role check (WeightHookAdminCap)
    public fun set_fee_with_compound_cap<P>(
        config: &mut ProtocolConfig,
        fee_rate: u64,
        _cap: &WeightHookAdminCap<P>,
    ) {
        config.fee_rate = fee_rate;
    }

    /// SAFE: Has sender check (traditional call syntax)
    public fun set_fee_with_sender(
        config: &mut ProtocolConfig,
        fee_rate: u64,
        ctx: &mut TxContext
    ) {
        assert!(tx_context::sender(ctx) == @0x1, 0);
        config.fee_rate = fee_rate;
    }

    /// SAFE: Has sender check (method-call syntax: ctx.sender())
    public fun set_fee_with_sender_method(
        config: &mut ProtocolConfig,
        fee_rate: u64,
        ctx: &mut TxContext
    ) {
        assert!(config.oracle == ctx.sender(), 0);
        config.fee_rate = fee_rate;
    }

    /// SAFE: public(package) is internal
    public(package) fun set_fee_internal(
        config: &mut ProtocolConfig,
        fee_rate: u64,
    ) {
        config.fee_rate = fee_rate;
    }

    /// Init
    fun init(ctx: &mut TxContext) {
        let config = ProtocolConfig {
            id: object::new(ctx),
            fee_rate: 100,
            oracle: @0x0,
            max_limit: 1000000,
        };
        transfer::share_object(config);

        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
