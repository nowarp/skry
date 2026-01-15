/// FQN collision test: test::fqn_a_dex::Config IS a config struct
module test::fqn_a_dex {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    /// Config struct - IS a protocol config
    public struct Config has key {
        id: UID,
        fee_rate: u64
    }

    /// VULNERABLE: Modifies config without auth
    // @expect: config-write-without-privileged
    public fun set_fee(config: &mut Config, rate: u64) {
        config.fee_rate = rate;
    }
}
