/// FQN collision test: test::fqn_b_user::Config is NOT a config struct (user data)
module test::fqn_b_user {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    /// Config struct - NOT a protocol config, just user preferences
    public struct Config has key {
        id: UID,
        display_name: vector<u8>
    }

    /// SAFE: This Config is user data, not protocol config - should NOT trigger
    public fun update_name(config: &mut Config, name: vector<u8>) {
        config.display_name = name;
    }
}
