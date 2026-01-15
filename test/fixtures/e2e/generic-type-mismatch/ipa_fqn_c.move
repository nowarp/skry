/// IPA FQN collision test: module_c calls ipa_fqn_a::validate (the validating one)
module test::ipa_fqn_c {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::UID;
    use test::ipa_fqn_a;

    public struct Pool has key {
        id: UID,
    }

    /// SAFE: Calls ipa_fqn_a::validate which does validate, then extracts value
    /// If IPA incorrectly uses simple name matching, this might not be marked safe
    public fun withdraw_calls_validated<T>(pool: &mut Pool, balance: &mut Balance<T>, expected_type: std::string::String, amount: u64, ctx: &mut TxContext) {
        ipa_fqn_a::validate<T>(expected_type);
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
