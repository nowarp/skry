/// IPA FQN collision test: module_d calls ipa_fqn_b::validate (the non-validating one)
module test::ipa_fqn_d {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::UID;
    use test::ipa_fqn_b;

    public struct Pool has key {
        id: UID,
    }

    /// VULNERABLE: Calls ipa_fqn_b::validate which does NOT validate, then extracts value
    // @expect: generic-type-mismatch
    public fun withdraw_calls_unvalidated<T>(pool: &mut Pool, balance: &mut Balance<T>, amount: u64, ctx: &mut TxContext) {
        ipa_fqn_b::validate<T>();
        let coins = coin::take(balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
