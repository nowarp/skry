/// FQN collision test - module A
module test::fqn_collision_a {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    public struct AdminCap has key, store {
        id: UID,
    }

    public struct Vault has key {
        id: UID,
        owner: address,
        balance: Balance<SUI>,
    }

    /// VULNERABLE: Admin drains to arbitrary recipient
    // @expect: admin-drain-risk
    public entry fun admin_withdraw(
        _admin: &AdminCap,
        vault: &mut Vault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let amount = balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }
}
