/// FQN collision test - module B
module test::fqn_collision_b {
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

    /// SAFE: Admin can only return to owner
    public entry fun admin_rescue(
        _admin: &AdminCap,
        vault: &mut Vault,
        ctx: &mut TxContext
    ) {
        let amount = balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, vault.owner);  // Only to owner
    }
}
