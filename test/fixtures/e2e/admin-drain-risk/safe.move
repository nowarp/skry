/// Safe test cases - no admin drain risk
module test::admin_drain_safe {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    public struct AdminCap has key, store {
        id: UID,
    }

    public struct UserVault has key {
        id: UID,
        owner: address,
        balance: Balance<SUI>,
    }

    /// SAFE: Admin withdraws protocol fees (not user assets)
    public fun admin_collect_fees(
        _admin: &AdminCap,
        protocol_treasury: &mut Balance<SUI>,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let amount = balance::value(protocol_treasury);
        let coins = coin::take(protocol_treasury, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// SAFE: Admin can only rescue to original owner
    /// FALSE POSITIVE (candidate): Rule flags as candidate but should be safe
    public entry fun admin_rescue_to_owner(
        _admin: &AdminCap,
        vault: &mut UserVault,
        ctx: &mut TxContext
    ) {
        let amount = balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, vault.owner);  // Only to owner
    }

    /// SAFE: User controls their own withdrawal
    public entry fun user_self_withdraw(
        vault: &mut UserVault,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        assert!(tx_context::sender(ctx) == vault.owner, 0);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);  // User's choice
    }
}
