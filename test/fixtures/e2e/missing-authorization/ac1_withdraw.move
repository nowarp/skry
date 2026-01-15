module test::ac1_withdraw;

use sui::transfer;
use sui::coin::{Self as coin, Coin};
use sui::tx_context::{Self as tx_context, TxContext};
use sui::event;
use sui::balance::{Self as balance, Balance};
use sui::object::{Self as object, UID};
use std::type_name;
use test::ac1_config::AdminCap;

public struct RewarderGlobalVault<phantom CoinType> has key {
    id: UID,
    balance: Balance<CoinType>,
}

public struct GlobalConfig has key {
    id: UID,
    min_withdraw: u64,
    max_withdraw: u64,
}

public struct EmergentWithdrawEvent has copy, drop {
    reward_type: vector<u8>,
    withdraw_amount: u64,
    after_amount: u64,
    recipient: address,
}

/// Init function to share the vault - required for shared object detection
fun init(ctx: &mut TxContext) {
    let vault = RewarderGlobalVault<sui::sui::SUI> {
        id: object::new(ctx),
        balance: balance::zero(),
    };
    transfer::share_object(vault);

    let config = GlobalConfig {
        id: object::new(ctx),
        min_withdraw: 100,
        max_withdraw: 10000,
    };
    transfer::share_object(config);
}

public fun create_vault<CoinType>(ctx: &mut TxContext): RewarderGlobalVault<CoinType> {
    RewarderGlobalVault {
        id: object::new(ctx),
        balance: balance::zero(),
    }
}

public fun deposit<CoinType>(
    vault: &mut RewarderGlobalVault<CoinType>,
    payment: Coin<CoinType>,
) {
    let payment_balance = coin::into_balance(payment);
    balance::join(&mut vault.balance, payment_balance);
}

fun withdraw_reward<CoinType>(
    vault: &mut RewarderGlobalVault<CoinType>,
    amount: u64,
): Balance<CoinType> {
    balance::split(&mut vault.balance, amount)
}

fun balance_of<CoinType>(vault: &RewarderGlobalVault<CoinType>): u64 {
    balance::value(&vault.balance)
}

/// SAFE: Has a capability check
public entry fun withdraw_safe<CoinType>(
    _: &AdminCap, // Admin privelege is checked
    config: &GlobalConfig,
    vault: &mut RewarderGlobalVault<CoinType>,
    amount: u64,
    recipient: address,
    ctx: &mut TxContext,
) {
    assert!(amount >= config.min_withdraw, 1);
    assert!(amount <= config.max_withdraw, 2);
    assert!(balance_of(vault) >= amount, 3);

    let withdraw_balance = withdraw_reward<CoinType>(vault, amount);
    let after_amount = balance_of<CoinType>(vault);

    let coin = coin::from_balance(withdraw_balance, ctx);
    transfer::public_transfer(coin, recipient);

    event::emit(EmergentWithdrawEvent {
        reward_type: type_name::get<CoinType>().into_string().into_bytes(),
        withdraw_amount: amount,
        after_amount,
        recipient,
    });
}

// @expect: missing-authorization
public entry fun withdraw_unsafe<CoinType>(
    // No permission check before transferring funds
    config: &GlobalConfig,
    vault: &mut RewarderGlobalVault<CoinType>,
    amount: u64,
    recipient: address,
    ctx: &mut TxContext,
) {
    assert!(amount >= config.min_withdraw, 1);
    assert!(amount <= config.max_withdraw, 2);
    assert!(balance_of(vault) >= amount, 3);

    let withdraw_balance = withdraw_reward<CoinType>(vault, amount);
    let after_amount = balance_of<CoinType>(vault);

    let coin = coin::from_balance(withdraw_balance, ctx);
    transfer::public_transfer(coin, recipient);

    event::emit(EmergentWithdrawEvent {
        reward_type: type_name::get<CoinType>().into_string().into_bytes(),
        withdraw_amount: amount,
        after_amount,
        recipient,
    });
}
