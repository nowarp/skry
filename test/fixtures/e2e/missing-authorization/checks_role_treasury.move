module test::checks_role_treasury;

use sui::transfer;
use sui::coin::{Self as coin, Coin};
use sui::balance::{Self as balance, Balance};
use sui::object::{Self as object, UID};
use sui::tx_context::{Self as tx_context, TxContext};
use test::checks_role_admin::{AdminCap, OperatorCap};

/// Treasury vault holding funds
public struct Treasury<phantom CoinType> has key {
    id: UID,
    balance: Balance<CoinType>,
}

/// Init function to share the treasury
fun init(ctx: &mut TxContext) {
    let treasury = Treasury<sui::sui::SUI> {
        id: object::new(ctx),
        balance: balance::zero(),
    };
    transfer::share_object(treasury);
}

/// Create a new treasury - admin only
public fun create_treasury<CoinType>(_: &AdminCap, ctx: &mut TxContext): Treasury<CoinType> {
    Treasury {
        id: object::new(ctx),
        balance: balance::zero(),
    }
}

/// Deposit funds into treasury - anyone can deposit
public fun deposit<CoinType>(
    treasury: &mut Treasury<CoinType>,
    payment: Coin<CoinType>,
) {
    let payment_balance = coin::into_balance(payment);
    balance::join(&mut treasury.balance, payment_balance);
}

/// Withdraw funds - requires admin capability (SAFE)
public entry fun withdraw_with_admin<CoinType>(
    _: &AdminCap,
    treasury: &mut Treasury<CoinType>,
    amount: u64,
    recipient: address,
    ctx: &mut TxContext,
) {
    let withdrawn = balance::split(&mut treasury.balance, amount);
    let coin = coin::from_balance(withdrawn, ctx);
    transfer::public_transfer(coin, recipient);
}

/// Withdraw funds - requires operator capability (SAFE)
public entry fun withdraw_with_operator<CoinType>(
    _: &OperatorCap,
    treasury: &mut Treasury<CoinType>,
    amount: u64,
    recipient: address,
    ctx: &mut TxContext,
) {
    let withdrawn = balance::split(&mut treasury.balance, amount);
    let coin = coin::from_balance(withdrawn, ctx);
    transfer::public_transfer(coin, recipient);
}

/// UNSAFE: Withdraw without any capability check
// @expect:missing-authorization
public entry fun withdraw_unsafe<CoinType>(
    treasury: &mut Treasury<CoinType>,
    amount: u64,
    recipient: address,
    ctx: &mut TxContext,
) {
    // No permission check! Anyone can call this
    let withdrawn = balance::split(&mut treasury.balance, amount);
    let coin = coin::from_balance(withdrawn, ctx);
    transfer::public_transfer(coin, recipient);
}

/// Helper to get balance (internal)
fun get_balance<CoinType>(treasury: &Treasury<CoinType>): u64 {
    balance::value(&treasury.balance)
}
