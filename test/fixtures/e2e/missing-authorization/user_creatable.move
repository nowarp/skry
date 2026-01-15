module test::user_creatable;

use sui::transfer;
use sui::tx_context::{Self, TxContext};
use sui::object::{Self, UID, ID};
use sui::table::{Self, Table};
use sui::coin::{Self, Coin};
use sui::balance::{Self, Balance};
use sui::sui::SUI;

/// Registry shared object for user assets
public struct AssetRegistry has key {
    id: UID,
    assets: Table<ID, u64>,
}

/// Pool with balance (for adversarial test)
public struct Pool has key {
    id: UID,
    balance: Balance<SUI>,
}

/// Config struct with privileged admin field (for create-and-corrupt test)
public struct Config has key {
    id: UID,
    admin: address,
}

/// User-creatable asset (anyone can mint)
public struct UserAsset has key, store {
    id: UID,
    creator: address,
    data: u64,
}

/// SAFE (no marker): Creates user asset and registers in shared registry
public entry fun create_and_register_asset(
    registry: &mut AssetRegistry,
    data: u64,
    ctx: &mut TxContext
) {
    let asset = UserAsset {
        id: object::new(ctx),
        creator: tx_context::sender(ctx),
        data,
    };
    table::add(&mut registry.assets, object::uid_to_inner(&asset.id), data);
    transfer::share_object(asset);
}

/// VULNERABLE: Creates user asset BUT ALSO drains pool
// @expect: missing-authorization
public entry fun create_and_drain(
    registry: &mut AssetRegistry,
    pool: &mut Pool,
    amount: u64,
    ctx: &mut TxContext
) {
    let asset = UserAsset {
        id: object::new(ctx),
        creator: tx_context::sender(ctx),
        data: amount,
    };
    table::add(&mut registry.assets, object::uid_to_inner(&asset.id), amount);
    transfer::share_object(asset);

    // The actual vulnerability - drains pool
    let coins = coin::take(&mut pool.balance, amount, ctx);
    transfer::public_transfer(coins, tx_context::sender(ctx));
}

/// Detected: Creates user asset BUT ALSO corrupts config (no value extraction)
/// The filter now detects writes to privileged fields even when creating user-creatable
// @expect: missing-authorization
public entry fun create_and_corrupt(
    registry: &mut AssetRegistry,
    config: &mut Config,
    data: u64,
    ctx: &mut TxContext
) {
    // Create user asset (triggers creates-user-creatable? = true)
    let asset = UserAsset {
        id: object::new(ctx),
        creator: tx_context::sender(ctx),
        data,
    };
    table::add(&mut registry.assets, object::uid_to_inner(&asset.id), data);
    transfer::share_object(asset);

    // BUT ALSO corrupt config admin - this is NOT value extraction!
    // The filter misses this because has-value-extraction? = false
    config.admin = tx_context::sender(ctx);
}

fun init(ctx: &mut TxContext) {
    let registry = AssetRegistry {
        id: object::new(ctx),
        assets: table::new(ctx),
    };
    transfer::share_object(registry);

    let pool = Pool {
        id: object::new(ctx),
        balance: balance::zero(),
    };
    transfer::share_object(pool);

    // Share Config for create-and-corrupt FN test
    let config = Config {
        id: object::new(ctx),
        admin: tx_context::sender(ctx),
    };
    transfer::share_object(config);
}
