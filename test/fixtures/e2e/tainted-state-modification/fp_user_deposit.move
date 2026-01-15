/// False positive test: User deposit patterns
/// User deposits own coin to pools - NOT a vulnerability
module test::fp_user_deposit {
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::dynamic_field;

    /// Pool shared object
    public struct Pool<phantom T> has key {
        id: UID,
        balance: Balance<T>,
        total_shares: u64,
    }

    /// LP token for liquidity providers
    public struct LPToken<phantom T> has key, store {
        id: UID,
        shares: u64,
    }

    /// SAFE: User deposits own coin to pool
    /// This is standard DeFi deposit - not a vulnerability
    public entry fun deposit<T>(
        pool: &mut Pool<T>,
        coin: Coin<T>,
        _ctx: &mut TxContext
    ) {
        let b = coin::into_balance(coin);
        balance::join(&mut pool.balance, b);
    }

    /// SAFE: User deposits and gets LP token back
    /// Standard liquidity provision pattern
    public entry fun add_liquidity<T>(
        pool: &mut Pool<T>,
        coin: Coin<T>,
        ctx: &mut TxContext
    ) {
        let value = coin::value(&coin);
        balance::join(&mut pool.balance, coin::into_balance(coin));
        // Mint LP token to user
        let lp = LPToken<T> {
            id: object::new(ctx),
            shares: value,
        };
        pool.total_shares = pool.total_shares + value;
        transfer::public_transfer(lp, tx_context::sender(ctx));
    }

    /// SAFE: User stakes SUI
    /// Standard staking pattern
    public entry fun stake<T>(
        pool: &mut Pool<T>,
        coin: Coin<T>,
        ctx: &mut TxContext
    ) {
        let amount = coin::value(&coin);
        balance::join(&mut pool.balance, coin::into_balance(coin));
        // Issue staking receipt
        let receipt = LPToken<T> {
            id: object::new(ctx),
            shares: amount,
        };
        transfer::public_transfer(receipt, tx_context::sender(ctx));
    }

    /// Coin pool using coin::put
    public struct CoinPool<phantom T> has key {
        id: UID,
        coins: Coin<T>,
    }

    /// SAFE: User deposits using coin::put pattern
    public entry fun deposit_coin<T>(
        pool: &mut CoinPool<T>,
        coin: Coin<T>,
        _ctx: &mut TxContext
    ) {
        coin::put(&mut pool.coins, coin);
    }

    /// SAFE: User deposits using coin::join pattern
    public entry fun join_coin<T>(
        pool: &mut CoinPool<T>,
        coin: Coin<T>,
        _ctx: &mut TxContext
    ) {
        coin::join(&mut pool.coins, coin);
    }

    /// SAFE: User deposits via mutable reference + coin::split
    /// tcpBridge pegin pattern - user provides &mut Coin, function splits it
    public entry fun deposit_via_split<T>(
        pool: &mut Pool<T>,
        coin: &mut Coin<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let split_coin = coin::split(coin, amount, ctx);
        balance::join(&mut pool.balance, coin::into_balance(split_coin));
    }

    /// SAFE: User deposits via mutable balance reference + balance::split
    public entry fun deposit_via_balance_split<T>(
        pool: &mut Pool<T>,
        balance: &mut Balance<T>,
        amount: u64,
        _ctx: &mut TxContext
    ) {
        let split_balance = balance::split(balance, amount);
        balance::join(&mut pool.balance, split_balance);
    }

    /// SAFE: User deposits all via withdraw_all
    public entry fun deposit_all<T>(
        pool: &mut Pool<T>,
        balance: &mut Balance<T>,
        _ctx: &mut TxContext
    ) {
        let all = balance::withdraw_all(balance);
        balance::join(&mut pool.balance, all);
    }

    /// SAFE: User deposits via split to dynamic_field (tcpBridge actual pattern)
    public entry fun deposit_via_split_to_df<T>(
        storage: &mut Storage,
        coin: &mut Coin<T>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let split_coin = coin::split(coin, amount, ctx);
        dynamic_field::add(&mut storage.id, b"deposit", coin::into_balance(split_coin));
    }

    /// Storage struct for state writes
    public struct Storage has key {
        id: UID,
        version: u64,
    }

    /// VULNERABLE: Deposits coin BUT ALSO writes arbitrary data to storage
    /// The deposit part is safe, but storage corruption is NOT
    /// This tests per-sink detection - should NOT suppress the whole function
    // @expect: tainted-state-modification
    public entry fun deposit_and_corrupt<T>(
        pool: &mut Pool<T>,
        storage: &mut Storage,
        coin: Coin<T>,
        key: vector<u8>,
        value: u64,
        _ctx: &mut TxContext
    ) {
        // Safe: user deposits their own coin
        balance::join(&mut pool.balance, coin::into_balance(coin));
        // VULNERABLE: anyone can write arbitrary data to storage!
        dynamic_field::add(&mut storage.id, key, value);
    }

    fun init(_ctx: &mut TxContext) {}
}
