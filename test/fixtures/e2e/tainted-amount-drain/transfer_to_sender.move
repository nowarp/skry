/// Test cases for tainted-amount-drain false positives.
/// Functions that transfer extracted value TO THE SENDER are safe because
/// the caller can only affect themselves, not drain funds to an arbitrary recipient.
module test::transfer_to_sender {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    /// Shared pool (lending protocol storage)
    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// User's lending position tracked by protocol
    public struct Storage has key {
        id: UID,
    }

    /// SAFE: Withdraw pattern - user withdraws to themselves via lending module
    /// The entry function is a thin wrapper that calls the lending module.
    /// The lending module (withdraw_with_validation) enforces collateral ratio.
    public entry fun entry_withdraw(
        pool: &mut Pool,
        storage: &mut Storage,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let user = tx_context::sender(ctx);
        // Calls lending module which validates position before extraction
        let coins = withdraw_with_validation(pool, storage, amount, user, ctx);
        transfer::public_transfer(coins, user);
    }

    /// SAFE: Same pattern with v2 suffix
    public entry fun entry_withdraw_v2(
        pool: &mut Pool,
        storage: &mut Storage,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let user = tx_context::sender(ctx);
        let coins = withdraw_with_validation(pool, storage, amount, user, ctx);
        transfer::public_transfer(coins, user);
    }

    /// SAFE: Borrow pattern - user borrows to themselves
    public entry fun entry_borrow(
        pool: &mut Pool,
        storage: &mut Storage,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let user = tx_context::sender(ctx);
        let coins = borrow_with_validation(pool, storage, amount, user, ctx);
        transfer::public_transfer(coins, user);
    }

    /// Internal: Withdraw with position validation (simulates lending::withdraw_coin)
    /// This function checks user's position before allowing withdrawal.
    fun withdraw_with_validation(
        pool: &mut Pool,
        _storage: &mut Storage,
        amount: u64,
        _user: address,
        ctx: &mut TxContext
    ): Coin<SUI> {
        // In real code: validate user's deposit position in storage
        // assert!(get_user_deposit(storage, user) >= amount, E_INSUFFICIENT_DEPOSIT);
        coin::take(&mut pool.balance, amount, ctx)
    }

    /// Internal: Borrow with collateral validation
    fun borrow_with_validation(
        pool: &mut Pool,
        _storage: &mut Storage,
        amount: u64,
        _user: address,
        ctx: &mut TxContext
    ): Coin<SUI> {
        // In real code: validate user's collateral ratio
        // assert!(check_collateral_ratio(storage, user, amount), E_INSUFFICIENT_COLLATERAL);
        coin::take(&mut pool.balance, amount, ctx)
    }

    /// VULNERABLE: Drain to arbitrary recipient
    /// User controls both amount AND recipient - classic drain pattern.
    // @expect: tainted-amount-drain
    public entry fun drain_to_arbitrary(
        pool: &mut Pool,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    fun init(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            balance: balance::zero(),
        };
        transfer::share_object(pool);

        let storage = Storage { id: object::new(ctx) };
        transfer::share_object(storage);
    }
}
