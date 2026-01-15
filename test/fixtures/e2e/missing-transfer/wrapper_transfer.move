/// Wrapper transfer tests
/// Tests indirect transfer patterns via wrapper structs and state storage
module test::missing_transfer_wrapper {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::sui::SUI;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::event;

    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// Wrapper struct that holds extracted coins
    public struct Receipt has key, store {
        id: UID,
        coins: Coin<SUI>,
    }

    /// Shared object that can hold coins
    public struct Escrow has key {
        id: UID,
        held_coins: Coin<SUI>,
    }

    /// Event with coin value
    public struct WithdrawalEvent has copy, drop {
        amount: u64,
    }

    // =========================================================================
    // SAFE: Extract coin, wrap in struct, transfer wrapper
    // The coins ARE transferred (inside the Receipt struct)
    // =========================================================================

    public entry fun extract_wrap_transfer(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        let receipt = Receipt {
            id: object::new(ctx),
            coins: coins,
        };
        transfer::public_transfer(receipt, sui::tx_context::sender(ctx));
    }

    // =========================================================================
    // VULNERABLE: Extract coin, store in shared object field
    // User loses access to their coins - stored in protocol state
    // =========================================================================

    /// VULNERABLE: Coins stored in shared escrow, user can't retrieve
    // @expect: missing-transfer
    public entry fun extract_store_in_shared(
        pool: &mut Pool,
        escrow: &mut Escrow,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        coin::join(&mut escrow.held_coins, coins);
        // User's coins are now in shared object - not transferred to them
    }

    // =========================================================================
    // VULNERABLE: Extract coin, just emit event, no actual transfer
    // =========================================================================

    /// VULNERABLE: Emits event but doesn't transfer coins
    // @expect: missing-transfer
    public entry fun extract_emit_only(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        event::emit(WithdrawalEvent { amount: coin::value(&coins) });
        // Coins not transferred - put back
        coin::put(&mut pool.balance, coins);
    }

    // =========================================================================
    // VULNERABLE: Extract coin, put back into DIFFERENT pool
    // User's coins go to wrong destination
    // =========================================================================

    /// VULNERABLE: Extracted from pool_a, deposited to pool_b
    // @expect: missing-transfer
    public entry fun extract_deposit_wrong_pool(
        pool_a: &mut Pool,
        pool_b: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool_a.balance, amount, ctx);
        coin::put(&mut pool_b.balance, coins);
        // User extracted from A but coins went to B - user loses funds
    }

    // =========================================================================
    // SAFE: Extract coin, put back into SAME pool (redeposit)
    // =========================================================================

    public entry fun extract_redeposit_same_pool(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        coin::put(&mut pool.balance, coins);
        // Redeposited to same pool - no loss
    }

    // =========================================================================
    // VULNERABLE: Create wrapper but don't transfer it
    // =========================================================================

    /// VULNERABLE: Creates Receipt wrapper but never transfers it
    // @expect: missing-transfer
    public entry fun wrap_but_no_transfer(
        pool: &mut Pool,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        let receipt = Receipt {
            id: object::new(ctx),
            coins: coins,
        };
        // Receipt not transferred - unpack and put back
        let Receipt { id, coins: inner_coins } = receipt;
        object::delete(id);
        coin::put(&mut pool.balance, inner_coins);
    }
}
