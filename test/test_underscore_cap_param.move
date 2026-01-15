module test::underscore_cap {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};

    /// Admin capability
    struct AdminCap has key, store {
        id: UID
    }

    /// Shared pool
    struct Pool<phantom T> has key {
        id: UID,
        balance: Balance<T>
    }

    /// Initialize with admin cap transferred to sender
    fun init(ctx: &mut TxContext) {
        let admin_cap = AdminCap {
            id: object::new(ctx)
        };
        transfer::transfer(admin_cap, tx_context::sender(ctx));
    }

    /// Function with unused capability parameter (underscore prefix)
    /// Should be detected as having role check
    public fun claim_fees<T>(
        _admin: &AdminCap,  // Unused parameter with underscore prefix
        pool: &mut Pool<T>,
        ctx: &mut TxContext
    ): Coin<T> {
        let amount = balance::withdraw_all(&mut pool.balance);
        coin::from_balance(amount, ctx)
    }

    /// Function with used capability parameter (no underscore)
    /// Should be detected as having role check
    public fun claim_fees_v2<T>(
        admin: &AdminCap,  // Used parameter
        pool: &mut Pool<T>,
        ctx: &mut TxContext
    ): Coin<T> {
        let _ = admin;  // Use it to avoid warning
        let amount = balance::withdraw_all(&mut pool.balance);
        coin::from_balance(amount, ctx)
    }
}
