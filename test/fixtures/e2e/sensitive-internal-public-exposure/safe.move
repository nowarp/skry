module test::safe_internal {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    public struct AdminCap has key, store {
        id: UID,
    }

    public struct VaultCap has key, store {
        id: UID,
    }

    public struct Vault has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// SAFE: public(friend) - properly restricted visibility
    public(friend) fun do_withdraw_restricted(vault: &mut Vault, amount: u64): Balance<SUI> {
        balance::split(&mut vault.balance, amount)
    }

    /// SAFE: Has capability parameter - authorized access
    public fun admin_withdraw_with_cap(
        _cap: &AdminCap,
        vault: &mut Vault,
        amount: u64
    ): Balance<SUI> {
        balance::split(&mut vault.balance, amount)
    }

    /// SAFE: No internal callers - standalone public API (read-only)
    public fun get_vault_balance(vault: &Vault): u64 {
        balance::value(&vault.balance)
    }

    /// SAFE: Factory pattern - returns capability to caller
    public fun create_vault(ctx: &mut TxContext): VaultCap {
        let vault = Vault {
            id: object::new(ctx),
            balance: balance::zero(),
        };
        let cap = VaultCap { id: object::new(ctx) };
        transfer::share_object(vault);
        cap
    }

    /// SAFE: Entry point - designed to be called directly by users
    public entry fun user_deposit(
        vault: &mut Vault,
        coin: Coin<SUI>,
    ) {
        balance::join(&mut vault.balance, coin::into_balance(coin));
    }

    /// SAFE: Checks sender - has authorization
    public fun sender_checked_withdraw(
        vault: &mut Vault,
        amount: u64,
        ctx: &TxContext
    ): Balance<SUI> {
        // Assume some sender check here
        assert!(tx_context::sender(ctx) == @0x1, 0);
        balance::split(&mut vault.balance, amount)
    }

    fun init(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
