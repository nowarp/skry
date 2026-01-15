/// Test safe patterns for arbitrary-recipient-drain rule.
/// These patterns should NOT be flagged as vulnerabilities.
module test::drain_safe_patterns {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    /// Shared protocol pool
    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// User-owned vault
    public struct Vault has key {
        id: UID,
        owner: address,
        balance: Balance<SUI>,
    }

    /// Admin capability (role-based access control)
    public struct AdminCap has key, store {
        id: UID,
    }

    /// User-creatable receipt (anyone can create)
    public struct Receipt has key, store {
        id: UID,
        amount: u64,
    }

    // ========== Pattern 1: checks-role? ==========

    /// SAFE: AdminCap protects function
    public entry fun withdraw_with_admin(
        _cap: &AdminCap,
        pool: &mut Pool,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut pool.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    // ========== Pattern 2: has-sender-equality-check? ==========

    /// SAFE: Checks vault.owner == sender
    public entry fun withdraw_owned(
        vault: &mut Vault,
        amount: u64,
        recipient: address,
        ctx: &mut TxContext
    ) {
        assert!(vault.owner == tx_context::sender(ctx), 1);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    // ========== Pattern 3: transfers-user-provided-value? ==========

    /// SAFE: User passes their own Coin
    public entry fun transfer_my_coin(
        coin: Coin<SUI>,
        recipient: address
    ) {
        transfer::public_transfer(coin, recipient);
    }

    // ========== Pattern 4: operates-on-owned-only? ==========

    /// SAFE: Function operates on owned objects only (Vault is not shared)
    public entry fun withdraw_from_owned_vault(
        vault: Vault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let Vault { id, owner: _, balance } = vault;
        object::delete(id);
        let coins = coin::from_balance(balance, ctx);
        transfer::public_transfer(coins, recipient);
    }

    // ========== Pattern 5: user-creatable-struct? ==========

    /// SAFE: Receipt can be created by any user
    public entry fun transfer_receipt(
        receipt: Receipt,
        recipient: address
    ) {
        transfer::public_transfer(receipt, recipient);
    }

    /// Anyone can create Receipt
    public entry fun create_receipt(amount: u64, ctx: &mut TxContext) {
        let receipt = Receipt {
            id: object::new(ctx),
            amount,
        };
        transfer::public_transfer(receipt, tx_context::sender(ctx));
    }

    // ========== Pattern 6: transfers-from-sender? ==========

    /// SAFE: User deposits own funds (reverse direction)
    public entry fun deposit_own_funds(
        pool: &mut Pool,
        coin: Coin<SUI>
    ) {
        balance::join(&mut pool.balance, coin::into_balance(coin));
    }

    // ========== Pattern 7: withdraws-from-caller-owned-pool? ==========

    /// SAFE: User withdraws from their own vault (owner check)
    public entry fun withdraw_my_vault(
        vault: &mut Vault,
        amount: u64,
        ctx: &mut TxContext
    ) {
        assert!(vault.owner == tx_context::sender(ctx), 1);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        // Note: recipient is sender (self-withdrawal)
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    // ========== Init ==========

    fun init(ctx: &mut TxContext) {
        let pool = Pool {
            id: object::new(ctx),
            balance: balance::zero(),
        };
        transfer::share_object(pool);

        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
