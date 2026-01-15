/// Sender-as-auth safe cases
/// These must NOT be flagged - sender used for identity/auth, not randomness
module test::weak_randomness_sender_safe {
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};

    public struct AdminCap has key, store {
        id: UID,
    }

    public struct Vault has key {
        id: UID,
        owner: address,
        balance: u64,
    }

    /// SAFE: Sender as transfer recipient
    public entry fun create_admin_cap(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
        // Sender used for ownership transfer - NOT randomness
    }

    /// SAFE: Sender for owner comparison (auth check)
    public entry fun withdraw(vault: &mut Vault, amount: u64, ctx: &mut TxContext) {
        assert!(vault.owner == tx_context::sender(ctx), 0);
        vault.balance = vault.balance - amount;
        // Sender compared for authorization - NOT randomness
    }

    /// SAFE: Sender stored as owner field
    public entry fun create_vault(ctx: &mut TxContext) {
        let vault = Vault {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            balance: 0,
        };
        transfer::share_object(vault);
        // Sender stored as owner - NOT randomness
    }

    /// SAFE: Sender in conditional without arithmetic
    public entry fun check_admin(expected: address, ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        if (sender == expected) {
            // Admin logic
        };
        // Comparison only - NOT randomness
    }

    /// SAFE: Sender passed to auth helper
    public entry fun withdraw_via_helper(vault: &mut Vault, amount: u64, ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        verify_and_withdraw(vault, sender, amount);
    }

    fun verify_and_withdraw(vault: &mut Vault, caller: address, amount: u64) {
        assert!(vault.owner == caller, 0);
        vault.balance = vault.balance - amount;
        // Sender used for auth in helper - NOT randomness
    }

    /// SAFE: Sender used in event emission (identity, not randomness)
    public entry fun log_action(ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        // sui::event::emit(ActionEvent { actor: sender });
        // Sender in event - NOT randomness
    }
}
