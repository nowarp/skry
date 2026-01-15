/// Test: Mixed safe/unsafe code paths in same function
/// Tests functions with conditional behavior
module test::mixed_paths {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    public struct AdminCap has key, store {
        id: UID,
    }

    public struct UserVault has key {
        id: UID,
        owner: address,
        balance: Balance<SUI>,
        emergency_recipient: address,
    }

    /// VULNERABLE: Conditional path - one safe, one unsafe
    /// If emergency_mode, drains to arbitrary recipient
    /// Else, returns to owner
    /// Should be flagged because unsafe path exists
    // @expect: admin-drain-risk
    public entry fun conditional_drain(
        _admin: &AdminCap,
        vault: &mut UserVault,
        recipient: address,
        emergency_mode: bool,
        ctx: &mut TxContext
    ) {
        let amount = sui::balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        if (emergency_mode) {
            // UNSAFE path: arbitrary recipient
            transfer::public_transfer(coins, recipient);
        } else {
            // SAFE path: returns to owner
            transfer::public_transfer(coins, vault.owner);
        }
    }

    /// VULNERABLE: Multiple transfers - one safe, one unsafe
    // @expect: admin-drain-risk
    public entry fun split_transfer(
        _admin: &AdminCap,
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let total = sui::balance::value(&vault.balance);
        let half = total / 2;

        // First half to owner (safe)
        let coins1 = coin::take(&mut vault.balance, half, ctx);
        transfer::public_transfer(coins1, vault.owner);

        // Second half to arbitrary recipient (unsafe)
        let coins2 = coin::take(&mut vault.balance, half, ctx);
        transfer::public_transfer(coins2, recipient);
    }

    /// SAFE: All paths return to owner
    public entry fun all_safe_paths(
        _admin: &AdminCap,
        vault: &mut UserVault,
        use_stored: bool,
        ctx: &mut TxContext
    ) {
        let amount = sui::balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        if (use_stored) {
            // Both paths go to owner
            transfer::public_transfer(coins, vault.owner);
        } else {
            transfer::public_transfer(coins, vault.owner);
        }
    }
}
