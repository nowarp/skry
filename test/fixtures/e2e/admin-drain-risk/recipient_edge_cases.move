/// Test: Transfer recipient edge cases
/// Tests various recipient patterns that should/shouldn't be flagged
module test::recipient_edge {
    use sui::coin::{Self, Coin};
    use sui::balance::Balance;
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    const TREASURY: address = @0x1234567890abcdef;
    const ZERO_ADDR: address = @0x0;

    public struct AdminCap has key, store {
        id: UID,
    }

    public struct UserVault has key {
        id: UID,
        owner: address,
        balance: Balance<SUI>,
    }

    /// SAFE: Transfer to hardcoded treasury address (not tainted)
    /// Tests if constant recipient is detected as safe
    public entry fun admin_to_treasury(
        _admin: &AdminCap,
        vault: &mut UserVault,
        ctx: &mut TxContext
    ) {
        let amount = sui::balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, TREASURY);
    }

    /// SAFE: Transfer to sender (admin gets their own deposit back)
    /// Tests if transfers-from-sender is detected
    public entry fun admin_to_self(
        _admin: &AdminCap,
        vault: &mut UserVault,
        ctx: &mut TxContext
    ) {
        let amount = sui::balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Transfer to vault owner field
    /// Tests if owner field access is detected as safe recipient
    public entry fun admin_to_owner(
        _admin: &AdminCap,
        vault: &mut UserVault,
        ctx: &mut TxContext
    ) {
        let amount = sui::balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, vault.owner);
    }

    /// SAFE: Transfer to object ID address
    /// Sending to object address (not a user address)
    public entry fun admin_to_object_id(
        _admin: &AdminCap,
        vault: &mut UserVault,
        ctx: &mut TxContext
    ) {
        let amount = sui::balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        let vault_addr = object::id_address(vault);
        transfer::public_transfer(coins, vault_addr);
    }

    /// VULNERABLE: Transfer to arbitrary recipient parameter
    // @expect: admin-drain-risk
    public entry fun admin_to_arbitrary(
        _admin: &AdminCap,
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let amount = sui::balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }
}
