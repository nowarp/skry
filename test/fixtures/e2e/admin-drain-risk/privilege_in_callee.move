/// Test: Privilege check happens in callee, not entry
/// Tests if checks-privileged? propagates via IPA
module test::priv_in_callee {
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
    }

    /// SAFE: Entry has no admin cap - rule checks entry signature for privilege
    /// Even though callee has cap, the entry itself is unprivileged
    /// This is correct - the rule is about admin drain, not unprivileged drain
    public entry fun unprivileged_entry(
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        // Can't actually call privileged_drain here without AdminCap
        // This entry is unprivileged, so it's not an admin-drain
        let _ = vault;
        let _ = recipient;
        let _ = ctx;
    }

    /// VULNERABLE: Entry has cap, passes it to callee
    /// Tests if privilege check propagates when cap is passed down
    // @expect: admin-drain-risk
    public entry fun privileged_entry_passes_cap(
        admin: &AdminCap,
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        privileged_drain(admin, vault, recipient, ctx);
    }

    /// Helper that requires AdminCap and drains
    fun privileged_drain(
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
