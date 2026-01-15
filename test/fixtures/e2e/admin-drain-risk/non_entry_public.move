/// Test: Non-entry public functions
/// Rule matches (fun :public :entry) - what about public non-entry?
module test::non_entry {
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

    /// NOT FLAGGED: Public but not entry
    /// This can be called from another module's entry point
    /// Should this be flagged? Currently rule skips non-entry
    /// Marking as @safe because rule intentionally matches :entry only
    public fun public_non_entry_drain(
        _admin: &AdminCap,
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let amount = sui::balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// VULNERABLE: Entry function that delegates to non-entry helper
    /// The entry IS flagged, testing IPA propagation
    // @expect: admin-drain-risk
    public entry fun entry_calls_public(
        _admin: &AdminCap,
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        public_non_entry_drain(_admin, vault, recipient, ctx);
    }

    /// NOT FLAGGED: Private function (correct - not callable externally)
    fun private_drain(
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let amount = sui::balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// VULNERABLE: Entry calls private helper
    // @expect: admin-drain-risk
    public entry fun entry_calls_private(
        _admin: &AdminCap,
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        private_drain(vault, recipient, ctx);
    }

    /// Friend function (package-level visibility)
    public(package) fun package_drain(
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
