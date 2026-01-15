/// Test: Deep call chains (4+ hops)
/// Tests IPA propagation depth for admin-drain-risk detection
module test::deep_chain {
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

    // === 4-hop chain: entry -> hop1 -> hop2 -> hop3 -> drain ===

    /// Final drain function (hop 4)
    fun do_drain(vault: &mut UserVault, recipient: address, ctx: &mut TxContext) {
        let amount = sui::balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }

    /// Hop 3: calls drain
    fun hop3(vault: &mut UserVault, recipient: address, ctx: &mut TxContext) {
        do_drain(vault, recipient, ctx);
    }

    /// Hop 2: calls hop3
    fun hop2(vault: &mut UserVault, recipient: address, ctx: &mut TxContext) {
        hop3(vault, recipient, ctx);
    }

    /// Hop 1: calls hop2
    fun hop1(vault: &mut UserVault, recipient: address, ctx: &mut TxContext) {
        hop2(vault, recipient, ctx);
    }

    /// VULNERABLE: 4-hop chain (entry -> hop1 -> hop2 -> hop3 -> drain)
    /// Tests if IPA propagates TransferSink through 4 levels
    // @expect: admin-drain-risk
    public entry fun deep_chain_4_hops(
        _admin: &AdminCap,
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        hop1(vault, recipient, ctx);
    }

    // === 5-hop chain ===

    /// Hop 4 for 5-hop chain
    fun hop4_deep(vault: &mut UserVault, recipient: address, ctx: &mut TxContext) {
        do_drain(vault, recipient, ctx);
    }

    /// Hop 3 for 5-hop chain
    fun hop3_deep(vault: &mut UserVault, recipient: address, ctx: &mut TxContext) {
        hop4_deep(vault, recipient, ctx);
    }

    /// Hop 2 for 5-hop chain
    fun hop2_deep(vault: &mut UserVault, recipient: address, ctx: &mut TxContext) {
        hop3_deep(vault, recipient, ctx);
    }

    /// Hop 1 for 5-hop chain
    fun hop1_deep(vault: &mut UserVault, recipient: address, ctx: &mut TxContext) {
        hop2_deep(vault, recipient, ctx);
    }

    /// VULNERABLE: 5-hop chain
    /// Tests IPA depth limits
    // @expect: admin-drain-risk
    public entry fun deep_chain_5_hops(
        _admin: &AdminCap,
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        hop1_deep(vault, recipient, ctx);
    }

    // === Mixed depth: privilege in middle of chain ===

    /// Deep hop with privilege check
    fun privileged_hop(_admin: &AdminCap, vault: &mut UserVault, recipient: address, ctx: &mut TxContext) {
        do_drain(vault, recipient, ctx);
    }

    /// Wrapper that doesn't check privilege
    fun unprivileged_wrapper(admin: &AdminCap, vault: &mut UserVault, recipient: address, ctx: &mut TxContext) {
        privileged_hop(admin, vault, recipient, ctx);
    }

    /// VULNERABLE: Entry -> unprivileged_wrapper -> privileged_hop -> drain
    /// Privilege check is in the middle of chain
    // @expect: admin-drain-risk
    public entry fun privilege_mid_chain(
        admin: &AdminCap,
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        unprivileged_wrapper(admin, vault, recipient, ctx);
    }

    // === Branching chain: multiple callees at different depths ===

    /// Branch A: drains to recipient
    fun branch_a(vault: &mut UserVault, recipient: address, ctx: &mut TxContext) {
        do_drain(vault, recipient, ctx);
    }

    /// Branch B: drains to owner (safe)
    fun branch_b(vault: &mut UserVault, ctx: &mut TxContext) {
        let amount = sui::balance::value(&vault.balance);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, vault.owner);
    }

    /// Dispatcher: calls both branches
    fun dispatch(vault: &mut UserVault, recipient: address, use_a: bool, ctx: &mut TxContext) {
        if (use_a) {
            branch_a(vault, recipient, ctx);
        } else {
            branch_b(vault, ctx);
        }
    }

    /// VULNERABLE: Has unsafe branch even though safe branch exists
    // @expect: admin-drain-risk
    public entry fun branching_chain(
        _admin: &AdminCap,
        vault: &mut UserVault,
        recipient: address,
        use_a: bool,
        ctx: &mut TxContext
    ) {
        dispatch(vault, recipient, use_a, ctx);
    }

    // === Recursive chain (bounded) ===

    /// Recursive drain with counter
    fun recursive_drain(vault: &mut UserVault, recipient: address, depth: u64, ctx: &mut TxContext) {
        if (depth == 0) {
            let amount = sui::balance::value(&vault.balance);
            let coins = coin::take(&mut vault.balance, amount, ctx);
            transfer::public_transfer(coins, recipient);
        } else {
            recursive_drain(vault, recipient, depth - 1, ctx);
        }
    }

    /// VULNERABLE: Recursive call chain
    /// Tests if analyzer handles recursion
    // @expect: admin-drain-risk
    public entry fun recursive_chain(
        _admin: &AdminCap,
        vault: &mut UserVault,
        recipient: address,
        ctx: &mut TxContext
    ) {
        recursive_drain(vault, recipient, 3, ctx);
    }
}
