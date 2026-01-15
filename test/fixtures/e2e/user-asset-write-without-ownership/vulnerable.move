/// Test cases for user-asset-write-without-ownership rule.
/// Detects writes to user asset containers without verifying caller ownership.
module test::user_asset_write {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::bag::{Self, Bag};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};

    /// User vault - holds per-user assets
    public struct UserVault has key {
        id: UID,
        owner: address,
        balance: Balance<SUI>,
        data: u64,
    }

    /// Admin capability
    public struct AdminCap has key, store {
        id: UID,
    }

    /// VULNERABLE: Basic write without ownership check
    /// Attacker can modify any user's vault
    // @expect: user-asset-write-without-ownership
    public entry fun steal_modify(
        vault: &mut UserVault,
        new_data: u64,
        ctx: &mut TxContext
    ) {
        vault.data = new_data;
    }

    /// VULNERABLE: Withdraw from vault without ownership check
    /// Attacker can drain any user's vault
    // @expect: user-asset-write-without-ownership
    public entry fun steal_withdraw(
        vault: &mut UserVault,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// VULNERABLE: IPA - entry calls helper that writes
    // @expect: user-asset-write-without-ownership
    public entry fun modify_via_helper(
        vault: &mut UserVault,
        new_data: u64,
        ctx: &mut TxContext
    ) {
        do_modify(vault, new_data);
    }

    fun do_modify(vault: &mut UserVault, new_data: u64) {
        vault.data = new_data;
    }

    /// SAFE: Sender equality check (owner == sender)
    public entry fun safe_modify(
        vault: &mut UserVault,
        new_data: u64,
        ctx: &mut TxContext
    ) {
        assert!(vault.owner == tx_context::sender(ctx), 1);
        vault.data = new_data;
    }

    /// SAFE: Deposits from sender (user's own funds)
    public entry fun safe_deposit(
        vault: &mut UserVault,
        coin: Coin<SUI>,
        ctx: &mut TxContext
    ) {
        balance::join(&mut vault.balance, coin::into_balance(coin));
    }

    /// SAFE: Role check
    public entry fun admin_modify(
        vault: &mut UserVault,
        new_data: u64,
        _cap: &AdminCap,
        ctx: &mut TxContext
    ) {
        vault.data = new_data;
    }

    /// SAFE: IPA - callee has sender equality check
    public entry fun modify_via_guarded_helper(
        vault: &mut UserVault,
        new_data: u64,
        ctx: &mut TxContext
    ) {
        do_modify_guarded(vault, new_data, ctx);
    }

    fun do_modify_guarded(
        vault: &mut UserVault,
        new_data: u64,
        ctx: &mut TxContext
    ) {
        assert!(vault.owner == tx_context::sender(ctx), 1);
        vault.data = new_data;
    }

    /// Create user vault
    public entry fun create_vault(ctx: &mut TxContext) {
        let vault = UserVault {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            balance: balance::zero(),
            data: 0,
        };
        transfer::share_object(vault);
    }

    /// User can withdraw their own funds (establishes withdraw pattern)
    public entry fun user_withdraw(
        vault: &mut UserVault,
        amount: u64,
        ctx: &mut TxContext
    ) {
        assert!(vault.owner == tx_context::sender(ctx), 1);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    fun init(ctx: &mut TxContext) {
        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    // ========== Owned Object Pattern ==========
    // When user asset is OWNED (not shared), only the owner can pass &mut to functions.
    // Sui runtime enforces this - no explicit sender check needed.

    /// User-owned showcase - holds NFTs (OWNED object, not shared)
    public struct OwnedShowcase has key, store {
        id: UID,
        creator: address,
        nfts: Bag,
    }

    /// Create owned showcase - transferred to creator (NOT shared)
    public entry fun create_owned_showcase(ctx: &mut TxContext) {
        let showcase = OwnedShowcase {
            id: object::new(ctx),
            creator: tx_context::sender(ctx),
            nfts: bag::new(ctx),
        };
        transfer::transfer(showcase, tx_context::sender(ctx));  // OWNED, not share_object
    }

    /// FP: Operates on owned object - only owner can pass &mut OwnedShowcase
    /// Sui runtime enforces ownership - sender check is implicit via object ownership.
    /// Rule should filter this with operates-on-owned-only? check.
    /// NOTE: Requires IsUserAsset injection to trigger (simulates LLM classification)
    public entry fun add_to_owned_showcase<NFT: key + store>(
        showcase: &mut OwnedShowcase,
        nft: NFT,
        position: u64,
        _ctx: &mut TxContext,
    ) {
        bag::add(&mut showcase.nfts, position, nft);
    }
}
