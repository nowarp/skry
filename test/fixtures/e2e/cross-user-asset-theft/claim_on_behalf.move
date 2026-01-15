/// Cross-User Asset Theft - Claim On Behalf Pattern
/// Tests that "claim on behalf" functions are NOT flagged as theft.
/// Pattern: function takes account param, accesses their data, sends result TO that account.
/// This is safe because the caller CANNOT redirect assets to themselves.

module test::claim_on_behalf {
    use sui::object::{Self, UID};
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::table::{Self, Table};

    /// Registry tracking pending rewards per user (user asset container)
    public struct RewardRegistry has key {
        id: UID,
        owner: address,
        pending_rewards: Table<address, u64>,
        reward_pool: Balance<SUI>,
    }

    fun init(ctx: &mut TxContext) {
        let registry = RewardRegistry {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            pending_rewards: table::new(ctx),
            reward_pool: balance::zero(),
        };
        transfer::share_object(registry);
    }

    /// SAFE: Claim on behalf - transfers TO the account parameter, not to sender
    /// Caller cannot steal because assets go to the account whose rewards are claimed.
    /// This is the Navi Protocol pattern that was incorrectly flagged.
    // @false-positive: cross-user-asset-theft
    public entry fun claim_reward_for(
        registry: &mut RewardRegistry,
        account: address,
        ctx: &mut TxContext
    ) {
        if (table::contains(&registry.pending_rewards, account)) {
            let amount = table::remove(&mut registry.pending_rewards, account);
            let coins = coin::take(&mut registry.reward_pool, amount, ctx);
            transfer::public_transfer(coins, account);  // Goes to account, NOT sender
        }
    }

    /// VULNERABLE: Takes account param but transfers to SENDER - this IS theft!
    /// Attacker specifies victim's data source, but receives funds themselves
    // @expect: cross-user-asset-theft
    public entry fun steal_rewards(
        registry: &mut RewardRegistry,
        victim: address,
        ctx: &mut TxContext
    ) {
        if (table::contains(&registry.pending_rewards, victim)) {
            let amount = table::remove(&mut registry.pending_rewards, victim);
            let coins = coin::take(&mut registry.reward_pool, amount, ctx);
            transfer::public_transfer(coins, tx_context::sender(ctx));  // THEFT: goes to sender!
        }
    }

    /// Deposit to registry - establishes user asset container pattern
    public entry fun deposit_rewards(
        registry: &mut RewardRegistry,
        coin: Coin<SUI>,
    ) {
        balance::join(&mut registry.reward_pool, coin::into_balance(coin));
    }
}
