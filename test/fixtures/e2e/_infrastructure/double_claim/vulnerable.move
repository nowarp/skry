/// Test cases for double-claim-no-state-update rule.
/// Function takes receipt by reference, extracts value, but doesn't destroy/update state.
module test::double_claim {
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;

    /// Receipt for claimed rewards
    public struct Receipt has key, store {
        id: UID,
        amount: u64,
        claimed: bool,
    }

    /// Protocol vault
    public struct Vault has key {
        id: UID,
        balance: Balance<SUI>,
    }

    /// VULNERABLE: Takes receipt by immutable reference, extracts value, doesn't update state
    /// Attacker can call claim() multiple times with same receipt
    public entry fun claim_vulnerable(
        vault: &mut Vault,
        receipt: &Receipt,  // Immutable reference - can't update!
        ctx: &mut TxContext
    ) {
        // Extract value based on receipt
        let amount = receipt.amount;
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
        // BUG: receipt.claimed never set to true - can claim multiple times!
    }

    /// VULNERABLE: Takes receipt by mutable reference but doesn't actually update it
    public entry fun claim_no_update(
        vault: &mut Vault,
        receipt: &mut Receipt,  // Mutable but not used
        ctx: &mut TxContext
    ) {
        let amount = receipt.amount;
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
        // BUG: receipt.claimed never updated
    }

    /// SAFE: Destroys receipt after claiming
    public entry fun claim_with_destroy(
        vault: &mut Vault,
        receipt: Receipt,  // Owned - will be destroyed
        ctx: &mut TxContext
    ) {
        let Receipt { id, amount, claimed: _ } = receipt;
        object::delete(id);
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// SAFE: Updates receipt state to mark as claimed
    public entry fun claim_with_state_update(
        vault: &mut Vault,
        receipt: &mut Receipt,
        ctx: &mut TxContext
    ) {
        assert!(!receipt.claimed, 1);
        receipt.claimed = true;  // Mark as claimed
        let amount = receipt.amount;
        let coins = coin::take(&mut vault.balance, amount, ctx);
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }

    /// Regular deposit - not a claim function
    public entry fun deposit(
        vault: &mut Vault,
        coin: Coin<SUI>,
    ) {
        let amount = coin::value(&coin);
        coin::put(&mut vault.balance, coin);
    }

    fun init(ctx: &mut TxContext) {
        let vault = Vault {
            id: object::new(ctx),
            balance: balance::zero(),
        };
        transfer::share_object(vault);
    }
}
