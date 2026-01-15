// Test case: Protocol invariant field only set in init, never modified
// Should NOT trigger mutable-protocol-invariant rule
module test::token_invariant {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    public struct Token has key {
        id: UID,
        decimals: u8,  // Protocol invariant - set once in init
        total_supply: u64,
    }

    fun init(ctx: &mut TxContext) {
        let token = Token {
            id: object::new(ctx),
            decimals: 18,  // Set once, never modified
            total_supply: 0,
        };
        sui::transfer::share_object(token);
    }

    // Safe: only reads decimals
    public fun get_decimals(token: &Token): u8 {
        token.decimals
    }

    // Safe: modifies non-invariant field
    public fun mint(token: &mut Token, amount: u64) {
        token.total_supply = token.total_supply + amount;
    }
}
