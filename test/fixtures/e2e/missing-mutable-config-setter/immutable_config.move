// Test case: Token.decimals is immutable config (set once in init, never changed)
// Should NOT trigger missing-mutable-config-setter rule
module test::token {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    public struct Token has key {
        id: UID,
        decimals: u8,  // Immutable config - never changes after init
        total_supply: u64,
    }

    public struct AdminCap has key, store { id: UID }

    fun init(ctx: &mut TxContext) {
        let token = Token {
            id: object::new(ctx),
            decimals: 9,  // Set once, never modified
            total_supply: 1000000,
        };
        sui::transfer::share_object(token);

        let admin = AdminCap { id: object::new(ctx) };
        sui::transfer::transfer(admin, sui::tx_context::sender(ctx));
    }

    // No setter for decimals - that's OK, it's immutable
}
