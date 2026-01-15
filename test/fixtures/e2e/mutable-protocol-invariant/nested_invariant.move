// Test case: Nested protocol invariant field modification
// Should trigger mutable-protocol-invariant rule
module test::nested_invariant {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    public struct TokenConfig has store, drop {
        decimals: u8,
        symbol: vector<u8>,
    }

    public struct Token has key {
        id: UID,
        config: TokenConfig,  // config.decimals is protocol invariant
        balance: u64,
    }

    public struct AdminCap has key, store { id: UID }

    fun init(ctx: &mut TxContext) {
        let token = Token {
            id: object::new(ctx),
            config: TokenConfig { decimals: 9, symbol: b"TEST" },
            balance: 0,
        };
        sui::transfer::share_object(token);

        let admin = AdminCap { id: object::new(ctx) };
        sui::transfer::transfer(admin, sui::tx_context::sender(ctx));
    }

    // @expect: mutable-protocol-invariant
    public fun update_config(_: &AdminCap, token: &mut Token, new_decimals: u8) {
        token.config.decimals = new_decimals;  // Modifying nested protocol invariant!
    }

    // Safe: only reads config
    public fun get_decimals(token: &Token): u8 {
        token.config.decimals
    }
}
