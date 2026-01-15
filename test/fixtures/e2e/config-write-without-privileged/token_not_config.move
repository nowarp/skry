/// Test that token/treasury structs are NOT classified as config.
/// These have supply tracking fields but should not trigger config-write rule.
module test::token_metadata {
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};

    /// Token metadata struct - NOT a config struct
    /// Has fields like total_supply, decimals that might look config-like
    /// but this is token state tracking, not protocol configuration
    public struct TokenMetadata has key {
        id: UID,
        total_supply: u64,
        burned: u64,
        fee_wallet: address,
        decimals: u8,
        metadata: vector<u8>,
    }

    /// Admin capability
    public struct AdminCap has key, store {
        id: UID,
    }

    /// This function modifies token supply tracking
    /// Should NOT be flagged as config-write because TokenMetadata is NOT a config struct
    public fun mint_tokens(
        token: &mut TokenMetadata,
        amount: u64,
        _cap: &AdminCap,
    ) {
        token.total_supply = token.total_supply + amount;
    }

    /// This function updates fee wallet in token metadata
    /// Should NOT be flagged because TokenMetadata is token state, not config
    public fun update_fee_wallet(
        token: &mut TokenMetadata,
        new_wallet: address,
        _cap: &AdminCap,
    ) {
        token.fee_wallet = new_wallet;
    }

    /// Init
    fun init(ctx: &mut TxContext) {
        let token = TokenMetadata {
            id: object::new(ctx),
            total_supply: 0,
            burned: 0,
            fee_wallet: @0x1,
            decimals: 9,
            metadata: vector::empty(),
        };
        transfer::share_object(token);

        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
