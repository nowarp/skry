// Test case: NFT user asset with price field
// Spec is a user-owned object (IsUserAsset) - its fields don't need setters
// Should NOT trigger missing-mutable-config-setter rule
// @safe: missing-mutable-config-setter
module test::nft_user_asset {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    public struct AdminCap has key, store { id: UID }

    // User-owned NFT specification - created per purchase, intentionally immutable
    public struct Spec has key, store {
        id: UID,
        name: vector<u8>,
        price: u64,      // Set at creation, intentionally immutable
        supply: u64,     // Set at creation, intentionally immutable
    }

    public struct Factory has key {
        id: UID,
    }

    fun init(ctx: &mut TxContext) {
        sui::transfer::share_object(Factory { id: object::new(ctx) });
        sui::transfer::transfer(AdminCap { id: object::new(ctx) }, sui::tx_context::sender(ctx));
    }

    // Admin creates specs - they're transferred to users (not stored in protocol)
    public fun create_spec(
        _: &AdminCap,
        name: vector<u8>,
        price: u64,
        supply: u64,
        ctx: &mut TxContext
    ): Spec {
        Spec {
            id: object::new(ctx),
            name,
            price,
            supply,
        }
    }

    // User mints NFT from spec - spec is user-owned, not protocol config
    public fun mint(_factory: &mut Factory, spec: &Spec, ctx: &mut TxContext) {
        // User pays spec.price, gets NFT
        let _ = spec.price;
        let _ = ctx;
    }
}
