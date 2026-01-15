/// Cross-module test for owned object FP fix.
/// Module A defines an owned struct, Module B operates on it.
module test::owned_showcase_def {
    use sui::object::{Self, UID};
    use sui::bag::{Self, Bag};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// User showcase - OWNED object (transferred to sender, NOT shared)
    public struct Showcase has key, store {
        id: UID,
        creator: address,
        nfts: Bag,
    }

    /// Create owned showcase - transferred to creator
    public entry fun create_showcase(ctx: &mut TxContext) {
        let showcase = Showcase {
            id: object::new(ctx),
            creator: tx_context::sender(ctx),
            nfts: bag::new(ctx),
        };
        transfer::transfer(showcase, tx_context::sender(ctx));  // OWNED
    }

    /// Public getter for cross-module access
    public fun nfts_mut(showcase: &mut Showcase): &mut Bag {
        &mut showcase.nfts
    }
}
