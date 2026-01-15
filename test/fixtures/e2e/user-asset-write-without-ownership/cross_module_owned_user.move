/// Cross-module consumer of owned Showcase.
/// Tests that owned object detection works across module boundaries.
module test::owned_showcase_user {
    use sui::bag;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use test::owned_showcase_def::{Self, Showcase};

    /// FP: Extract from owned showcase - only owner can call this
    /// Sui runtime enforces ownership via &mut Showcase requirement.
    /// Should NOT be flagged because Showcase is owned (not shared).
    public entry fun extract_from_showcase<NFT: key + store>(
        showcase: &mut Showcase,
        position: u64,
        ctx: &mut TxContext,
    ) {
        let nft: NFT = bag::remove(owned_showcase_def::nfts_mut(showcase), position);
        transfer::public_transfer(nft, tx_context::sender(ctx));
    }

    /// FP: Add to owned showcase - only owner can call this
    public entry fun add_to_showcase<NFT: key + store>(
        showcase: &mut Showcase,
        nft: NFT,
        position: u64,
        _ctx: &mut TxContext,
    ) {
        bag::add(owned_showcase_def::nfts_mut(showcase), position, nft);
    }
}
