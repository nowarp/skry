/// Cross-module sender test - A (entry) calls B
module test::weak_randomness_sender_hop_a {
    use sui::tx_context::{Self, TxContext};
    use sui::address;
    use test::weak_randomness_sender_hop_b;

    /// VULNERABLE: Entry gets sender, casts to u64, passes to B
    // @expect: weak-randomness
    public entry fun start_sender_lottery(ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        let seed = (address::to_u256(sender) as u64);
        weak_randomness_sender_hop_b::process_seed(seed);
    }
}
