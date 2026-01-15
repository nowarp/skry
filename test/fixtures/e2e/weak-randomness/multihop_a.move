/// Multihop test - A calls B
module test::weak_randomness_hop_a {
    use sui::clock::{Self, Clock};
    use sui::tx_context::TxContext;
    use test::weak_randomness_hop_b;

    /// Entry point - gets weak random and starts chain
    // @expect: weak-randomness
    public entry fun start_lottery(clock: &Clock, ctx: &mut TxContext) {
        let weak_random = clock::timestamp_ms(clock);  // Predictable
        weak_randomness_hop_b::process_random(weak_random);
    }
}
