/// Cross-module test - entry module
module test::weak_randomness_entry {
    use sui::clock::{Self, Clock};
    use sui::tx_context::TxContext;
    use test::weak_randomness_helper;

    /// VULNERABLE: Gets weak random and passes to helper module
    // @expect: weak-randomness
    public entry fun run_lottery(clock: &Clock, ctx: &mut TxContext) {
        let weak_random = clock::timestamp_ms(clock);  // Predictable
        weak_randomness_helper::select_winner(weak_random);
    }
}
