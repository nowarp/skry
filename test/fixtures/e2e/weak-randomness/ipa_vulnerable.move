/// IPA test - vulnerable entry -> helper chain
module test::weak_randomness_ipa_vuln {
    use sui::clock::{Self, Clock};
    use sui::tx_context::{Self, TxContext};

    /// VULNERABLE: Entry gets weak random, passes to helper
    // @expect: weak-randomness
    public entry fun pick_winner(clock: &Clock, ctx: &mut TxContext) {
        let weak_random = clock::timestamp_ms(clock);  // Predictable
        select_winner(weak_random);
    }

    fun select_winner(seed: u64) {
        let winner_index = seed % 100;
        // Tainted randomness propagated through IPA
    }

    /// VULNERABLE: Two-hop weak randomness
    // @expect: weak-randomness
    public entry fun draw_lottery(ctx: &mut TxContext) {
        let epoch = tx_context::epoch(ctx);  // Weak
        process_draw(epoch);
    }

    fun process_draw(seed: u64) {
        finalize_draw(seed);
    }

    fun finalize_draw(random: u64) {
        let result = random % 1000;
        // Still using weak randomness
    }
}
