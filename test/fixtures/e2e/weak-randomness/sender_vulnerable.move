/// Sender-as-randomness vulnerable cases
/// These MUST be detected - sender used for randomness is weak
module test::weak_randomness_sender_vuln {
    use sui::tx_context::{Self, TxContext};
    use sui::address;

    /// VULNERABLE: Direct sender modulo - classic lottery attack
    // @expect: weak-randomness
    public entry fun pick_winner_sender(ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        let winner_index = (address::to_u256(sender) as u64) % 100;
        // Attacker can grind addresses to win
    }

    /// VULNERABLE: Sender combined with epoch (detected via epoch, not sender)
    // @expect: weak-randomness
    public entry fun pick_winner_sender_combined(ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        let epoch = tx_context::epoch(ctx);
        let random = ((address::to_u256(sender) as u64) + epoch) % 1000;
        // Detected because epoch is weak - sender issue masked
    }

    /// VULNERABLE: Sender XOR'd (still predictable)
    // @expect: weak-randomness
    public entry fun pick_winner_sender_xor(ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        let seed = (address::to_u256(sender) as u64) ^ 0xDEADBEEF;
        let winner = seed % 50;
        // XOR with constant doesn't add entropy
    }

    /// VULNERABLE: IPA - sender flows to helper
    // @expect: weak-randomness
    public entry fun pick_winner_sender_ipa(ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        let seed = (address::to_u256(sender) as u64);
        select_winner(seed);
    }

    fun select_winner(seed: u64) {
        let winner = seed % 100;
        // Still weak - derived from sender
    }

    /// VULNERABLE: Two-hop IPA with sender
    // @expect: weak-randomness
    public entry fun lottery_sender_twohop(ctx: &mut TxContext) {
        let sender = tx_context::sender(ctx);
        process_sender((address::to_u256(sender) as u64));
    }

    fun process_sender(value: u64) {
        finalize_lottery(value);
    }

    fun finalize_lottery(seed: u64) {
        let result = seed % 1000;
        // Weak randomness propagated through call chain
    }
}
