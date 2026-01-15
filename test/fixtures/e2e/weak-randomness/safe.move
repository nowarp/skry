/// Safe test cases - proper randomness
module test::weak_randomness_safe {
    use sui::clock::{Self, Clock};
    use sui::tx_context::{Self, TxContext};
    use sui::random::{Self, Random};

    /// Uses sui::random properly
    public entry fun pick_winner(r: &Random, ctx: &mut TxContext) {
        let mut gen = random::new_generator(r, ctx);
        let random = random::generate_u64(&mut gen);
        let _ = random % 100;
    }

    /// Uses sui::random for boolean
    public entry fun flip_coin(r: &Random, ctx: &mut TxContext) {
        let mut gen = random::new_generator(r, ctx);
        let _ = random::generate_bool(&mut gen);
    }

    /// Uses sui::random for range
    public entry fun roll_dice(r: &Random, ctx: &mut TxContext) {
        let mut gen = random::new_generator(r, ctx);
        let _ = random::generate_u64_in_range(&mut gen, 1, 7);
    }

    /// SAFE: timestamp for logging/timing, not randomness
    /// FP: Rule flags ALL timestamp usage, not just randomness patterns
    // @false-positive: weak-randomness (no modulo/arithmetic - just timing)
    public entry fun record_timestamp(clock: &Clock) {
        let time = clock::timestamp_ms(clock);
        // Logging, expiry check, timing - NOT randomness
    }

    /// SAFE: timestamp for expiry check
    // @false-positive: weak-randomness (comparison, not randomness)
    public entry fun check_expiry(clock: &Clock, deadline: u64) {
        let now = clock::timestamp_ms(clock);
        assert!(now < deadline, 0);  // Expiry check - NOT randomness
    }

    /// SAFE: timestamp stored in struct (audit trail)
    // @false-positive: weak-randomness (stored for record, not randomness)
    public entry fun record_action_time(clock: &Clock) {
        let timestamp = clock::timestamp_ms(clock);
        // Would store in struct: Record { timestamp, ... }
    }

    /// SAFE: epoch for upgrade gating
    // @false-positive: weak-randomness (comparison, not randomness)
    public entry fun check_upgrade_epoch(min_epoch: u64, ctx: &mut TxContext) {
        let current = tx_context::epoch(ctx);
        assert!(current >= min_epoch, 0);  // Epoch gate - NOT randomness
    }

    /// SAFE: timestamp comparison for time-lock
    // @false-positive: weak-randomness (comparison, not randomness)
    public entry fun check_timelock(clock: &Clock, unlock_time: u64) {
        let now = clock::timestamp_ms(clock);
        assert!(now >= unlock_time, 0);  // Time-lock - NOT randomness
    }
}
