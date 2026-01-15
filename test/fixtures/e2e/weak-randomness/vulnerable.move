/// Test cases for weak-randomness rule.
/// Predictable values used as randomness (timestamp, epoch, sender)
module test::weak_randomness {
    use sui::clock::{Self, Clock};
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::address;

    public struct Lottery has key {
        id: UID,
        prize_pool: u64,
    }

    /// VULNERABLE: timestamp for randomness
    // @expect: weak-randomness
    public entry fun pick_winner_timestamp(clock: &Clock, ctx: &mut TxContext) {
        let random = clock::timestamp_ms(clock);  // Predictable!
        let winner_index = random % 100;
        // Use winner_index to select winner
    }

    /// VULNERABLE: epoch for randomness
    // @expect: weak-randomness
    public entry fun pick_winner_epoch(ctx: &mut TxContext) {
        let random = tx_context::epoch(ctx);  // Same for entire epoch!
        let winner_index = random % 100;
        // Attacker can predict outcome
    }

    /// VULNERABLE: sender address for randomness
    // @expect: weak-randomness
    public entry fun pick_winner_sender(ctx: &mut TxContext) {
        let random_addr = tx_context::sender(ctx);
        let winner_index = (address::to_u256(random_addr) as u64) % 100;
    }

    /// VULNERABLE: epoch timestamp combination (still weak)
    // @expect: weak-randomness
    public entry fun pick_winner_combined(clock: &Clock, ctx: &mut TxContext) {
        let t = clock::timestamp_ms(clock);
        let e = tx_context::epoch(ctx);
        let random = (t + e) % 1000;  // Still predictable
    }

    /// SAFE: Uses sui::random
    public entry fun pick_winner_safe(r: &sui::random::Random, ctx: &mut TxContext) {
        let mut gen = sui::random::new_generator(r, ctx);
        let random = sui::random::generate_u64(&mut gen);
        let _ = random % 100;
    }

    /// VULNERABLE: timestamp XOR (still predictable)
    // @expect: weak-randomness
    public entry fun pick_winner_timestamp_xor(clock: &Clock, ctx: &mut TxContext) {
        let t = clock::timestamp_ms(clock);
        let seed = t ^ 0xDEADBEEF;
        let winner = seed % 100;
    }

    /// VULNERABLE: timestamp division for slot selection
    // @expect: weak-randomness
    public entry fun select_slot_timestamp(clock: &Clock, ctx: &mut TxContext) {
        let t = clock::timestamp_ms(clock);
        let slot = (t / 1000) % 10;  // "Random" slot every second
    }

    /// VULNERABLE: epoch for round-robin selection
    // @expect: weak-randomness
    public entry fun select_validator_epoch(ctx: &mut TxContext) {
        let e = tx_context::epoch(ctx);
        let validator_idx = e % 21;  // "Random" validator
    }

    /// VULNERABLE: timestamp multiplication (obfuscated)
    // @expect: weak-randomness
    public entry fun obfuscated_timestamp(clock: &Clock, ctx: &mut TxContext) {
        let t = clock::timestamp_ms(clock);
        let scrambled = (t * 31337) % 1000000;
        let winner = scrambled % 50;
    }

    /// VULNERABLE: digest for randomness
    // @expect: weak-randomness
    public entry fun pick_winner_digest(ctx: &mut TxContext) {
        let d = tx_context::digest(ctx);
        // Digest is bytes, but using it as seed is still predictable post-submission
    }

    /// VULNERABLE: timestamp for NFT trait assignment
    // @expect: weak-randomness
    public entry fun mint_random_nft(clock: &Clock, ctx: &mut TxContext) {
        let t = clock::timestamp_ms(clock);
        let rarity = t % 4;  // 0=common, 1=uncommon, 2=rare, 3=legendary
        // Attacker times mint to get legendary
    }

    /// VULNERABLE: epoch for airdrop distribution
    // @expect: weak-randomness
    public entry fun distribute_airdrop(ctx: &mut TxContext) {
        let e = tx_context::epoch(ctx);
        let recipient_idx = e % 1000;  // "Random" recipient
        // Predictable - attacker knows epoch
    }

    /// VULNERABLE: timestamp for lottery ticket
    // @expect: weak-randomness
    public entry fun generate_ticket_number(clock: &Clock, ctx: &mut TxContext) {
        let t = clock::timestamp_ms(clock);
        let ticket = t % 1000000;  // 6-digit ticket number
        // Miner can manipulate timestamp
    }

    /// VULNERABLE: timestamp for card shuffle seed
    // @expect: weak-randomness
    public entry fun shuffle_deck(clock: &Clock, ctx: &mut TxContext) {
        let seed = clock::timestamp_ms(clock);
        let first_card = seed % 52;
        // Entire shuffle is predictable from timestamp
    }

    /// VULNERABLE: epoch + timestamp for "better" randomness (still weak)
    // @expect: weak-randomness
    public entry fun pick_winner_double_weak(clock: &Clock, ctx: &mut TxContext) {
        let t = clock::timestamp_ms(clock);
        let e = tx_context::epoch(ctx);
        let seed = (t * e) % 10000;  // Multiplying weak sources doesn't help
        let winner = seed % 100;
    }

    /// VULNERABLE: timestamp for game dice roll
    // @expect: weak-randomness
    public entry fun roll_game_dice(clock: &Clock, ctx: &mut TxContext) {
        let t = clock::timestamp_ms(clock);
        let dice1 = (t % 6) + 1;
        let dice2 = ((t / 6) % 6) + 1;
        // Both dice predictable
    }

    /// VULNERABLE: timestamp for raffle entry selection
    // @expect: weak-randomness
    public entry fun select_raffle_winner(clock: &Clock, num_entries: u64, ctx: &mut TxContext) {
        let t = clock::timestamp_ms(clock);
        let winner_idx = t % num_entries;
        // Raffle completely riggable
    }
}
