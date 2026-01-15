/// Simplified version of Kahoot's create_quiz to reproduce FPs.
/// Source: projects/sui/Iwetan77__Kahoot/sources/kahoot.move:103
module test::kahoot_fp {
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use sui::table::{Self, Table};
    use sui::clock::{Self, Clock};
    use std::string::{Self, String};

    public struct QuizRegistry has key {
        id: UID,
        quizzes: Table<address, bool>,
        quiz_count: u64,
    }

    public struct Quiz has key, store {
        id: UID,
        creator: address,
        title: String,
        description: String,
        prize_pool: Balance<SUI>,
        total_prize: u64,
        created_at: u64,
    }

    fun init(ctx: &mut TxContext) {
        let registry = QuizRegistry {
            id: object::new(ctx),
            quizzes: table::new(ctx),
            quiz_count: 0,
        };
        transfer::share_object(registry);
    }

    /// Reproduces FPs from Kahoot's create_quiz function.
    /// This is an open-creation pattern that is safe:
    /// - Anyone can create a quiz with their own funds
    /// - Quiz creator becomes owner (creator field)
    /// - Registry is just tracking, not privileged state
    /// - Timestamp is for records, not randomness
    // @false-positive: weak-randomness
    public entry fun create_quiz(
        registry: &mut QuizRegistry,
        title: vector<u8>,
        description: vector<u8>,
        mut prize_coins: vector<Coin<SUI>>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Merge all prize coins (user's own funds)
        let mut total_balance = balance::zero<SUI>();
        let mut i = 0;
        while (i < vector::length(&prize_coins)) {
            let coin = vector::pop_back(&mut prize_coins);
            balance::join(&mut total_balance, coin::into_balance(coin));
            i = i + 1;
        };
        vector::destroy_empty(prize_coins);

        let total_prize = balance::value(&total_balance);

        // Create quiz
        let quiz_id = object::new(ctx);
        let quiz_address = object::uid_to_address(&quiz_id);

        let quiz = Quiz {
            id: quiz_id,
            creator: tx_context::sender(ctx),
            title: string::utf8(title),
            description: string::utf8(description),
            prize_pool: total_balance,
            total_prize,
            created_at: clock::timestamp_ms(clock),
        };

        // Register quiz
        table::add(&mut registry.quizzes, quiz_address, true);
        registry.quiz_count = registry.quiz_count + 1;

        // Share the quiz object
        transfer::share_object(quiz);
    }
}
