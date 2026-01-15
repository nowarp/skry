/// Test cases for orphan-event rule.
/// Event struct defined but never emitted
module test::orphan_event {
    use sui::event;
    use sui::tx_context::TxContext;

    /// ORPHAN: Never emitted
    // @expect: orphan-event
    public struct UnusedEvent has copy, drop {
        amount: u64,
        user: address,
    }

    /// ORPHAN: Another unused event
    // @expect: orphan-event
    public struct AnotherUnusedEvent has copy, drop {
        data: vector<u8>,
    }

    /// USED: This event is emitted
    public struct WithdrawEvent has copy, drop {
        amount: u64,
    }

    /// USED: This event is also emitted
    public struct DepositEvent has copy, drop {
        amount: u64,
    }

    public entry fun withdraw(amount: u64, ctx: &mut TxContext) {
        event::emit(WithdrawEvent { amount });
    }

    public entry fun deposit(amount: u64, ctx: &mut TxContext) {
        event::emit(DepositEvent { amount });
    }

    /// Doesn't emit UnusedEvent or AnotherUnusedEvent
    public entry fun process(ctx: &mut TxContext) {
        // No event emission
    }
}
