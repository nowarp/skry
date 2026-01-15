/// Safe test cases - all events are emitted
module test::orphan_event_safe {
    use sui::event;
    use sui::tx_context::TxContext;

    public struct ActionEvent has copy, drop {
        action_type: u64,
    }

    public struct CompletionEvent has copy, drop {
        success: bool,
    }

    /// Emits ActionEvent
    public entry fun do_action(ctx: &mut TxContext) {
        event::emit(ActionEvent { action_type: 1 });
    }

    /// Emits CompletionEvent
    public entry fun complete(success: bool, ctx: &mut TxContext) {
        event::emit(CompletionEvent { success });
    }

    /// Emits both
    public entry fun complex_action(ctx: &mut TxContext) {
        event::emit(ActionEvent { action_type: 2 });
        event::emit(CompletionEvent { success: true });
    }
}

/// Test case: struct with copy+drop used as return type is NOT an event
/// This was a FP - SwapResult-like structs flagged as orphan events
module test::data_transfer_struct {
    /// NOT AN EVENT: used as return type, never emitted
    public struct SwapResult has copy, drop {
        amount_in: u64,
        amount_out: u64,
        fee: u64,
    }

    /// Returns SwapResult - this makes it a data transfer struct, not an event
    public fun calculate_swap(amount: u64): SwapResult {
        SwapResult { amount_in: amount, amount_out: amount * 2, fee: 1 }
    }

    /// Uses SwapResult fields
    public fun get_output(result: &SwapResult): u64 {
        result.amount_out
    }
}

/// Test case: event emitted via wrapper function (like emit_event helper)
/// This is a common pattern in real projects
module test::orphan_event_wrapper {
    use sui::event;
    use sui::tx_context::TxContext;

    /// USED: event emitted via wrapper function
    public struct CreateEvent has copy, drop {
        creator: address,
    }

    /// USED: event emitted via wrapper function
    public struct MintEvent has copy, drop {
        amount: u64,
    }

    /// Wrapper for CreateEvent
    public fun emit_create_event(creator: address) {
        event::emit(CreateEvent { creator });
    }

    /// Wrapper for MintEvent
    public fun emit_mint_event(amount: u64) {
        event::emit(MintEvent { amount });
    }

    /// Uses wrapper to emit CreateEvent
    public entry fun create(ctx: &mut TxContext) {
        emit_create_event(@0x1);
    }

    /// Uses wrapper to emit MintEvent
    public entry fun mint(amount: u64, ctx: &mut TxContext) {
        emit_mint_event(amount);
    }
}
