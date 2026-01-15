/// Safe cases for missing-admin-event rule.
/// Privileged functions that properly emit events.
module test::missing_admin_event_safe {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::transfer;
    use sui::event;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    public struct AdminCap has key, store {
        id: UID,
    }

    public struct Protocol has key {
        id: UID,
        fee_balance: Balance<SUI>,
        fee_rate: u64,
        paused: bool,
    }

    /// Initialize and share the protocol
    fun init(ctx: &mut TxContext) {
        let admin_cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(admin_cap, tx_context::sender(ctx));

        let protocol = Protocol {
            id: object::new(ctx),
            fee_balance: balance::zero(),
            fee_rate: 100,
            paused: false,
        };
        transfer::share_object(protocol);
    }

    /// Event emitted when fees are withdrawn
    public struct FeesWithdrawn has copy, drop {
        amount: u64,
    }

    /// Event emitted when fee rate is changed
    public struct FeeRateChanged has copy, drop {
        old_rate: u64,
        new_rate: u64,
    }

    /// SAFE: Admin withdraws fees WITH event
    // @safe: missing-admin-event
    public fun withdraw_fees(
        _admin: &AdminCap,
        protocol: &mut Protocol,
        ctx: &mut TxContext
    ): Coin<SUI> {
        let amount = balance::value(&protocol.fee_balance);
        event::emit(FeesWithdrawn { amount });
        coin::take(&mut protocol.fee_balance, amount, ctx)
    }

    /// SAFE: Admin changes fee rate WITH event
    // @safe: missing-admin-event
    public fun set_fee_rate(
        _admin: &AdminCap,
        protocol: &mut Protocol,
        new_rate: u64
    ) {
        let old_rate = protocol.fee_rate;
        protocol.fee_rate = new_rate;
        event::emit(FeeRateChanged { old_rate, new_rate });
    }

    /// SAFE: Non-privileged function (no capability check)
    // @safe: missing-admin-event
    public fun get_fee_rate(protocol: &Protocol): u64 {
        protocol.fee_rate
    }

    /// Pause control function - now excluded (pure state write, no theft sink)
    // @safe: missing-admin-event
    public fun pause(
        _admin: &AdminCap,
        protocol: &mut Protocol
    ) {
        protocol.paused = true;
    }
}
