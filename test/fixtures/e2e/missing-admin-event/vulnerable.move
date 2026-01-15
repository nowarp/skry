/// Test cases for missing-admin-event rule.
/// Privileged functions that modify state without emitting events.
module test::missing_admin_event {
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::transfer;
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

    /// VULNERABLE: Admin withdraws fees without event
    // @expect: missing-admin-event
    public fun withdraw_fees(
        _admin: &AdminCap,
        protocol: &mut Protocol,
        ctx: &mut TxContext
    ): Coin<SUI> {
        let amount = balance::value(&protocol.fee_balance);
        coin::take(&mut protocol.fee_balance, amount, ctx)
    }

    /// Pure config setter - excluded from rule (low audit value)
    // @safe: missing-admin-event
    public fun set_fee_rate(
        _admin: &AdminCap,
        protocol: &mut Protocol,
        new_rate: u64
    ) {
        protocol.fee_rate = new_rate;
    }

    /// VULNERABLE: Admin transfers fees to recipient without event
    // @expect: missing-admin-event
    public entry fun transfer_fees(
        _admin: &AdminCap,
        protocol: &mut Protocol,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let amount = balance::value(&protocol.fee_balance);
        let coins = coin::take(&mut protocol.fee_balance, amount, ctx);
        transfer::public_transfer(coins, recipient);
    }
}
