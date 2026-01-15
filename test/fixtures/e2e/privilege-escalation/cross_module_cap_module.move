/// Privilege Escalation - Cross-Module Test (Cap Module)
/// Defines the privileged capabilities used across modules

module test::cap_module {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// Privileged admin capability
    public struct AdminCap has key, store {
        id: UID,
    }

    /// Privileged operator capability (should be created only by AdminCap)
    public struct OperatorCap has key, store {
        id: UID,
    }

    /// Init creates both AdminCap and OperatorCap (both privileged)
    fun init(ctx: &mut TxContext) {
        let admin = AdminCap { id: object::new(ctx) };
        transfer::transfer(admin, tx_context::sender(ctx));

        // Create OperatorCap in init to make it privileged
        let operator = OperatorCap { id: object::new(ctx) };
        transfer::transfer(operator, tx_context::sender(ctx));
    }

    /// Helper to create OperatorCap (exported for cross-module use)
    // @expect: privilege-escalation
    public fun create_operator_cap(ctx: &mut TxContext): OperatorCap {
        OperatorCap { id: object::new(ctx) }
    }

    /// SAFE: Creates OperatorCap with AdminCap check
    public fun create_operator_with_admin(
        _admin: &AdminCap,
        ctx: &mut TxContext
    ): OperatorCap {
        create_operator_cap(ctx)
    }
}
