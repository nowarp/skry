/// Privilege Escalation - FQN Collision Test (Module A)
/// Tests that FQN resolution correctly distinguishes same-named caps

module test::module_a {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// Privileged AdminCap in module A
    public struct AdminCap has key {
        id: UID,
    }

    /// Privileged OperatorCap in module A
    public struct OperatorCap has key {
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

    /// VULNERABLE: Creates OperatorCap without AdminCap check
    /// Should be flagged (module_a::OperatorCap is privileged)
    // @expect: privilege-escalation
    public entry fun create_operator_unsafe(recipient: address, ctx: &mut TxContext) {
        let cap = OperatorCap { id: object::new(ctx) };
        transfer::transfer(cap, recipient);
    }

    /// SAFE: Creates OperatorCap with AdminCap check
    public entry fun create_operator_safe(
        _admin: &AdminCap,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let cap = OperatorCap { id: object::new(ctx) };
        transfer::transfer(cap, recipient);
    }
}
