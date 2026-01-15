/// Privilege Escalation - IPA Test
/// Tests that privilege escalation is detected through helper call chains

module test::privilege_escalation_ipa {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// Privileged admin capability
    public struct AdminCap has key {
        id: UID,
    }

    /// Another privileged capability (should be created only by AdminCap holders)
    public struct OperatorCap has key {
        id: UID,
    }

    /// Init creates both AdminCap and OperatorCap (both transferred to sender)
    /// This makes BOTH capabilities privileged
    fun init(ctx: &mut TxContext) {
        let admin = AdminCap { id: object::new(ctx) };
        transfer::transfer(admin, tx_context::sender(ctx));

        // Also create OperatorCap in init to make it privileged
        let operator = OperatorCap { id: object::new(ctx) };
        transfer::transfer(operator, tx_context::sender(ctx));
    }

    /// VULNERABLE: Public function creates OperatorCap through helper chain
    /// without requiring AdminCap (privilege escalation via IPA)
    // @expect: privilege-escalation
    public entry fun create_operator_unsafe(recipient: address, ctx: &mut TxContext) {
        let cap = create_cap_helper(ctx);
        send_cap_helper(cap, recipient);
    }

    /// Helper that creates the capability (transitive creation)
    fun create_cap_helper(ctx: &mut TxContext): OperatorCap {
        OperatorCap { id: object::new(ctx) }
    }

    /// Helper that transfers the capability
    fun send_cap_helper(cap: OperatorCap, recipient: address) {
        transfer::transfer(cap, recipient);
    }

    /// SAFE: Requires AdminCap to create OperatorCap
    public entry fun create_operator_safe(
        _admin: &AdminCap,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let cap = OperatorCap { id: object::new(ctx) };
        transfer::transfer(cap, recipient);
    }
}
