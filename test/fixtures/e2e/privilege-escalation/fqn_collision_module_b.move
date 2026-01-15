/// Privilege Escalation - FQN Collision Test (Module B)
/// Same-named caps but different semantics (NOT privileged)

module test::module_b {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// NOT privileged (multiple fields = user asset, not admin cap)
    public struct OperatorCap has key {
        id: UID,
        value: u64,  // Additional field makes it NOT a privileged role
    }

    /// Init creates shared OperatorCap (not transferred to sender = not privileged)
    fun init(ctx: &mut TxContext) {
        let cap = OperatorCap {
            id: object::new(ctx),
            value: 100,
        };
        transfer::share_object(cap);  // Shared, not transferred to sender
    }

    /// SAFE: Creates module_b::OperatorCap (NOT privileged, so no escalation)
    /// Should NOT be flagged (module_b::OperatorCap is not privileged)
    public entry fun create_operator(recipient: address, ctx: &mut TxContext) {
        let cap = OperatorCap {
            id: object::new(ctx),
            value: 50,
        };
        transfer::transfer(cap, recipient);
    }

    /// Just another function using the same simple name "AdminCap" as module_a
    /// but with FQN test::module_a::AdminCap
    public entry fun create_with_module_a_admin(
        _admin: &test::module_a::AdminCap,
        recipient: address,
        ctx: &mut TxContext
    ) {
        let cap = OperatorCap {
            id: object::new(ctx),
            value: 200,
        };
        transfer::transfer(cap, recipient);
    }
}
