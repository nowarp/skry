/// Capability Leakage - Friend Visibility Test
/// Tests that public(friend) functions should NOT trigger capability-leakage
/// because they are internal-only (callable only by friend modules)

module test::capability_leakage_friend {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// Privileged admin capability
    public struct AdminCap has key {
        id: UID,
    }

    /// Init creates AdminCap (transferred to sender) - establishes it as privileged
    fun init(ctx: &mut TxContext) {
        let admin = AdminCap { id: object::new(ctx) };
        transfer::transfer(admin, tx_context::sender(ctx));
    }

    /// SAFE: public(friend) is internal visibility - only callable by friend modules.
    /// Should NOT be flagged as capability leakage.
    public(friend) fun new_admin_cap(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }

    /// SAFE: Another public(friend) function returning privileged cap
    public(friend) fun create_cap_internal(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }

    /// VULNERABLE: public function returning privileged cap - SHOULD be flagged
    // @expect: capability-leakage
    public fun get_admin_cap_public(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }
}
