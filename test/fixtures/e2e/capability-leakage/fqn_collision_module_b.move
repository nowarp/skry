/// Capability Leakage - FQN Collision Test (Module B)
/// Same-named cap but NOT privileged (no leakage concern)

module test::module_b {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// NOT privileged (multi-field struct = user asset)
    public struct AdminCap has key {
        id: UID,
        value: u64,  // Additional field makes it NOT privileged
    }

    /// Init shares AdminCap (not transferred to sender = not privileged)
    fun init(ctx: &mut TxContext) {
        let cap = AdminCap {
            id: object::new(ctx),
            value: 100,
        };
        transfer::share_object(cap);  // Shared, not transferred
    }

    /// SAFE: Returns module_b::AdminCap (NOT privileged, so no leakage)
    /// FALSE POSITIVE: Rule incorrectly classifies module_b::AdminCap as privileged
    /// Should NOT be flagged (module_b::AdminCap is not privileged)
    // @expect: capability-leakage
    public fun get_admin_cap(ctx: &mut TxContext): AdminCap {
        AdminCap {
            id: object::new(ctx),
            value: 50,
        }
    }

    /// Transfers module_b::AdminCap to arbitrary recipient
    // @expect: capability-leakage
    public entry fun transfer_cap(recipient: address, ctx: &mut TxContext) {
        let cap = AdminCap {
            id: object::new(ctx),
            value: 200,
        };
        transfer::transfer(cap, recipient);
    }

    /// Uses module_a::AdminCap (the privileged one)
    /// VULNERABLE: Leaks module_a::AdminCap even though called from module_b
    // @expect: capability-leakage
    public entry fun leak_other_module_cap(recipient: address, ctx: &mut TxContext) {
        let cap = test::module_a::get_admin_cap(ctx);
        transfer::public_transfer(cap, recipient);
    }
}
