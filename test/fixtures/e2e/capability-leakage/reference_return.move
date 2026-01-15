/// Capability Leakage - Reference Return Test
/// Tests that the rule detects when a public function returns a reference (&)
/// to a privileged capability type without authorization

module test::capability_leakage_reference {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    /// Privileged admin capability
    public struct AdminCap has key {
        id: UID,
    }

    /// Shared config that stores AdminCap
    public struct Config has key {
        id: UID,
        admin_cap: AdminCap,
    }

    fun init(ctx: &mut TxContext) {
        let admin = AdminCap { id: object::new(ctx) };
        transfer::transfer(admin, tx_context::sender(ctx));
    }

    // VULNERABLE: Returns reference to privileged cap from shared object
    // Anyone can get &AdminCap and use it for privileged operations
    // @expect: capability-leakage
    public fun get_admin_cap_ref(config: &Config): &AdminCap {
        &config.admin_cap
    }

    // VULNERABLE: Returns mutable reference to privileged cap
    // @expect: capability-leakage
    public fun get_admin_cap_mut(config: &mut Config): &mut AdminCap {
        &mut config.admin_cap
    }

    // Already returns by value (current tests cover this)
    // @expect: capability-leakage
    public fun get_admin_cap_value(ctx: &mut TxContext): AdminCap {
        AdminCap { id: object::new(ctx) }
    }

    // SAFE: Requires AdminCap to access
    public fun get_admin_cap_guarded(
        _guard: &AdminCap,
        config: &Config
    ): &AdminCap {
        &config.admin_cap
    }
}
