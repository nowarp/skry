/// Safe test cases - all roles are used
module test::orphan_role_safe {
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};

    public struct AdminCap has key {
        id: UID,
    }

    public struct ModeratorCap has key {
        id: UID,
    }

    /// Uses AdminCap
    public entry fun admin_action(_cap: &AdminCap) {
        // Protected
    }

    /// Uses ModeratorCap
    public entry fun moderate(_cap: &ModeratorCap) {
        // Protected
    }

    /// Uses both
    public entry fun super_action(_admin: &AdminCap, _mod: &ModeratorCap) {
        // Dual protection
    }
}
