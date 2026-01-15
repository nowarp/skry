/// Safe test cases - all privileged caps are used
module test::orphan_privileged_safe {
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};

    public struct AdminCap has key {
        id: UID,
    }

    public struct ModeratorCap has key {
        id: UID,
    }

    fun init(ctx: &mut TxContext) {
        transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
        transfer::transfer(ModeratorCap { id: object::new(ctx) }, tx_context::sender(ctx));
    }

    /// Uses AdminCap
    public entry fun admin_action(_cap: &AdminCap) {
        // Protected
    }

    /// Uses ModeratorCap
    public entry fun moderate(_cap: &ModeratorCap) {
        // Protected
    }
}
