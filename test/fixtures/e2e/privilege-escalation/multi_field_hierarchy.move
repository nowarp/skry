/// Multi-field capability hierarchy pattern (evefrontier-style)
/// Tests that capabilities with extra fields (not just UID) are properly
/// recognized in hierarchy relationships.
///
/// Key test: AdminCap has 2 fields (id + admin), so it won't be detected by
/// structural detection (single-UID only). It requires LLM classification.
/// The hierarchy AdminCap -> OwnerCap must still work.
module test::multi_field_hierarchy {
    use sui::object::{Self, UID, ID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    /// Top-level capability - single UID (detected structurally)
    public struct GovernorCap has key {
        id: UID,
    }

    /// Mid-level capability - has extra field (requires LLM classification)
    /// This is the key struct: 2 fields means structural detection skips it
    public struct AdminCap has key {
        id: UID,
        admin: address,
    }

    /// Object-level capability - has extra field (requires LLM classification)
    public struct OwnerCap has key {
        id: UID,
        owned_object_id: ID,
    }

    fun init(ctx: &mut TxContext) {
        // Only GovernorCap is created in init - AdminCap/OwnerCap are NOT
        // This means AdminCap/OwnerCap won't pass structural detection
        let gov = GovernorCap { id: object::new(ctx) };
        transfer::transfer(gov, tx_context::sender(ctx));
    }

    /// @safe: privilege-escalation (GovernorCap guards AdminCap creation - valid hierarchy)
    public fun create_admin_cap(_: &GovernorCap, admin: address, ctx: &mut TxContext) {
        let admin_cap = AdminCap { id: object::new(ctx), admin };
        transfer::transfer(admin_cap, admin);
    }

    /// @safe: privilege-escalation (AdminCap guards OwnerCap creation - valid hierarchy)
    public fun create_owner_cap(_: &AdminCap, owned_object_id: ID, ctx: &mut TxContext): OwnerCap {
        OwnerCap { id: object::new(ctx), owned_object_id }
    }

    /// @safe: privilege-escalation (AdminCap guards OwnerCap transfer - valid hierarchy)
    public fun transfer_owner_cap(owner_cap: OwnerCap, _: &AdminCap, owner: address) {
        transfer::transfer(owner_cap, owner);
    }
}
