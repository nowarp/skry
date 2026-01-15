/// FP: Registry misclassified as privileged
/// Registry is a storage container, not a privileged cap
/// Pattern from suilend registry.move
module test::registry_return {
    use sui::object::{Self, UID};
    use sui::bag::{Self, Bag};
    use sui::tx_context::TxContext;

    public struct Version has store { value: u64 }

    // Registry is NOT privileged:
    // - Has multiple fields (id, version, table)
    // - Not transferred to sender in init
    public struct Registry has key, store {
        id: UID,
        version: Version,
        table: Bag,
    }

    fun init(_ctx: &mut TxContext) {
        // No capability created
    }

    // @false-positive: capability-leakage (Registry is storage container not privileged cap)
    public fun new(ctx: &mut TxContext): Registry {
        Registry {
            id: object::new(ctx),
            version: Version { value: 1 },
            table: bag::new(ctx),
        }
    }
}
