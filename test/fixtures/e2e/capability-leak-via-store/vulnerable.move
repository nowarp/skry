/// Test cases for capability-leak-via-store rule.
/// Tests detection of capabilities stored in shared object fields.
module test::capability_leak_via_store {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    /// Admin capability - should be owned, not stored in shared object
    // @expect: capability-leak-via-store
    public struct AdminCap has key {
        id: UID,
    }

    /// Operator capability - also should not be stored in shared
    // @expect: capability-leak-via-store
    public struct OperatorCap has key {
        id: UID,
    }

    /// Shared vault that stores AdminCap - VULNERABLE
    public struct SharedVault has key {
        id: UID,
        admin_cap: AdminCap,  // Capability stored in shared object!
    }

    /// Shared config that stores OperatorCap - VULNERABLE
    public struct SharedConfig has key {
        id: UID,
        operator: OperatorCap,  // Another capability leak
        value: u64,
    }

    /// VULNERABLE: Creates shared object containing capability
    fun init(ctx: &mut TxContext) {
        // Create AdminCap and store it in shared vault
        let admin = AdminCap { id: object::new(ctx) };
        let vault = SharedVault {
            id: object::new(ctx),
            admin_cap: admin,
        };
        transfer::share_object(vault);  // Anyone can now access admin_cap!

        // Create OperatorCap and store it in shared config
        let operator = OperatorCap { id: object::new(ctx) };
        let config = SharedConfig {
            id: object::new(ctx),
            operator: operator,
            value: 100,
        };
        transfer::share_object(config);  // Anyone can access operator cap!
    }
}

/// Safe patterns - capabilities properly owned
module test::safe_patterns {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    /// Safe capability - will be properly transferred
    // @safe: capability-leak-via-store
    public struct SafeCap has key {
        id: UID,
    }

    /// Shared pool without capability fields - SAFE
    public struct SharedPool has key {
        id: UID,
        balance: u64,
    }

    /// SAFE: Capability transferred to owner, not stored in shared
    fun init(ctx: &mut TxContext) {
        // Properly transfer capability to deployer
        let cap = SafeCap { id: object::new(ctx) };
        transfer::transfer(cap, tx_context::sender(ctx));

        // Share a pool without capability fields
        let pool = SharedPool {
            id: object::new(ctx),
            balance: 0,
        };
        transfer::share_object(pool);
    }
}
