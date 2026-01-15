/// Test cases for capability-takeover rule.
/// Tests detection of unauthorized capability acquisition.
module test::capability_takeover {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    /// Admin capability - created for deployer in init
    public struct AdminCap has key {
        id: UID,
    }

    /// Treasury capability
    public struct TreasuryCap has key {
        id: UID,
    }

    /// Non-privileged struct (not a role)
    public struct UserData has key {
        id: UID,
        value: u64,
    }

    // =========================================================================
    // INIT - Creates caps for deployer
    // =========================================================================

    fun init(ctx: &mut TxContext) {
        // Create AdminCap and transfer to deployer
        let admin = AdminCap { id: object::new(ctx) };
        transfer::transfer(admin, tx_context::sender(ctx));

        // Create TreasuryCap and transfer to deployer
        let treasury = TreasuryCap { id: object::new(ctx) };
        transfer::transfer(treasury, tx_context::sender(ctx));
    }

    // =========================================================================
    // VULNERABLE: Capability takeover - transfer deployer cap to TxSender
    // =========================================================================

    /// VULNERABLE: Anyone with the cap can transfer it to themselves
    // @expect: capability-takeover
    public entry fun steal_admin_cap(cap: AdminCap, ctx: &mut TxContext) {
        // Takes admin cap by value and transfers to caller
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// VULNERABLE: Same pattern with treasury cap
    // @expect: capability-takeover
    public entry fun steal_treasury_cap(cap: TreasuryCap, ctx: &mut TxContext) {
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    // =========================================================================
    // SAFE: Proper authorization or non-capability types
    // =========================================================================

    /// SAFE: Requires admin proof to transfer
    // @safe: capability-takeover
    public entry fun transfer_with_auth(
        _admin: &AdminCap,
        cap: TreasuryCap,
        ctx: &mut TxContext
    ) {
        // Requires admin reference as proof
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// SAFE: Self-transfer (admin transfers their own cap)
    // @safe: capability-takeover
    public entry fun admin_transfer_self(
        cap: AdminCap,
        _proof: &AdminCap,  // Must prove they have another admin cap
        ctx: &mut TxContext
    ) {
        transfer::transfer(cap, tx_context::sender(ctx));
    }

    /// SAFE: Non-capability struct transfer
    // @safe: capability-takeover
    public entry fun transfer_user_data(data: UserData, ctx: &mut TxContext) {
        // UserData is not a role/capability, so this is fine
        transfer::transfer(data, tx_context::sender(ctx));
    }

    /// SAFE: Internal helper (not public entry)
    fun internal_transfer(cap: AdminCap, ctx: &mut TxContext) {
        transfer::transfer(cap, tx_context::sender(ctx));
    }
}
