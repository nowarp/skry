/// False positive test cases for admin-bypasses-pause rule.
/// Config setters that only do state_write should NOT be flagged.
/// They are intentional admin operations during pause, not centralization risks.
///
/// This simulates the Navi protocol pattern where config is stored in a Table.

// @inject: FeaturePause(True)
// @inject: IsGlobalPauseField("test::config_setter::Config", "paused")

module test::config_setter {
    use sui::tx_context::TxContext;
    use sui::transfer;
    use sui::object::{Self, UID};
    use sui::table::{Self, Table};

    /// Protocol config with pause field
    public struct Config has key {
        id: UID,
        paused: bool,
        reserves: Table<u8, Reserve>,
    }

    /// Reserve config (like Navi's reserve struct)
    public struct Reserve has store {
        supply_cap: u256,
        borrow_cap: u256,
        ltv: u64,
        fee_rate: u64,
    }

    /// Admin capability
    public struct AdminCap has key, store {
        id: UID,
    }

    // =========================================================================
    // FALSE POSITIVES: Config setters should NOT be flagged
    // These only do state_write (no value extraction/transfer)
    // Admins updating config during pause is intentional, not a centralization risk
    // =========================================================================

    /// Config setter - only state_write sink (borrow_mut), should NOT be flagged
    public entry fun set_supply_cap(
        config: &mut Config,
        _cap: &AdminCap,
        asset: u8,
        new_cap: u256,
    ) {
        let reserve = table::borrow_mut(&mut config.reserves, asset);
        reserve.supply_cap = new_cap;
    }

    /// Config setter - only state_write sink, should NOT be flagged
    public entry fun set_borrow_cap(
        config: &mut Config,
        _cap: &AdminCap,
        asset: u8,
        new_cap: u256,
    ) {
        let reserve = table::borrow_mut(&mut config.reserves, asset);
        reserve.borrow_cap = new_cap;
    }

    /// Config setter - only state_write sink, should NOT be flagged
    public entry fun set_ltv(
        config: &mut Config,
        _cap: &AdminCap,
        asset: u8,
        new_ltv: u64,
    ) {
        let reserve = table::borrow_mut(&mut config.reserves, asset);
        reserve.ltv = new_ltv;
    }

    /// Config setter - only state_write sink, should NOT be flagged
    public entry fun set_fee_rate(
        config: &mut Config,
        _cap: &AdminCap,
        asset: u8,
        new_rate: u64,
    ) {
        let reserve = table::borrow_mut(&mut config.reserves, asset);
        reserve.fee_rate = new_rate;
    }

    fun init(ctx: &mut TxContext) {
        let config = Config {
            id: object::new(ctx),
            paused: false,
            reserves: table::new(ctx),
        };
        transfer::share_object(config);

        let cap = AdminCap { id: object::new(ctx) };
        transfer::transfer(cap, @0x1);
    }
}
