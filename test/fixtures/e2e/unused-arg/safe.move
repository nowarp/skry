/// Safe test cases - all args used or explicitly marked unused
// @inject: IsCapability("AdminCap")
// @inject: IsCapability("VersionCap")
// @inject: IsCapability("ExecutorCap")
module test::unused_arg_safe {
    use sui::tx_context::TxContext;
    use sui::object::UID;

    /// All arguments used
    public fun add(a: u64, b: u64): u64 {
        a + b
    }

    /// Explicitly marked as unused with underscore
    public fun process(_ignored: u64, value: u64): u64 {
        value * 2
    }

    /// All used
    public fun calculate(x: u64, y: u64, z: u64): u64 {
        x + y + z
    }

    /// Underscore prefix for intentionally unused
    public fun with_marker(_unused_param: u64, _another_unused: address, used: u64): u64 {
        used + 10
    }

    /// Parameter used in type cast expression
    public fun uses_cast(amount: u64): u128 {
        (amount as u128) * 2
    }

    /// Multiple casts in complex expression
    public fun calculate_mint_fee(sui_amount: u64, fee_bps: u64): u64 {
        (((sui_amount as u128) * (fee_bps as u128) + 9999) / 10_000) as u64
    }

    /// Nested cast expression
    public fun nested_cast(x: u64, y: u32): u128 {
        ((x as u128) + (y as u128)) * 100
    }

    public struct Stop has drop {
        offset: u64,
        color: u64,
    }

    public enum ShapeType has drop {
        LinearGradient { stops: vector<Stop> },
        RadialGradient { stops: vector<Stop> },
        Empty,
    }

    public struct Shape has drop {
        shape: ShapeType,
    }

    /// Field access on struct argument (via match)
    public fun add_stop(gradient: &mut Shape, offset: u64, color: u64) {
        let stops = match (&mut gradient.shape) {
            ShapeType::LinearGradient { stops } => stops,
            ShapeType::RadialGradient { stops } => stops,
            ShapeType::Empty => abort 0,
        };
        stops.push_back(Stop { offset, color });
    }

    // ==========================================================================
    // Lambda and macro closure patterns - variables captured inside lambdas
    // ==========================================================================

    public struct Grid<T> has drop { width: u64, data: vector<T> }
    public struct Cell has drop { x: u64 }
    public struct Container has drop { attrs: vector<u64> }

    /// Parameter used in condition - NOT unused
    public fun filter_by_width(g: &Grid<u64>, cell: Cell): bool {
        cell.x < g.width
    }

    /// Parameter used in index expression - NOT unused
    public fun index_access(grid: &Grid<u64>, x: u64, y: u64): u64 {
        *std::vector::borrow(&grid.data, x + y)
    }

    /// Parameters used in container mutation - NOT unused
    public fun transform_container(container: &mut Container, x: u64, y: u64) {
        std::vector::push_back(&mut container.attrs, x);
        std::vector::push_back(&mut container.attrs, y);
    }

    /// Multiple index accesses in complex expression
    public fun multi_index(grid: &Grid<u64>, i: u64, j: u64): u64 {
        grid.data[i] + grid.data[j]
    }

    // ==========================================================================
    // Capability arguments - used for authorization proof, presence IS the check
    // ==========================================================================

    public struct AdminCap has key, store { id: UID }
    public struct VersionCap has key, store { id: UID }
    public struct ExecutorCap has key, store { id: UID }

    /// Capability arg not used in body but serves as authorization proof
    /// Should NOT be flagged (IsCapability fact injected above)
    public fun admin_only(cap: &AdminCap, value: u64): u64 {
        value * 2
    }

    /// Multiple capability args - none used but all are authorization proofs
    public fun multi_cap_auth(
        _admin: &AdminCap,
        version_cap: &VersionCap,
        value: u64
    ): u64 {
        value + 1
    }

    /// Mutable capability reference - still an authorization proof
    public fun admin_mut(cap: &mut AdminCap, amount: u64): u64 {
        amount * 3
    }

    /// Mix of capability and regular unused - only regular should be flagged
    /// NOTE: This function has 'unused_regular' which SHOULD be flagged
    /// But that's tested in vulnerable.move. Here we verify cap is NOT flagged.
    public fun cap_with_used_args(cap: &ExecutorCap, used_value: u64): u64 {
        used_value + 100
    }
}
