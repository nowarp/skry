/// Cell::set() method pattern FP test
/// Pattern from suilend: fee_config uses Cell wrapper with .set() method
module test::cell_method_setter {
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};

    // Cell wrapper simulating sui::dynamic_field::Cell
    public struct Cell<T: store> has store { value: T }

    public fun set<T: store + drop>(c: &mut Cell<T>, v: T) {
        c.value = v;
    }

    public struct FeeConfig has store, drop { rate: u64 }

    // @false-positive: missing-mutable-config-setter (has setter via Cell::set method call)
    public struct LiquidStakingInfo<phantom P> has key {
        id: UID,
        fee_config: Cell<FeeConfig>,
    }

    public struct AdminCap<phantom P> has key, store { id: UID }

    fun init(ctx: &mut TxContext) {
        let admin = AdminCap<u8> { id: object::new(ctx) };
        sui::transfer::transfer(admin, sui::tx_context::sender(ctx));
    }

    public fun update_fees<P>(
        self: &mut LiquidStakingInfo<P>,
        _admin_cap: &AdminCap<P>,
        fee_config: FeeConfig,
    ) {
        set(&mut self.fee_config, fee_config);
    }
}
