/// Test receiver/method call syntax - arguments should not be flagged as unused
/// This tests the fix for false positives where obj.method(arg) was parsed incorrectly
module test::receiver_method_call {
    use sui::tx_context::TxContext;

    public struct AdminCap has key {
        id: UID,
    }

    public struct Item has key {
        id: UID,
        value: u64,
    }

    public struct Stats has store, drop {
        power: u64,
    }

    public struct StatsKey has store, copy, drop {}

    /// admin is used via receiver syntax: admin.verify(ctx)
    public fun verify_admin(admin: &AdminCap, ctx: &TxContext) {
        admin.verify(ctx);
    }

    /// stats is used via receiver syntax: item.add_field(key, stats)
    public fun augment_with_stats(item: &mut Item, stats: Stats) {
        item.add_field(StatsKey {}, stats);
    }

    /// Multiple args used in receiver call: kiosk.lock(kiosk_cap, policy, item)
    public fun lock_item(kiosk: &mut Kiosk, kiosk_cap: &KioskOwnerCap, policy: &Policy, item: Item) {
        kiosk.lock(kiosk_cap, policy, item);
    }

    /// Chained receiver calls: obj.get_field().unwrap()
    public fun get_nested_field(item: &Item): u64 {
        item.get_field().unwrap()
    }

    // Dummy implementations to make test self-contained
    public fun verify(_admin: &AdminCap, _ctx: &TxContext) {}
    public fun add_field<K: store + copy + drop, V: store + drop>(_item: &mut Item, _key: K, _val: V) {}

    public struct Kiosk has key { id: UID }
    public struct KioskOwnerCap has key { id: UID }
    public struct Policy has key { id: UID }
    public fun lock(_kiosk: &mut Kiosk, _cap: &KioskOwnerCap, _policy: &Policy, _item: Item) { let Item { id, value: _ } = _item; id.delete(); }

    public struct FieldWrapper<T> { value: T }
    public fun get_field<T: copy>(_item: &Item): FieldWrapper<T> { abort 0 }
    public fun unwrap<T>(_wrapper: FieldWrapper<T>): T { abort 0 }
}
