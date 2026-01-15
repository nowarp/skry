// Test case: 3-level nested field setter via method call pattern
// Should NOT trigger missing-mutable-config-setter rule
module test::config {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    public struct Inner has store { value: u64 }
    public struct Wrapper has store { inner: Inner }

    public struct Config has key {
        id: UID,
        settings: Wrapper,
    }

    public struct AdminCap has key, store { id: UID }

    fun init(ctx: &mut TxContext) {
        let config = Config {
            id: object::new(ctx),
            settings: Wrapper { inner: Inner { value: 100 } },
        };
        sui::transfer::share_object(config);

        let admin = AdminCap { id: object::new(ctx) };
        sui::transfer::transfer(admin, sui::tx_context::sender(ctx));
    }

    // Privileged setter using 3-level nested method call - should be recognized
    public fun update(_: &AdminCap, cfg: &mut Config, v: u64) {
        cfg.settings.inner.set(v);  // 3-level deep
    }

    public fun set(i: &mut Inner, v: u64) {
        i.value = v;
    }
}
