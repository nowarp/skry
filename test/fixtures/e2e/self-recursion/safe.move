/// Safe test cases - no recursion or bounded recursion
module test::self_recursion_safe {
    use sui::tx_context::TxContext;

    /// Iterative approach
    public fun iterative_sum(n: u64): u64 {
        let mut sum = 0;
        let mut i = 0;
        while (i <= n) {
            sum = sum + i;
            i = i + 1;
        };
        sum
    }

    /// Non-recursive public function
    public fun process(n: u64): u64 {
        n * 2
    }

    public entry fun safe_entry(n: u64, ctx: &mut TxContext) {
        let _result = process(n);
    }

    /// Helper with loop
    fun calculate(n: u64): u64 {
        let mut result = 1;
        let mut i = 1;
        while (i <= n) {
            result = result * i;
            i = i + 1;
        };
        result
    }

    public struct WeightHook<phantom P> has store {
        admin_cap: u64
    }

    public struct Registry has key {
        id: sui::object::UID
    }

    /// SAFE: Method call on different receiver with same name
    public fun add_to_registry<P>(
        self: &WeightHook<P>,
        registry: &mut Registry,
    ) {
        registry.register_item(&self.admin_cap);
    }

    /// Method on Registry
    public fun register_item(self: &mut Registry, cap: &u64) {
        // Implementation
    }

    public struct Pool has key {
        id: sui::object::UID,
        storage: Storage
    }

    public struct Storage has store {
        balance: u64
    }

    /// SAFE: Method call on nested object
    public fun get_total_supply(self: &Pool): u64 {
        self.storage.storage_balance()
    }

    /// Method on Storage
    public fun storage_balance(self: &Storage): u64 {
        self.balance
    }

    /// SAFE: Method call on self param (different method)
    public fun mint(self: &mut Pool, ctx: &mut TxContext) {
        self.refresh(ctx);
    }

    /// Different method
    public fun refresh(self: &mut Pool, ctx: &mut TxContext) {
        // Implementation
    }
}
