/// Safe test cases - bounded loops
module test::unbounded_loop_safe {
    use sui::tx_context::TxContext;
    use sui::vec_map::{Self, VecMap};
    use sui::object::{Self, UID};

    public struct Config has key {
        id: UID,
        max_iterations: u64,
    }

    const MAX_BATCH_SIZE: u64 = 100;

    /// Constant bound
    public entry fun process_constant() {
        let mut i = 0;
        while (i < 100) {
            i = i + 1;
        };
    }

    /// Validated user input
    public entry fun process_with_validation(count: u64) {
        assert!(count <= MAX_BATCH_SIZE, 0);
        let mut i = 0;
        while (i < count) {
            i = i + 1;
        };
    }

    /// Multiple validation checks
    public entry fun process_multi_check(count: u64) {
        assert!(count > 0, 1);
        assert!(count <= 1000, 2);
        let mut i = 0;
        while (i < count) {
            i = i + 1;
        };
    }

    /// Bound from config (not direct user input)
    public entry fun process_from_config(config: &Config) {
        let mut i = 0;
        while (i < config.max_iterations) {
            i = i + 1;
        };
    }
}
