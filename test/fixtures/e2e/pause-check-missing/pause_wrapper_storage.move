/// Pause wrapper module - simulates Navi's storage::when_not_paused pattern
/// The wrapper function directly checks the pause field.

// @inject: FeaturePause(True)
// @inject: IsGlobalPauseField("test::wrapper_storage::Config", "paused")
// @inject: ChecksPause("test::wrapper_storage::when_not_paused")

module test::wrapper_storage {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;
    use sui::transfer;

    public struct Config has key {
        id: UID,
        paused: bool,
    }

    /// Wrapper function that checks pause - has ChecksPause fact
    public fun when_not_paused(config: &Config) {
        assert!(!config.paused, 0);
    }

    fun init(ctx: &mut TxContext) {
        let config = Config {
            id: object::new(ctx),
            paused: false,
        };
        transfer::share_object(config);
    }
}
