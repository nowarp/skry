/// FQN collision test - module A
module test::fqn_collision_a {
    use sui::event;
    use sui::tx_context::TxContext;

    /// ORPHAN: StatusEvent never emitted
    // @expect: orphan-event
    public struct StatusEvent has copy, drop {
        status: u64,
    }

    public entry fun update(ctx: &mut TxContext) {
        // No event emission
    }
}
