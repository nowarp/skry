/// FQN collision test - module B
module test::fqn_collision_b {
    use sui::event;
    use sui::tx_context::TxContext;

    public struct StatusEvent has copy, drop {
        status: u64,
    }

    /// SAFE: StatusEvent is emitted
    public entry fun update(status: u64, ctx: &mut TxContext) {
        event::emit(StatusEvent { status });
    }
}
