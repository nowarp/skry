// Cross-module test: type definitions
module test::cross_types {
    use sui::object::UID;

    public struct GlobalConfig has key, store {
        id: UID,
        protocol_fee_bps: u64,  // Protocol invariant - basis points
        min_amount: u64,        // NOT invariant - can be adjusted
    }

    public struct OperatorCap has key, store { id: UID }
}
