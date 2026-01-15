/// Multihop C - final hop, emits event
module test::sensitive_event_hop_c {
    use sui::event;

    public struct DataEmitted has copy, drop {
        data: vector<u8>,
    }

    /// Emits data - LEAKS if sensitive flows here
    public fun emit_data(data: vector<u8>) {
        event::emit(DataEmitted { data });
    }
}
