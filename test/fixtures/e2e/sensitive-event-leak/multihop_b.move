/// Multihop B - middle hop in A->B->C chain
module test::sensitive_event_hop_b {
    use test::sensitive_event_hop_c;

    /// Just forwards to C
    public fun forward_data(data: vector<u8>) {
        sensitive_event_hop_c::emit_data(data);
    }
}
