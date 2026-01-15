/// IPA FQN test: module A has emit_data that DOES leak sensitive
module test::ipa_fqn_emit_a {
    use sui::event;

    public struct DataEvent has copy, drop {
        data: vector<u8>,
    }

    /// Emits data as-is - LEAKS if sensitive
    public fun emit_data(data: vector<u8>) {
        event::emit(DataEvent { data });
    }
}
