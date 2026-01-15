/// IPA FQN test: module B has emit_data that does NOT leak (hashes first)
module test::ipa_fqn_emit_b {
    use sui::event;

    public struct HashedEvent has copy, drop {
        data_hash: vector<u8>,
    }

    /// Hashes data before emitting - SAFE even with sensitive input
    /// (In real code this would call std::hash::sha3_256, simplified here)
    public fun emit_data(data: vector<u8>) {
        // Pretend we hash - the point is we don't emit raw data
        let hashed = data;  // placeholder
        event::emit(HashedEvent { data_hash: hashed });
    }
}
