/// IPA FQN test: caller that uses both emit modules
module test::ipa_fqn_caller {
    use sui::object::UID;
    use test::ipa_fqn_emit_a;
    use test::ipa_fqn_emit_b;

    public struct Secret has key {
        id: UID,
        key: vector<u8>,  // SENSITIVE
    }

    /// VULNERABLE: Calls the leaking emit_data (module A)
    // @expect: sensitive-event-leak
    public entry fun call_leaking(s: &Secret) {
        ipa_fqn_emit_a::emit_data(s.key);
    }

    /// SAFE: Calls the safe emit_data (module B - hashes first)
    /// Note: This tests FQN disambiguation in IPA
    /// The hashing is a placeholder (let hashed = data), so rule correctly detects sink
    // @false-positive: sensitive-event-leak
    public entry fun call_safe(s: &Secret) {
        ipa_fqn_emit_b::emit_data(s.key);
    }
}
