/// Multihop A - entry point for A->B->C chain
module test::sensitive_event_hop_a {
    use sui::object::UID;
    use test::sensitive_event_hop_b;

    public struct Credentials has key {
        id: UID,
        api_token: vector<u8>,  // SENSITIVE
    }

    /// VULNERABLE: Calls B which calls C which emits
    // @expect: sensitive-event-leak
    public entry fun start_chain(creds: &Credentials) {
        sensitive_event_hop_b::forward_data(creds.api_token);
    }
}
