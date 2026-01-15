/// Field aliasing test - sensitive data through local variables
module test::sensitive_event_alias {
    use sui::event;
    use sui::object::UID;

    public struct UserData has key {
        id: UID,
        username: vector<u8>,
        private_key: vector<u8>,  // SENSITIVE
    }

    public struct LeakedEvent has copy, drop {
        data: vector<u8>,
    }

    public struct SafeEvent has copy, drop {
        username: vector<u8>,
    }

    /// VULNERABLE: Sensitive field aliased to local var
    // @expect: sensitive-event-leak
    public entry fun leak_via_alias(user: &UserData) {
        let secret = user.private_key;
        event::emit(LeakedEvent { data: secret });
    }

    /// VULNERABLE: Multiple aliasing hops
    // @expect: sensitive-event-leak
    public entry fun leak_via_multi_hop(user: &UserData) {
        let x = user.private_key;
        let y = x;
        let z = y;
        event::emit(LeakedEvent { data: z });
    }

    /// SAFE: Non-sensitive field aliased
    public entry fun safe_alias(user: &UserData) {
        let name = user.username;
        event::emit(SafeEvent { username: name });
    }
}
