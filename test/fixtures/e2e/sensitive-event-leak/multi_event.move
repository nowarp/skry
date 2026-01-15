/// Multiple events test - one safe, one leaking in same function
module test::sensitive_event_multi {
    use sui::event;
    use sui::object::UID;

    public struct UserData has key {
        id: UID,
        username: vector<u8>,
        password: vector<u8>,  // SENSITIVE
    }

    public struct UsernameEvent has copy, drop {
        username: vector<u8>,
    }

    public struct PasswordEvent has copy, drop {
        password: vector<u8>,
    }

    public struct MixedEvent has copy, drop {
        username: vector<u8>,
        password: vector<u8>,  // LEAKED!
    }

    /// VULNERABLE: Emits both safe and leaking events
    // @expect: sensitive-event-leak
    public entry fun emit_both(user: &UserData) {
        event::emit(UsernameEvent { username: user.username });
        event::emit(PasswordEvent { password: user.password });
    }

    /// VULNERABLE: Single event with both safe and sensitive fields
    // @expect: sensitive-event-leak
    public entry fun emit_mixed(user: &UserData) {
        event::emit(MixedEvent {
            username: user.username,
            password: user.password,
        });
    }

    /// SAFE: Only safe events
    public entry fun emit_safe_only(user: &UserData) {
        event::emit(UsernameEvent { username: user.username });
    }
}
