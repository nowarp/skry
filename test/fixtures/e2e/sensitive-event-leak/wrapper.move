/// Wrapper helper test - helper function emits sensitive data
module test::sensitive_event_wrapper {
    use sui::event;
    use sui::object::UID;

    public struct UserData has key {
        id: UID,
        username: vector<u8>,
        password_hash: vector<u8>,  // SENSITIVE
    }

    public struct DataEvent has copy, drop {
        data: vector<u8>,
    }

    public struct SafeNameEvent has copy, drop {
        username: vector<u8>,
    }

    /// VULNERABLE: Entry calls wrapper that leaks
    // @expect: sensitive-event-leak
    public entry fun call_leaking_wrapper(user: &UserData) {
        emit_data(user.password_hash);
    }

    /// Helper that emits whatever is passed
    fun emit_data(data: vector<u8>) {
        event::emit(DataEvent { data });
    }

    /// SAFE: Entry passes non-sensitive to wrapper
    public entry fun call_safe_wrapper(user: &UserData) {
        emit_username(user.username);
    }

    fun emit_username(username: vector<u8>) {
        event::emit(SafeNameEvent { username });
    }
}
