/// Cross-module helper - emits events
module test::sensitive_event_helper {
    use sui::event;

    public struct UserLogEvent has copy, drop {
        data: vector<u8>,
    }

    public struct UsernameEvent has copy, drop {
        username: vector<u8>,
    }

    /// Helper that emits data - LEAKS if sensitive data passed
    public fun log_user_data(data: vector<u8>) {
        event::emit(UserLogEvent { data });
    }

    /// Helper that emits username - always safe
    public fun log_username(username: vector<u8>) {
        event::emit(UsernameEvent { username });
    }
}
