/// Cross-module entry - calls helper that emits sensitive event
module test::sensitive_event_entry {
    use sui::object::UID;
    use test::sensitive_event_helper;

    public struct UserData has key {
        id: UID,
        username: vector<u8>,
        secret_key: vector<u8>,  // SENSITIVE
    }

    /// VULNERABLE: Calls helper that emits sensitive data
    // @expect: sensitive-event-leak
    public entry fun process_user(user: &UserData) {
        sensitive_event_helper::log_user_data(user.secret_key);
    }

    /// SAFE: Calls helper with non-sensitive data
    public entry fun process_user_safe(user: &UserData) {
        sensitive_event_helper::log_username(user.username);
    }
}
