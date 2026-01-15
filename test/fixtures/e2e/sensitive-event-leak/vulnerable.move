/// Test cases for sensitive-event-leak rule.
/// Sensitive data exposed in event
module test::sensitive_event_leak {
    use sui::event;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};
    use std::string::String;

    public struct UserData has key {
        id: UID,
        username: String,
        private_key: vector<u8>,  // SENSITIVE!
        password_hash: vector<u8>,  // SENSITIVE!
    }

    public struct UserUpdated has copy, drop {
        username: String,
        private_key: vector<u8>,  // LEAKED IN EVENT!
    }

    public struct UserCreated has copy, drop {
        username: String,
        password_hash: vector<u8>,  // LEAKED!
    }

    public struct SafeEvent has copy, drop {
        username: String,
        user_id: address,
    }

    /// VULNERABLE: Leaks private_key in event
    // @expect: sensitive-event-leak
    public entry fun update_user(user: &mut UserData) {
        event::emit(UserUpdated {
            username: user.username,
            private_key: user.private_key,  // LEAK!
        });
    }

    /// VULNERABLE: Leaks password_hash
    // @expect: sensitive-event-leak
    public entry fun create_user(user: &mut UserData) {
        event::emit(UserCreated {
            username: user.username,
            password_hash: user.password_hash,  // LEAK!
        });
    }

    /// SAFE: Event doesn't contain sensitive fields
    public entry fun safe_update(user: &mut UserData) {
        event::emit(SafeEvent {
            username: user.username,
            user_id: sui::object::uid_to_address(&user.id),
        });
    }
}
