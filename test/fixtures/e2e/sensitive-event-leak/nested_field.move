/// Nested field access test - obj.inner.sensitive
module test::sensitive_event_nested {
    use sui::event;
    use sui::object::UID;

    public struct Profile has store {
        display_name: vector<u8>,
        private_key: vector<u8>,  // SENSITIVE
    }

    public struct UserAccount has key {
        id: UID,
        profile: Profile,
    }

    public struct ProfileEvent has copy, drop {
        key: vector<u8>,
    }

    public struct SafeProfileEvent has copy, drop {
        name: vector<u8>,
    }

    /// VULNERABLE: Leaks nested sensitive field
    // @expect: sensitive-event-leak
    public entry fun leak_nested(account: &UserAccount) {
        event::emit(ProfileEvent {
            key: account.profile.private_key,
        });
    }

    /// SAFE: Only non-sensitive nested fields
    public entry fun safe_nested(account: &UserAccount) {
        event::emit(SafeProfileEvent {
            name: account.profile.display_name,
        });
    }
}
