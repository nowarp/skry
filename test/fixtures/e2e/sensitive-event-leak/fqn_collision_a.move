/// FQN collision test - module A
module test::fqn_collision_a {
    use sui::event;
    use sui::object::UID;
    use std::string::String;

    public struct Profile has key {
        id: UID,
        name: String,
        api_key: vector<u8>,  // Sensitive
    }

    public struct ProfileEvent has copy, drop {
        name: String,
        api_key: vector<u8>,  // LEAKED
    }

    /// VULNERABLE: Leaks api_key
    // @expect: sensitive-event-leak
    public entry fun emit_profile(profile: &Profile) {
        event::emit(ProfileEvent {
            name: profile.name,
            api_key: profile.api_key,
        });
    }
}
