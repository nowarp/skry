/// FQN collision test - module B
module test::fqn_collision_b {
    use sui::event;
    use sui::object::UID;
    use std::string::String;

    public struct Profile has key {
        id: UID,
        name: String,
        api_key: vector<u8>,  // Sensitive but not leaked
    }

    public struct ProfileEvent has copy, drop {
        name: String,
        profile_id: address,
    }

    /// SAFE: Doesn't leak api_key
    public entry fun emit_profile(profile: &Profile) {
        event::emit(ProfileEvent {
            name: profile.name,
            profile_id: sui::object::uid_to_address(&profile.id),
        });
    }
}
