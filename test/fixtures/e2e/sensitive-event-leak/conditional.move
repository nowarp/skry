/// Conditional leak test - branch-sensitive analysis
module test::sensitive_event_conditional {
    use sui::event;
    use sui::object::UID;

    public struct UserData has key {
        id: UID,
        username: vector<u8>,
        secret: vector<u8>,  // SENSITIVE
    }

    public struct SafeEvent has copy, drop {
        username: vector<u8>,
    }

    public struct LeakEvent has copy, drop {
        data: vector<u8>,
    }

    /// VULNERABLE: Leaks in one branch
    // @expect: sensitive-event-leak
    public entry fun conditional_leak(user: &UserData, verbose: bool) {
        if (verbose) {
            event::emit(LeakEvent { data: user.secret });
        } else {
            event::emit(SafeEvent { username: user.username });
        }
    }

    /// VULNERABLE: Leaks unconditionally despite conditional
    // @expect: sensitive-event-leak
    public entry fun unconditional_leak(user: &UserData, flag: bool) {
        event::emit(LeakEvent { data: user.secret });
        if (flag) {
            event::emit(SafeEvent { username: user.username });
        }
    }

    /// SAFE: Both branches are safe
    public entry fun conditional_safe(user: &UserData, verbose: bool) {
        if (verbose) {
            event::emit(SafeEvent { username: user.username });
        } else {
            event::emit(SafeEvent { username: user.username });
        }
    }
}
