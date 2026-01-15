/// Test: public(package) vs public visibility
module test::friend_cap {
    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;

    public struct FriendCap has key, store {
        id: UID,
    }

    /// public(package) - internal to package
    /// NOT flagged: rule matches :public, not package visibility
    public(package) fun internal_create(ctx: &mut TxContext): FriendCap {
        FriendCap { id: object::new(ctx) }
    }

    /// Public wrapper that exposes package function
    // @expect: test-only-missing
    public fun expose_friend(ctx: &mut TxContext): FriendCap {
        internal_create(ctx)
    }
}
