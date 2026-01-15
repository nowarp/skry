module test::ipa_chain {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};

    public struct AdminCap has key, store { id: UID }

    fun init(ctx: &mut TxContext) {
        transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
    }

    /// A -> B -> C chain: entry calls helper_b which calls helper_c
    // @expect: single-step-ownership
    public entry fun transfer_via_chain(cap: AdminCap, recipient: address) {
        helper_b(cap, recipient);
    }

    fun helper_b(cap: AdminCap, addr: address) {
        helper_c(cap, addr);
    }

    fun helper_c(cap: AdminCap, addr: address) {
        transfer::transfer(cap, addr);
    }

    /// A -> B chain with taint propagation
    // @expect: single-step-ownership
    public entry fun transfer_via_helper(cap: AdminCap, user_addr: address) {
        let target = compute_target(user_addr);
        do_transfer(cap, target);
    }

    fun compute_target(addr: address): address {
        addr  // taint propagates through
    }

    fun do_transfer(cap: AdminCap, addr: address) {
        transfer::transfer(cap, addr);
    }
}
