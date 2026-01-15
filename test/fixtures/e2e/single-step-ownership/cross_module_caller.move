module test::cross_caller {
    use test::cross_cap::{Self, AdminCap};

    // @expect: single-step-ownership
    public entry fun transfer_cross_module(cap: AdminCap, new_owner: address) {
        cross_cap::do_transfer(cap, new_owner);
    }
}
