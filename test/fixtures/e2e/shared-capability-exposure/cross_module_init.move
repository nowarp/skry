/// Cross-module test: shares capability from another module
module test::init_module {
    use sui::transfer;
    use sui::tx_context::TxContext;
    use test::cap_module::{Self, AdminCap};

    /// Shares cap from another module (violation is on AdminCap struct in cap_module)
    fun init(ctx: &mut TxContext) {
        let cap = cap_module::create_admin_cap(ctx);
        transfer::public_share_object(cap);  // WRONG: should use transfer::transfer
    }
}
