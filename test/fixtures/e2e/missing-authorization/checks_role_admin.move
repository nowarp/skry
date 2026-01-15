module test::checks_role_admin;

use sui::transfer;
use sui::object::{Self as object, UID};
use sui::tx_context::{Self as tx_context, TxContext};

/// Admin capability - represents admin role
public struct AdminCap has key, store {
    id: UID,
}

/// Operator capability - represents operator role
public struct OperatorCap has key, store {
    id: UID,
}

/// Initialize and transfer capabilities to deployer
fun init(ctx: &mut TxContext) {
    let admin_cap = AdminCap { id: object::new(ctx) };
    let operator_cap = OperatorCap { id: object::new(ctx) };
    let sender = tx_context::sender(ctx);
    transfer::transfer(admin_cap, sender);
    transfer::transfer(operator_cap, sender);
}

/// Create a new operator - requires admin permission
public fun create_operator(_: &AdminCap, ctx: &mut TxContext): OperatorCap {
    OperatorCap { id: object::new(ctx) }
}
